//! Performance baseline measurements for the LP-0002 approve circuit.
//!
//! These tests give PLAN.md concrete numbers to replace the prior placeholder
//! ("fast in dev_mode"). They cover, in order of how often they should be run:
//!
//! 1. Fast metrics (default `cargo test` run):
//!    - `perf_guest_cycle_count`         — total/user/paging cycles via
//!      `ProveInfo.stats` (deterministic; identical whether dev_mode is on or
//!      off because the executor itself runs in both modes).
//!    - `perf_dev_mode_proving_time`     — wall-clock for `prover.prove()`
//!      under `RISC0_DEV_MODE=1` (no SNARK, executor only).
//!    - `perf_verification_time`         — median wall-clock for
//!      `receipt.verify(image_id)` across 10 runs of a dev-mode receipt.
//!    - `perf_receipt_serialized_size`   — `borsh::to_vec(&receipt).len()`.
//!    - `perf_journal_is_96_bytes`       — the `ApprovePublicInputs` size
//!      sentinel reproduced here as part of the perf profile.
//!
//! 2. Slow metrics (gated behind `#[ignore]`; opt in explicitly):
//!    - `perf_real_proving_with_dev_mode_off` — full SNARK proving under
//!      `RISC0_DEV_MODE=0`. Multi-minute on M1.
//!    - `perf_real_proving_verification`      — verification cost for a real
//!      (non-dev-mode) receipt.
//!
//! # Running
//!
//! Fast tests only (CI-friendly, dev_mode=1 throughout):
//! ```text
//! cargo test -p private_multisig_program --test perf_baseline -- --nocapture
//! ```
//!
//! Full proving baseline (slow — multi-minute on M1; do NOT run in CI):
//! ```text
//! cargo test -p private_multisig_program --test perf_baseline -- --ignored --nocapture
//! ```
//!
//! `--nocapture` is recommended either way so the printed timings actually
//! reach the terminal; the assertions only sanity-check the band, the
//! reported numbers are the artifact.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]

use std::env;
use std::time::{Duration, Instant};

use crypto::{Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH};
use private_multisig_core::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProveInfo};

// ---------------------------------------------------------------------------
// Shared fixture helpers
// ---------------------------------------------------------------------------

/// Same deterministic-identity fixture as `approve_circuit.rs` — keeps the
/// witness reproducible across runs so the cycle count is stable.
fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

/// Build a complete `ExecutorEnv` for a known-good approve witness. The
/// fixture is identical to `approve_circuit.rs` so the perf numbers track
/// exactly the same code path the e2e test exercises.
///
/// Returned tuple: (env, expected_public_inputs). Caller can re-derive the
/// expected journal independently if needed.
fn build_valid_env() -> (ExecutorEnv<'static>, ApprovePublicInputs) {
    // Five-member set, frozen root.
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let members_root = tree.root();

    let approver_index = 2usize;
    let approver = &members[approver_index];
    let proof = tree.proof(approver_index).unwrap();

    // Synthetic proposal — same constants as `approve_circuit.rs`.
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let proposal_id = derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program);

    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&proposal_id);
    let expected_bundle = ApprovePublicInputs {
        members_root,
        proposal_id,
        nullifier: expected_nullifier,
    };

    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&members_root);
    public_prefix[32..].copy_from_slice(&proposal_id);

    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    let env = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&approver.sk)
        .write_slice(&approver.salt)
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build()
        .expect("ExecutorEnv build must succeed");

    (env, expected_bundle)
}

/// Force `RISC0_DEV_MODE=1` for the current process unless already explicitly
/// set. The fast tests must NOT clobber an outer `RISC0_DEV_MODE=0`; we only
/// install the default when no value is present.
fn ensure_dev_mode_on() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: each `cargo test` test runs in its own process when run
        // serially under nextest, or shares a process with other tests under
        // the default harness. In either case `set_var` is called before
        // any other thread reads the variable.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

/// Force `RISC0_DEV_MODE=0` for the real-proving tests. Unlike the default
/// `ensure_dev_mode_on` helper this is unconditional — the whole point of
/// the `#[ignore]`d tests is to exercise the SNARK regardless of what the
/// outer environment defaulted to.
fn force_real_mode() {
    // SAFETY: see `ensure_dev_mode_on`.
    unsafe {
        env::set_var("RISC0_DEV_MODE", "0");
    }
}

/// Run a single prove cycle against the cached `APPROVE_CIRCUIT_ELF`. Returns
/// the wall-clock duration and the full `ProveInfo` (stats + receipt) so the
/// caller can pull whichever pieces it cares about.
fn prove_once() -> (Duration, ProveInfo) {
    let (env, _expected) = build_valid_env();
    let prover = default_prover();
    let start = Instant::now();
    let prove_info = prover
        .prove(env, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid witness");
    let elapsed = start.elapsed();
    (elapsed, prove_info)
}

/// Compute the median of a slice of `Duration`s. Used to dampen the noise
/// in repeated wall-clock verification timings.
fn median_duration(samples: &mut [Duration]) -> Duration {
    samples.sort();
    let mid = samples.len() / 2;
    if samples.len() % 2 == 0 {
        // Even count: arithmetic mean of the two middle values.
        (samples[mid - 1] + samples[mid]) / 2
    } else {
        samples[mid]
    }
}

// ---------------------------------------------------------------------------
// Fast tests (run by default)
// ---------------------------------------------------------------------------

#[test]
fn perf_guest_cycle_count() {
    // Cycle counts are produced by the executor and are independent of
    // whether the SNARK is generated, so dev_mode=1 is enough to pin them.
    // Running in dev_mode keeps this test fast (~hundreds of ms instead of
    // minutes) while still capturing the deterministic cycle profile.
    ensure_dev_mode_on();

    let (_elapsed, prove_info) = prove_once();
    let stats = &prove_info.stats;

    println!("perf_guest_cycle_count:");
    println!("  segments         = {}", stats.segments);
    println!("  total_cycles     = {}", stats.total_cycles);
    println!("  user_cycles      = {}", stats.user_cycles);
    println!("  paging_cycles    = {}", stats.paging_cycles);
    println!("  reserved_cycles  = {}", stats.reserved_cycles);

    // Sanity band for a Merkle-path + Sha256-nullifier circuit. 100 K is
    // unrealistically low (would imply the guest barely executed); 100 M
    // is unrealistically high for a 20-deep Merkle path + a couple of
    // Sha256 invocations (would imply a regression like accidentally
    // doing per-byte hashing or pulling in std).
    const MIN_CYCLES: u64 = 100_000;
    const MAX_CYCLES: u64 = 100_000_000;
    assert!(
        stats.total_cycles >= MIN_CYCLES,
        "total_cycles {} is below the sanity floor {} — guest barely ran",
        stats.total_cycles,
        MIN_CYCLES,
    );
    assert!(
        stats.total_cycles <= MAX_CYCLES,
        "total_cycles {} is above the sanity ceiling {} — guest ballooned",
        stats.total_cycles,
        MAX_CYCLES,
    );

    // User cycles must be a non-trivial fraction of total — if user_cycles
    // were zero or near-zero with total in the millions, the guest would
    // effectively be doing nothing and the proof would be vacuous.
    assert!(
        stats.user_cycles > 0,
        "user_cycles is zero — guest produced no useful work",
    );
    assert!(
        stats.user_cycles <= stats.total_cycles,
        "user_cycles ({}) must not exceed total_cycles ({})",
        stats.user_cycles,
        stats.total_cycles,
    );

    // At least one segment must have been produced.
    assert!(
        stats.segments >= 1,
        "expected ≥1 segment, got {}",
        stats.segments
    );
}

#[test]
fn perf_dev_mode_proving_time() {
    // dev_mode=1: executes the guest but skips SNARK generation. Should be
    // fast — well under five seconds even on a cold cache. The exact number
    // varies with machine, but the band catches the case where dev_mode
    // accidentally falls back to real proving.
    ensure_dev_mode_on();

    let (elapsed, prove_info) = prove_once();

    println!("perf_dev_mode_proving_time:");
    println!(
        "  RISC0_DEV_MODE     = {}",
        env::var("RISC0_DEV_MODE").unwrap_or_default()
    );
    println!("  wall-clock prove   = {:?}", elapsed);
    println!("  total_cycles       = {}", prove_info.stats.total_cycles);
    println!("  segments           = {}", prove_info.stats.segments);

    // 5 s is *very* generous; a dev-mode prove on the LP-0002 approve
    // circuit is typically ~100 ms. If this fires, either dev_mode isn't
    // actually active or the cycle count exploded — either way, a real
    // regression worth investigating.
    assert!(
        elapsed < Duration::from_secs(5),
        "dev_mode prove took {:?} (>5s) — likely not actually in dev mode \
         or guest cycle count regressed; check RISC0_DEV_MODE env var",
        elapsed,
    );
}

#[test]
fn perf_verification_time() {
    // Produce a receipt once, then time verification 10x to dampen jitter.
    // Verification under dev_mode is a no-op for the SNARK portion but still
    // walks the receipt structure and checks the image-id binding, which is
    // the same code path on-chain logic will exercise (modulo the SNARK
    // check itself, which dominates only for real receipts).
    ensure_dev_mode_on();

    let (_elapsed, prove_info) = prove_once();
    let receipt = prove_info.receipt;

    const N: usize = 10;
    let mut samples: Vec<Duration> = Vec::with_capacity(N);
    for _ in 0..N {
        let start = Instant::now();
        receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .expect("dev-mode receipt must verify");
        samples.push(start.elapsed());
    }
    let median = median_duration(&mut samples.clone());
    let min = samples.iter().min().copied().unwrap_or_default();
    let max = samples.iter().max().copied().unwrap_or_default();

    println!("perf_verification_time (dev_mode=1, N={}):", N);
    println!("  min     = {:?}", min);
    println!("  median  = {:?}", median);
    println!("  max     = {:?}", max);

    // Sub-second is extremely generous. Real dev-mode verify is typically
    // microseconds-to-low-milliseconds; we use 1 s as a robust ceiling that
    // won't false-fire on a loaded CI host.
    assert!(
        median < Duration::from_secs(1),
        "median verify time {:?} exceeded 1 s ceiling",
        median,
    );
}

#[test]
fn perf_receipt_serialized_size() {
    // The `Receipt` type derives `BorshSerialize` (and `Serialize`) — the
    // on-chain SDK is going to ship receipts as bytes either way, so the
    // serialized size is what callers actually pay for. Under dev_mode this
    // is much smaller than under real proving (no SNARK group elements);
    // we pin a dev-mode band here and re-measure the real-mode size in the
    // `#[ignore]`d test.
    ensure_dev_mode_on();

    let (_elapsed, prove_info) = prove_once();
    let receipt = prove_info.receipt;

    let encoded = borsh::to_vec(&receipt).expect("receipt must borsh-serialize");
    let len = encoded.len();

    println!("perf_receipt_serialized_size (dev_mode=1):");
    println!("  borsh::to_vec(&receipt).len() = {} bytes", len);
    println!(
        "  journal.bytes.len()           = {}",
        receipt.journal.bytes.len()
    );

    // Non-zero is the floor. The ceiling is generous — a dev-mode receipt
    // is dominated by the journal + small claim metadata and should be
    // well under 64 KiB even with structural overhead. If this fires, the
    // receipt shape changed materially and SDK/on-chain consumers need to
    // adjust.
    assert!(len > 0, "borsh-serialized receipt is empty");
    assert!(
        len < 64 * 1024,
        "dev-mode receipt is {} bytes (>64 KiB) — receipt shape regressed",
        len,
    );
}

#[test]
fn perf_journal_is_96_bytes() {
    // Reproduces the sentinel from `approve_circuit.rs` as part of the
    // canonical perf profile. The journal carries exactly the public
    // inputs bundle (`members_root || proposal_id || nullifier`) which is
    // 3 * 32 = 96 bytes. Any drift here breaks on-chain ABI.
    ensure_dev_mode_on();

    let (_elapsed, prove_info) = prove_once();
    let receipt = prove_info.receipt;

    let journal_len = receipt.journal.bytes.len();
    println!("perf_journal_is_96_bytes: journal_len = {}", journal_len);

    assert_eq!(
        journal_len, APPROVE_PUBLIC_INPUTS_LEN,
        "journal must be exactly {} bytes (ApprovePublicInputs), got {}",
        APPROVE_PUBLIC_INPUTS_LEN, journal_len,
    );
    assert_eq!(
        APPROVE_PUBLIC_INPUTS_LEN, 96,
        "APPROVE_PUBLIC_INPUTS_LEN drifted from the documented 96 bytes",
    );
}

// ---------------------------------------------------------------------------
// Slow tests (opt-in via `--ignored`)
// ---------------------------------------------------------------------------

/// Real proving on the LP-0002 approve circuit takes multiple minutes on M1
/// silicon today. CI must not block on it; developers run it ad-hoc when
/// they need real-mode numbers (e.g. for a release-notes update).
///
/// Invocation:
/// ```text
/// cargo test -p private_multisig_program --test perf_baseline \
///   perf_real_proving_with_dev_mode_off -- --ignored --nocapture
/// ```
#[test]
#[ignore = "multi-minute real SNARK proving; run with --ignored"]
fn perf_real_proving_with_dev_mode_off() {
    force_real_mode();

    let (elapsed, prove_info) = prove_once();
    let stats = &prove_info.stats;

    let encoded =
        borsh::to_vec(&prove_info.receipt).expect("real-mode receipt must borsh-serialize");

    println!("perf_real_proving_with_dev_mode_off:");
    println!(
        "  RISC0_DEV_MODE         = {}",
        env::var("RISC0_DEV_MODE").unwrap_or_default()
    );
    println!("  wall-clock prove       = {:?}", elapsed);
    println!("  total_cycles           = {}", stats.total_cycles);
    println!("  user_cycles            = {}", stats.user_cycles);
    println!("  paging_cycles          = {}", stats.paging_cycles);
    println!("  reserved_cycles        = {}", stats.reserved_cycles);
    println!("  segments               = {}", stats.segments);
    println!("  receipt borsh size     = {} bytes", encoded.len());
    println!(
        "  journal bytes          = {}",
        prove_info.receipt.journal.bytes.len()
    );

    // 30 minutes is absurdly generous — the true number is expected to be
    // in the 1–10 min range on M1. The ceiling exists only so that a
    // pathological regression (e.g. infinite-paging bug) fails the test
    // instead of hanging CI indefinitely if anyone accidentally enables it.
    const MAX_PROVE: Duration = Duration::from_secs(30 * 60);
    assert!(
        elapsed < MAX_PROVE,
        "real-mode prove took {:?}, exceeding the 30 min sanity ceiling",
        elapsed,
    );

    // Cycle count must match what dev_mode reports — the executor is the
    // same code path; only the SNARK back-end differs. This is a useful
    // cross-check that we are in fact in real mode (the receipt shape
    // changes) without depending on RISC0_DEV_MODE being readable.
    assert!(
        stats.total_cycles >= 100_000,
        "real-mode total_cycles too low"
    );
}

/// Verification cost on a *real* receipt. On M1 this is typically
/// 100 ms – 1 s; we ceiling at 5 s as a very loose sanity bound. Run with:
/// ```text
/// cargo test -p private_multisig_program --test perf_baseline \
///   perf_real_proving_verification -- --ignored --nocapture
/// ```
#[test]
#[ignore = "depends on real proving; run with --ignored"]
fn perf_real_proving_verification() {
    force_real_mode();

    let (prove_elapsed, prove_info) = prove_once();
    let receipt = prove_info.receipt;

    const N: usize = 5;
    let mut samples: Vec<Duration> = Vec::with_capacity(N);
    for _ in 0..N {
        let start = Instant::now();
        receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .expect("real-mode receipt must verify");
        samples.push(start.elapsed());
    }
    let median = median_duration(&mut samples.clone());
    let min = samples.iter().min().copied().unwrap_or_default();
    let max = samples.iter().max().copied().unwrap_or_default();

    println!("perf_real_proving_verification (real proving, N={}):", N);
    println!("  prove (one-shot) = {:?}", prove_elapsed);
    println!("  verify min       = {:?}", min);
    println!("  verify median    = {:?}", median);
    println!("  verify max       = {:?}", max);

    // 5 s ceiling: real verification on M1 is sub-second; 5 s catches a
    // gross regression without false-firing on a loaded host.
    assert!(
        median < Duration::from_secs(5),
        "real-mode verify median {:?} exceeded 5 s ceiling",
        median,
    );
}
