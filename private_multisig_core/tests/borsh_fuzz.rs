//! Structured fuzz battery for every Borsh deserializer
//! `private_multisig_core` exposes.
//!
//! Borsh is the on-chain ABI for this protocol — every byte that arrives at
//! the verifier program goes through these deserializers first. They must
//! never panic, OOM, infinite-loop, or accept structurally invalid input.
//!
//! Methodology:
//! - Property-style fuzzing with deterministic seeds (`StdRng::seed_from_u64`)
//!   so any failure reproduces verbatim. We do not require nightly toolchains
//!   nor `cargo-fuzz` infrastructure.
//! - Each fuzz target runs at least 10_000 iterations and wraps every
//!   deserialize call in `std::panic::catch_unwind` so a panic surfaces as a
//!   clean test failure rather than crashing the test runner.
//! - Adversarial inputs cover: random bytes of varying lengths, oversized
//!   length prefixes, every truncation, trailing-byte handling, invalid enum
//!   discriminants, invalid `bool` byte values, length-prefix-vs-buffer
//!   attacks, and a curated "known dangerous" seed corpus.
//!
//! The deserializers under test (all expose `try_from_slice`):
//! - `Instruction` (4-variant enum)
//! - `MultisigState` (fixed 77 bytes)
//! - `Proposal` (variable: `action_bytes` is `Vec<u8>`)
//! - `NullifierEntry` (zero bytes)
//! - `Vault` (32 bytes)
//! - `ApprovePublicInputs` (fixed 96 bytes)

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::needless_range_loop,
    clippy::unreadable_literal,
    clippy::needless_pass_by_value,
    clippy::items_after_statements,
    clippy::similar_names,
    clippy::manual_range_contains,
    clippy::range_plus_one
)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    ApprovePublicInputs, Instruction, MultisigState, NullifierEntry, Proposal, Vault,
};

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn rng_for(label: &str) -> StdRng {
    // Per-test deterministic seed derived from the label. Any failure
    // therefore reproduces by re-running the exact named test.
    let mut seed = [0u8; 32];
    let bytes = label.as_bytes();
    for (i, b) in bytes.iter().enumerate().take(32) {
        seed[i] = *b;
    }
    // Avalanche by xoring a constant so the all-short-label case is not
    // mostly-zero entropy.
    for i in 0..32 {
        seed[i] ^= 0xA5u8.wrapping_add(i as u8);
    }
    StdRng::from_seed(seed)
}

fn random_bytes(r: &mut StdRng, max_len: usize) -> Vec<u8> {
    let len = r.gen_range(0..=max_len);
    let mut buf = vec![0u8; len];
    r.fill_bytes(&mut buf);
    buf
}

/// Wrap a single deserialize attempt: a panic becomes a returned `Err`
/// carrying the panic payload as a string. Treats any panic as a finding.
fn deser_catch<T>(name: &str, bytes: &[u8]) -> std::result::Result<Result<T, String>, String>
where
    T: BorshDeserialize,
{
    let bytes_owned = bytes.to_vec();
    let result = catch_unwind(AssertUnwindSafe(|| T::try_from_slice(&bytes_owned)));
    match result {
        Ok(Ok(v)) => Ok(Ok(v)),
        Ok(Err(e)) => Ok(Err(format!("{e}"))),
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&'static str>() {
                (*s).to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "non-string panic payload".to_string()
            };
            Err(format!(
                "PANIC in {name}::try_from_slice ({} bytes): {msg}\nbytes (hex): {}",
                bytes_owned.len(),
                hex::encode(&bytes_owned)
            ))
        }
    }
}

/// Assert that deserializing `bytes` as `T` does not panic. Caller does
/// not care about Ok-vs-Err here; only that the runtime did not crash.
fn check_no_panic<T: BorshDeserialize>(label: &str, bytes: &[u8]) {
    if let Err(panic_msg) = deser_catch::<T>(label, bytes) {
        panic!("{panic_msg}");
    }
}

fn sample_inputs() -> ApprovePublicInputs {
    ApprovePublicInputs {
        members_root: [0x11; 32],
        proposal_id: [0x22; 32],
        nullifier: [0x33; 32],
    }
}

fn one_of_each_instruction() -> Vec<Instruction> {
    vec![
        Instruction::CreateMultisig {
            create_key: [0xAA; 32],
            members_root: [0xBB; 32],
            m: 3,
            n: 5,
        },
        Instruction::Propose {
            create_key: [0xAA; 32],
            index: 7,
            action_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            target_program: [0xCC; 32],
        },
        Instruction::Approve {
            create_key: [0xAA; 32],
            index: 7,
            public_inputs: sample_inputs(),
        },
        Instruction::Execute {
            create_key: [0xAA; 32],
            index: 12_345,
        },
    ]
}

// ============================================================================
// (1) Random bytes — no deserializer panics, ever.
// ============================================================================

#[test]
fn fuzz_instruction_try_from_random_bytes_no_panic() {
    let mut r = rng_for("fuzz_instruction_try_from_random_bytes_no_panic");
    for i in 0..10_000 {
        let buf = random_bytes(&mut r, 2048);
        let res = deser_catch::<Instruction>("Instruction", &buf);
        if let Err(panic_msg) = res {
            panic!("iteration {i}: {panic_msg}");
        }
        // Most should error; that's expected. We don't reject Ok here —
        // Borsh's enum encoding can succeed for arbitrary bytes given the
        // right discriminant + matching body, and that's not a security
        // bug per se. Per-field validation lives in the verifier program.
    }
}

#[test]
fn fuzz_multisig_state_random_bytes_no_panic() {
    // 32 (create_key) + 32 (members_root) + 1 (m) + 4 (n) + 8 (proposal_count) = 77
    const FIXED_LEN: usize = 77;
    let mut r = rng_for("fuzz_multisig_state_random_bytes_no_panic");
    for i in 0..10_000 {
        let buf = random_bytes(&mut r, 2048);
        let res = deser_catch::<MultisigState>("MultisigState", &buf);
        match res {
            Err(panic_msg) => panic!("iteration {i}: {panic_msg}"),
            Ok(Ok(_)) => {
                assert_eq!(
                    buf.len(),
                    FIXED_LEN,
                    "MultisigState accepted at len={} (expected only len=77 to succeed): {}",
                    buf.len(),
                    hex::encode(&buf)
                );
            }
            Ok(Err(_)) => {}
        }
    }
}

#[test]
fn fuzz_proposal_random_bytes_no_panic() {
    let mut r = rng_for("fuzz_proposal_random_bytes_no_panic");
    for i in 0..10_000 {
        let buf = random_bytes(&mut r, 2048);
        let res = deser_catch::<Proposal>("Proposal", &buf);
        if let Err(panic_msg) = res {
            panic!("iteration {i}: {panic_msg}");
        }
        // Proposal is variable-length (Vec<u8> + AccountId + u32 + bool).
        // Min successful length is at least 4 (vec len prefix) + 32 + 4 + 1 = 41.
        if let Ok(Ok(_)) = res {
            assert!(
                buf.len() >= 41,
                "Proposal accepted at impossibly short len={}: {}",
                buf.len(),
                hex::encode(&buf)
            );
        }
    }
}

#[test]
fn fuzz_approve_public_inputs_random_bytes_no_panic() {
    const FIXED_LEN: usize = 96;
    let mut r = rng_for("fuzz_approve_public_inputs_random_bytes_no_panic");
    for i in 0..10_000 {
        let buf = random_bytes(&mut r, 2048);
        let res = deser_catch::<ApprovePublicInputs>("ApprovePublicInputs", &buf);
        match res {
            Err(panic_msg) => panic!("iteration {i}: {panic_msg}"),
            Ok(Ok(_)) => {
                assert_eq!(
                    buf.len(),
                    FIXED_LEN,
                    "ApprovePublicInputs accepted at len={} (expected only len=96): {}",
                    buf.len(),
                    hex::encode(&buf)
                );
            }
            Ok(Err(_)) => {}
        }
    }
}

// Also exercise Vault and NullifierEntry randomly; these are short types
// but cheap to fuzz and we want full coverage of the surface.
#[test]
fn fuzz_vault_random_bytes_no_panic() {
    const FIXED_LEN: usize = 32;
    let mut r = rng_for("fuzz_vault_random_bytes_no_panic");
    for _ in 0..10_000 {
        let buf = random_bytes(&mut r, 256);
        let res = deser_catch::<Vault>("Vault", &buf);
        match res {
            Err(panic_msg) => panic!("{panic_msg}"),
            Ok(Ok(_)) => assert_eq!(buf.len(), FIXED_LEN),
            Ok(Err(_)) => {}
        }
    }
}

#[test]
fn fuzz_nullifier_entry_random_bytes_no_panic() {
    // NullifierEntry is a zero-size unit struct. Borsh accepts any 0-length
    // slice; non-zero slices must be rejected by `try_from_slice` (trailing
    // bytes) but never panic.
    let mut r = rng_for("fuzz_nullifier_entry_random_bytes_no_panic");
    for _ in 0..10_000 {
        let buf = random_bytes(&mut r, 64);
        let res = deser_catch::<NullifierEntry>("NullifierEntry", &buf);
        match res {
            Err(panic_msg) => panic!("{panic_msg}"),
            Ok(Ok(_)) => assert!(
                buf.is_empty(),
                "NullifierEntry accepted at len={}",
                buf.len()
            ),
            Ok(Err(_)) => {}
        }
    }
}

// ============================================================================
// (5) Oversized length-prefix attack — must reject without allocating.
// ============================================================================

/// Construct a Borsh-encoded `Proposal` where the `action_bytes` length
/// prefix is `u32::MAX` but no actual data follows. The deserializer must
/// reject without allocating ~4 GiB. Borsh 1.x uses `cautious::<T>(len)` to
/// pre-cap the initial `Vec::with_capacity`, so this should error cleanly.
#[test]
fn fuzz_borsh_with_oversized_length_prefix_rejects() {
    // Layout of `Proposal`:
    //   action_bytes: Vec<u8>      -> u32 LE length + bytes
    //   target_program: [u8; 32]
    //   approvals_count: u32       -> u32 LE
    //   executed: bool             -> 1 byte (0|1)
    //
    // We craft just the 4-byte length prefix == u32::MAX and stop there.
    // The deserializer should error reading the action_bytes payload long
    // before exhausting memory.
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32::MAX.to_le_bytes());

    let res = deser_catch::<Proposal>("Proposal", &buf);
    match res {
        Err(panic_msg) => panic!("oversized-length-prefix attack PANICKED: {panic_msg}"),
        Ok(Ok(_)) => panic!("oversized-length-prefix attack ACCEPTED a 4-byte input"),
        Ok(Err(_)) => {}
    }

    // Also do u32::MAX-1, 2^16, 2^20, 2^24 in case a future allocator tweak
    // catches one but not another.
    for &len_prefix in &[1u32 << 16, 1u32 << 20, 1u32 << 24, u32::MAX - 1, u32::MAX] {
        let mut buf2 = Vec::new();
        buf2.extend_from_slice(&len_prefix.to_le_bytes());
        // Provide just 1 byte of "payload" so reader doesn't see immediate EOF
        // on the length prefix itself, only when consuming the payload.
        buf2.push(0xAA);
        let res2 = deser_catch::<Proposal>("Proposal", &buf2);
        match res2 {
            Err(panic_msg) => panic!(
                "len_prefix=0x{len_prefix:08x} caused PANIC: {panic_msg}"
            ),
            Ok(Ok(_)) => panic!(
                "len_prefix=0x{len_prefix:08x} unexpectedly accepted (allocated and read?)"
            ),
            Ok(Err(_)) => {}
        }
    }

    // Also exercise via Instruction::Propose / Instruction::Approve which
    // both embed a Vec<u8>. Discriminant 1 = Propose, 2 = Approve.
    for &disc in &[1u8, 2u8] {
        let mut buf = Vec::new();
        buf.push(disc);
        buf.extend_from_slice(&[0xAA; 32]); // create_key
        buf.extend_from_slice(&0u64.to_le_bytes()); // index
        buf.extend_from_slice(&u32::MAX.to_le_bytes()); // bogus vec len
        let res = deser_catch::<Instruction>("Instruction", &buf);
        match res {
            Err(panic_msg) => panic!(
                "Instruction(disc={disc}) with u32::MAX vec len PANICKED: {panic_msg}"
            ),
            Ok(Ok(_)) => panic!(
                "Instruction(disc={disc}) with u32::MAX vec len was ACCEPTED"
            ),
            Ok(Err(_)) => {}
        }
    }
}

// ============================================================================
// (6) Truncation — every prefix of a valid encoding must error cleanly.
// ============================================================================

#[test]
fn fuzz_instruction_truncation_rejects_cleanly() {
    for ix in one_of_each_instruction() {
        let bytes = to_vec(&ix).expect("serialize ok");
        for len in 0..bytes.len() {
            let truncated = &bytes[..len];
            let res = deser_catch::<Instruction>("Instruction", truncated);
            match res {
                Err(panic_msg) => panic!(
                    "truncation len={len} of {ix:?} PANICKED: {panic_msg}"
                ),
                Ok(Ok(_)) => panic!(
                    "truncation len={len} of {ix:?} was unexpectedly ACCEPTED (full encoded len = {})",
                    bytes.len()
                ),
                Ok(Err(_)) => {}
            }
        }
        // The full-length case must of course succeed.
        let res = deser_catch::<Instruction>("Instruction", &bytes);
        match res {
            Ok(Ok(decoded)) => assert_eq!(decoded, ix, "round-trip mismatch"),
            other => panic!("full-length encoding rejected/panicked: {other:?}"),
        }
    }
}

#[test]
fn fuzz_state_truncation_rejects_cleanly() {
    let state = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 3,
        n: 5,
        proposal_count: 42,
    };
    let bytes = to_vec(&state).expect("serialize ok");
    for len in 0..bytes.len() {
        let truncated = &bytes[..len];
        let res = deser_catch::<MultisigState>("MultisigState", truncated);
        match res {
            Err(panic_msg) => panic!("truncation len={len} PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("truncation len={len} ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }
}

#[test]
fn fuzz_approve_public_inputs_truncation_rejects_cleanly() {
    let bytes = to_vec(&sample_inputs()).expect("serialize ok");
    for len in 0..bytes.len() {
        let truncated = &bytes[..len];
        let res = deser_catch::<ApprovePublicInputs>("ApprovePublicInputs", truncated);
        match res {
            Err(panic_msg) => panic!("truncation len={len} PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("truncation len={len} ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }
}

// ============================================================================
// (7) Trailing-garbage handling — pin Borsh strict-mode behavior per type.
// ============================================================================

#[test]
fn fuzz_instruction_trailing_garbage_handling() {
    // Borsh `try_from_slice` is strict: it errors if any bytes remain after
    // the structure has been consumed. This test pins that behavior across
    // every Instruction variant, MultisigState, Proposal, Vault,
    // ApprovePublicInputs, and NullifierEntry.
    let mut r = rng_for("fuzz_instruction_trailing_garbage_handling");

    for ix in one_of_each_instruction() {
        let base = to_vec(&ix).expect("serialize ok");
        for &extra in &[0usize, 1, 2, 100, 1000] {
            let mut buf = base.clone();
            let mut tail = vec![0u8; extra];
            r.fill_bytes(&mut tail);
            buf.extend_from_slice(&tail);

            let res = deser_catch::<Instruction>("Instruction", &buf);
            match res {
                Err(panic_msg) => panic!(
                    "Instruction trailing={extra} PANICKED: {panic_msg}"
                ),
                Ok(Ok(_)) => {
                    assert_eq!(
                        extra, 0,
                        "Borsh accepted Instruction with {extra} trailing bytes — strict-mode violated"
                    );
                }
                Ok(Err(_)) => {
                    assert!(
                        extra > 0,
                        "Borsh rejected Instruction with 0 trailing bytes — round-trip broken"
                    );
                }
            }
        }
    }

    // MultisigState: fixed-size, must reject any trailing byte.
    let state = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 0,
        n: 0,
        proposal_count: 0,
    };
    let base = to_vec(&state).unwrap();
    for &extra in &[1usize, 2, 100, 1000] {
        let mut buf = base.clone();
        buf.extend(std::iter::repeat(0xCDu8).take(extra));
        let res = deser_catch::<MultisigState>("MultisigState", &buf);
        match res {
            Err(panic_msg) => panic!("MultisigState trailing={extra} PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!(
                "MultisigState with {extra} trailing bytes ACCEPTED — strict-mode violated"
            ),
            Ok(Err(_)) => {}
        }
    }

    // Vault: fixed 32 bytes, must reject trailing.
    let vault = Vault {
        create_key: [0xAB; 32],
    };
    let vbase = to_vec(&vault).unwrap();
    for &extra in &[1usize, 100] {
        let mut buf = vbase.clone();
        buf.extend(std::iter::repeat(0xCDu8).take(extra));
        match deser_catch::<Vault>("Vault", &buf) {
            Err(panic_msg) => panic!("Vault trailing PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("Vault with trailing bytes ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }

    // ApprovePublicInputs: fixed 96 bytes, must reject trailing.
    let inputs = sample_inputs();
    let ibase = to_vec(&inputs).unwrap();
    for &extra in &[1usize, 50, 1000] {
        let mut buf = ibase.clone();
        buf.extend(std::iter::repeat(0xCDu8).take(extra));
        match deser_catch::<ApprovePublicInputs>("ApprovePublicInputs", &buf) {
            Err(panic_msg) => panic!("ApprovePublicInputs trailing PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("ApprovePublicInputs with trailing bytes ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }

    // NullifierEntry: empty serialization, anything non-empty must error.
    let nbytes = to_vec(&NullifierEntry).unwrap();
    assert!(nbytes.is_empty());
    for &extra in &[1usize, 2, 100] {
        let buf = vec![0xCDu8; extra];
        match deser_catch::<NullifierEntry>("NullifierEntry", &buf) {
            Err(panic_msg) => panic!("NullifierEntry trailing PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("NullifierEntry with {extra} trailing bytes ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }

    // Proposal: variable-length tail (Vec<u8>) — still strict, trailing must
    // error.
    let prop = Proposal {
        action_bytes: vec![0x01, 0x02, 0x03],
        target_program: [0xCC; 32],
        approvals_count: 2,
        executed: false,
    };
    let pbase = to_vec(&prop).unwrap();
    for &extra in &[1usize, 100] {
        let mut buf = pbase.clone();
        buf.extend(std::iter::repeat(0xCDu8).take(extra));
        match deser_catch::<Proposal>("Proposal", &buf) {
            Err(panic_msg) => panic!("Proposal trailing PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("Proposal with {extra} trailing bytes ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }
}

// ============================================================================
// (8) Invalid enum discriminants — bytes 4..=255 are not valid Instruction.
// ============================================================================

#[test]
fn fuzz_instruction_discriminant_in_invalid_range() {
    // Build an otherwise-valid Execute body so we can swap just the
    // discriminant byte.
    let ix = Instruction::Execute {
        create_key: [0xAA; 32],
        index: 0,
    };
    let valid = to_vec(&ix).unwrap();
    assert_eq!(valid[0], 3, "Execute discriminant drifted");

    for disc in 4u8..=255u8 {
        let mut buf = valid.clone();
        buf[0] = disc;
        let res = deser_catch::<Instruction>("Instruction", &buf);
        match res {
            Err(panic_msg) => panic!("disc={disc} PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("disc={disc} ACCEPTED — Instruction variants are 0..=3"),
            Ok(Err(_)) => {}
        }
    }

    // Also try just the discriminant byte alone (with no body) for each
    // invalid value.
    for disc in 4u8..=255u8 {
        let buf = vec![disc];
        let res = deser_catch::<Instruction>("Instruction", &buf);
        match res {
            Err(panic_msg) => panic!("disc={disc} (alone) PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("disc={disc} (alone) ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }
}

// ============================================================================
// (9) Invalid bool byte — only 0x00 and 0x01 are valid for `executed`.
// ============================================================================

#[test]
fn fuzz_random_bool_byte_in_proposal_executed() {
    // Layout of Proposal:
    //   action_bytes: Vec<u8>   -> [u32 LE len][bytes]
    //   target_program: [u8;32]
    //   approvals_count: u32
    //   executed: bool          <-- last byte
    let prop = Proposal {
        action_bytes: vec![0x01, 0x02, 0x03],
        target_program: [0xCC; 32],
        approvals_count: 2,
        executed: false,
    };
    let valid = to_vec(&prop).unwrap();
    let exec_idx = valid.len() - 1;
    assert_eq!(valid[exec_idx], 0x00, "executed-byte position drifted");

    for b in 2u8..=255u8 {
        let mut buf = valid.clone();
        buf[exec_idx] = b;
        let res = deser_catch::<Proposal>("Proposal", &buf);
        match res {
            Err(panic_msg) => panic!("executed byte=0x{b:02x} PANICKED: {panic_msg}"),
            Ok(Ok(p)) => panic!(
                "executed byte=0x{b:02x} ACCEPTED (decoded executed={}) — Borsh bool strict-mode violated",
                p.executed
            ),
            Ok(Err(_)) => {}
        }
    }
}

// ============================================================================
// (10) Curated dangerous-pattern corpus — across every type.
// ============================================================================

#[test]
fn fuzz_seed_corpus_no_panic_across_types() {
    let mut corpus: Vec<Vec<u8>> = Vec::new();

    // All zeros at a variety of canonical lengths.
    for &len in &[0usize, 1, 13, 32, 33, 41, 77, 78, 96, 97, 128, 1024, 4096] {
        corpus.push(vec![0u8; len]);
    }
    // All 0xFF at the same lengths.
    for &len in &[0usize, 1, 13, 32, 33, 41, 77, 78, 96, 97, 128, 1024, 4096] {
        corpus.push(vec![0xFFu8; len]);
    }
    // Alternating 0xAA / 0x55.
    for &len in &[16usize, 77, 96, 128, 256] {
        corpus.push(
            (0..len)
                .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
                .collect(),
        );
    }
    // Fibonacci-sized random buffers (chosen for "unusual" lengths).
    let mut a = 1usize;
    let mut b = 2usize;
    let mut r = rng_for("fuzz_seed_corpus");
    while a < 4096 {
        let mut buf = vec![0u8; a];
        r.fill_bytes(&mut buf);
        corpus.push(buf);
        let next = a + b;
        a = b;
        b = next;
    }

    // FINDING-1 / FINDING-1b empty-marker patterns mentioned in
    // THREAT_MODEL.md: the empty NullifierEntry serialization is 0 bytes,
    // and an empty Proposal action_bytes is the 4-byte LE prefix 0x00000000.
    corpus.push(Vec::new()); // 0 bytes
    corpus.push(vec![0u8; 4]); // u32 LE = 0

    // Real serialized Instruction fed to MultisigState::try_from_slice and
    // vice versa — a classic ABI confusion attempt.
    for ix in one_of_each_instruction() {
        corpus.push(to_vec(&ix).unwrap());
    }
    corpus.push(
        to_vec(&MultisigState {
            create_key: [0; 32],
            members_root: [0; 32],
            m: 0,
            n: 0,
            proposal_count: 0,
        })
        .unwrap(),
    );
    corpus.push(
        to_vec(&Proposal {
            action_bytes: vec![0; 32],
            target_program: [0; 32],
            approvals_count: 0,
            executed: false,
        })
        .unwrap(),
    );
    corpus.push(to_vec(&sample_inputs()).unwrap());
    corpus.push(to_vec(&Vault { create_key: [0; 32] }).unwrap());

    // Maximum-size action_bytes serialization — the legal upper bound.
    let max_prop = Proposal {
        action_bytes: vec![0x77; 4096],
        target_program: [0xEE; 32],
        approvals_count: u32::MAX,
        executed: true,
    };
    corpus.push(to_vec(&max_prop).unwrap());

    // u32::MAX length prefix with no payload — the classic OOM bait.
    let mut oom_bait = Vec::new();
    oom_bait.extend_from_slice(&u32::MAX.to_le_bytes());
    corpus.push(oom_bait);

    // Single-byte-each across discriminants.
    for b in 0u8..=10u8 {
        corpus.push(vec![b]);
    }

    // Run every corpus entry through every deserializer. None may panic.
    for (i, bytes) in corpus.iter().enumerate() {
        let target = format!("corpus[{i}] len={}", bytes.len());
        if let Err(p) = deser_catch::<Instruction>(&target, bytes) {
            panic!("Instruction {p}");
        }
        if let Err(p) = deser_catch::<MultisigState>(&target, bytes) {
            panic!("MultisigState {p}");
        }
        if let Err(p) = deser_catch::<Proposal>(&target, bytes) {
            panic!("Proposal {p}");
        }
        if let Err(p) = deser_catch::<NullifierEntry>(&target, bytes) {
            panic!("NullifierEntry {p}");
        }
        if let Err(p) = deser_catch::<Vault>(&target, bytes) {
            panic!("Vault {p}");
        }
        if let Err(p) = deser_catch::<ApprovePublicInputs>(&target, bytes) {
            panic!("ApprovePublicInputs {p}");
        }
    }
}

// ============================================================================
// (12) Vec length-prefix attacks at increasing magnitudes — must reject.
// ============================================================================

#[test]
fn fuzz_borsh_vec_length_prefix_attacks() {
    // Construct byte streams where the inner Vec<u8> length prefix indicates
    // a size far larger than the available bytes. Deserializer must reject
    // cleanly (never panic, never allocate the full requested size, never
    // succeed reading data that isn't there).
    let attack_lens: &[u32] = &[
        1 << 16,
        1 << 20,
        1 << 24,
        u32::MAX - 1,
        u32::MAX,
    ];

    // (a) Proposal direct: just a length prefix + 1 padding byte so the
    // reader actually attempts to read the payload.
    for &len in attack_lens {
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.push(0x00); // 1 byte of "payload"
        match deser_catch::<Proposal>("Proposal", &buf) {
            Err(panic_msg) => panic!("Proposal vec-len 0x{len:08x} PANICKED: {panic_msg}"),
            Ok(Ok(_)) => panic!("Proposal vec-len 0x{len:08x} ACCEPTED"),
            Ok(Err(_)) => {}
        }
    }

    // (b) Instruction::Propose: discriminant (1) + create_key (32) +
    // index (8) + action_bytes vec-len + 1 byte payload + missing trailer.
    for &len in attack_lens {
        let mut buf = Vec::new();
        buf.push(1u8); // Propose discriminant
        buf.extend_from_slice(&[0xAA; 32]); // create_key
        buf.extend_from_slice(&0u64.to_le_bytes()); // index
        buf.extend_from_slice(&len.to_le_bytes()); // bogus vec len
        buf.push(0x00); // 1 byte of "payload"
        match deser_catch::<Instruction>("Instruction", &buf) {
            Err(panic_msg) => panic!(
                "Instruction::Propose vec-len 0x{len:08x} PANICKED: {panic_msg}"
            ),
            Ok(Ok(_)) => panic!(
                "Instruction::Propose vec-len 0x{len:08x} ACCEPTED"
            ),
            Ok(Err(_)) => {}
        }
    }

    // (c) Round 5 removed Instruction::Approve.receipt — the vec-len attack
    // surface is gone for Approve. Pin the negative: any bytes that DON'T
    // match the new fixed-length 137-byte shape (disc + create_key +
    // index + public_inputs) must reject without panicking. We feed the
    // old shape (with a phony length prefix in place of public_inputs) and
    // confirm clean rejection.
    for &len in attack_lens {
        let mut buf = Vec::new();
        buf.push(2u8); // Approve discriminant
        buf.extend_from_slice(&[0xAA; 32]); // create_key
        buf.extend_from_slice(&0u64.to_le_bytes()); // index
        // Where public_inputs (96 bytes) is expected, supply 4-byte garbage
        // shaped like a former length prefix — exercises the "what if a
        // future PR re-adds a Vec" regression detector.
        buf.extend_from_slice(&len.to_le_bytes());
        match deser_catch::<Instruction>("Instruction", &buf) {
            Err(panic_msg) => panic!(
                "Instruction::Approve garbage 0x{len:08x} PANICKED: {panic_msg}"
            ),
            Ok(Ok(_)) => panic!(
                "Instruction::Approve garbage 0x{len:08x} ACCEPTED"
            ),
            Ok(Err(_)) => {}
        }
    }

    // (d) Sanity timing: each attack iteration above should complete in
    // milliseconds, not seconds. If Borsh ever pre-allocates the full
    // requested capacity, this entire test will exceed the per-test
    // timeout (`cargo test` default is generous, but allocating 16 GiB
    // would fail or hang). The completion of this test IS the assertion.
}

// ============================================================================
// Extra: random-input fuzzing of EVERY deserializer using a single seeded
// stream, primarily a smoke test that nothing surprises us with a panic
// on cross-type input.
// ============================================================================

#[test]
fn fuzz_all_types_with_shared_random_corpus_no_panic() {
    let mut r = rng_for("fuzz_all_types_with_shared_random_corpus_no_panic");
    for i in 0..10_000 {
        // Bias length distribution toward the "interesting" zones around
        // each type's canonical size.
        let len: usize = match r.gen_range(0..10) {
            0 => r.gen_range(0..=4),
            1 => r.gen_range(10..=20),
            2 => r.gen_range(30..=50),
            3 => r.gen_range(70..=100),
            4 => r.gen_range(90..=110),
            5 => r.gen_range(120..=200),
            6 => r.gen_range(0..=2048),
            7 => 0,
            8 => 77,
            _ => 96,
        };
        let mut buf = vec![0u8; len];
        r.fill_bytes(&mut buf);

        let label = format!("iter {i} len {len}");
        check_no_panic::<Instruction>(&label, &buf);
        check_no_panic::<MultisigState>(&label, &buf);
        check_no_panic::<Proposal>(&label, &buf);
        check_no_panic::<NullifierEntry>(&label, &buf);
        check_no_panic::<Vault>(&label, &buf);
        check_no_panic::<ApprovePublicInputs>(&label, &buf);
    }
}
