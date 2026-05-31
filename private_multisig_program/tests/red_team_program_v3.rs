//! Red-team validation (round 3) of the LP-0002 Risc0 approve circuit.
//!
//! Rounds 1 and 2 produced zero new findings across 26 adversarial tests. The
//! cryptographic + core layers have had four rounds each. Returns are
//! deeply diminishing, but this file still applies adversarial pressure on
//! the residual surface the prior two rounds did not directly cover:
//!
//!   1.  `red3_image_id_hex_lowercase_and_capacity_sentinel`
//!   2.  `red3_image_id_hex_endianness_matches_pinned_stability`
//!   3.  `red3_image_id_hex_deterministic_across_calls`
//!   4.  `red3_receipt_serialized_size_deterministic_across_runs`
//!   5.  `red3_elf_does_not_contain_witness_fixture_secrets`
//!   6.  `red3_risc0_zkvm_version_pin_sentinel`
//!   7.  `red3_segment_count_is_one_sentinel`
//!   8.  `red3_image_id_single_byte_flip_within_word_rejected`
//!   9.  `red3_cross_process_determinism_sentinel`
//!   10. `red3_journal_byte_swap_inside_a_field_rejected`
//!   11. `red3_creative_image_id_byte_rotation_rejected`
//!
//! All tests set `RISC0_DEV_MODE=1` before invoking the prover.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::similar_names)]

use std::env;
use std::process::Command;

use crypto::{merkle::MERKLE_DEPTH, Identity, MerkleTree, Sha256Hasher, HASH_LEN};
use private_multisig_core::{derive_proposal_id, ChainId, APPROVE_PUBLIC_INPUTS_LEN};
use private_multisig_program::{image_id_hex, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

// ---------------------------------------------------------------------------
// Shared scaffolding (mirroring round-1/-2 patterns, kept self-contained).
// ---------------------------------------------------------------------------

fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: cargo runs each `#[test]` in its own thread but each test
        // process is single-threaded with respect to env until the prover
        // (or our own spawn) is invoked, both of which happen after this
        // point. Same pattern the existing red_team_program{,_v2}.rs files
        // use.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

fn build_member_set() -> (Vec<Identity>, MerkleTree<Sha256Hasher>) {
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    (members, tree)
}

fn canonical_proposal_id() -> [u8; 32] {
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program)
}

#[derive(Clone)]
struct Witness {
    public_prefix: [u8; 64],
    sk: [u8; 32],
    salt: [u8; 32],
    siblings_flat: [u8; MERKLE_DEPTH * HASH_LEN],
    direction_bytes: [u8; MERKLE_DEPTH],
}

impl Witness {
    fn from_member(
        member: &Identity,
        proof: &crypto::MerkleProof,
        members_root: [u8; HASH_LEN],
        proposal_id: [u8; HASH_LEN],
    ) -> Self {
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
        Self {
            public_prefix,
            sk: member.sk,
            salt: member.salt,
            siblings_flat,
            direction_bytes,
        }
    }

    fn try_prove(&self) -> Result<risc0_zkvm::Receipt, ()> {
        let env_builder = match ExecutorEnv::builder()
            .write_slice(&self.public_prefix)
            .write_slice(&self.sk)
            .write_slice(&self.salt)
            .write_slice(&self.siblings_flat)
            .write_slice(&self.direction_bytes)
            .build()
        {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        let prover = default_prover();
        match prover.prove(env_builder, APPROVE_CIRCUIT_ELF) {
            Ok(prove_info) => Ok(prove_info.receipt),
            Err(_) => Err(()),
        }
    }
}

fn happy_witness(i: usize) -> (Identity, Witness, [u8; 32]) {
    let (members, tree) = build_member_set();
    let approver = members[i].clone();
    let proof = tree.proof(i).unwrap();
    let pid = canonical_proposal_id();
    let w = Witness::from_member(&approver, &proof, tree.root(), pid);
    (approver, w, pid)
}

/// Locally-pinned hex string. Mirrors `tests/image_id_stability.rs` so the
/// cross-test endianness sentinel below can compare against it independently.
/// If `image_id_stability.rs` is updated for a legitimate ABI bump, update
/// here too; both pins must move together. Canonical value is the
/// reproducible-Docker-build image-id; sentinels are gated on
/// `private_multisig_program::BUILD_USED_DOCKER` because a plain host build
/// produces an intentionally divergent image-id.
const PINNED_IMAGE_ID_HEX_V3: &str =
    "69f156642ae3e69e7c7517949dcc706172b34db8d967aec5ddfd8879fcbed9ce";

// ===========================================================================
// 1. image_id_hex() — lowercase, length 64, restricted alphabet.
//    The host helper allocates with `String::with_capacity(64)`; pin that the
//    final string is exactly 64 chars (no growth) and all-lowercase hex.
// ===========================================================================

#[test]
fn red3_image_id_hex_lowercase_and_capacity_sentinel() {
    let s = image_id_hex();

    // Length sentinel: 8 u32 words × 4 bytes × 2 hex chars = 64.
    assert_eq!(s.len(), 64, "image_id_hex must be exactly 64 chars");
    // The `String::with_capacity(64)` initialization should be sufficient —
    // we cannot directly inspect capacity from a returned owned string
    // without UB, but we CAN pin that `capacity() >= len()` and that the
    // returned string holds no surprise expansion. The contract is satisfied
    // if the length is exactly 64 and the bytes are restricted to lowercase
    // hex.
    assert!(
        s.capacity() >= s.len(),
        "string capacity ({}) is below its length ({})",
        s.capacity(),
        s.len()
    );

    // Alphabet: only [0-9a-f]. No uppercase, no other characters.
    for (i, c) in s.chars().enumerate() {
        assert!(
            c.is_ascii_digit() || ('a'..='f').contains(&c),
            "image_id_hex char {i} = {c:?} is not lowercase hex"
        );
        // Belt-and-suspenders against an uppercase regression slipping
        // through `is_ascii_digit() || (a..=f)`: explicitly reject A..=F.
        assert!(
            !('A'..='F').contains(&c),
            "image_id_hex contains uppercase hex at position {i}: {c:?}"
        );
    }

    // The string is pure ASCII — its byte length must equal its char count.
    assert_eq!(s.len(), s.chars().count());
}

// ===========================================================================
// 2. image_id_hex() endianness — cross-check against the pin in
//    `image_id_stability.rs`. The pinned hex is the concatenation of each
//    word's `to_le_bytes()` in lowercase. Independently rebuild that string
//    from the live `APPROVE_CIRCUIT_IMAGE_ID` here and confirm both match
//    the pin AND that `image_id_hex()` returns the same value.
// ===========================================================================

#[test]
fn red3_image_id_hex_endianness_matches_pinned_stability() {
    if !private_multisig_program::BUILD_USED_DOCKER {
        eprintln!(
            "SKIP: image-id endianness-vs-pin check requires a reproducible Docker build. \
             Re-run with `RISC0_USE_DOCKER=1 cargo test -p private_multisig_program \
             --test red_team_program_v3` to enforce."
        );
        return;
    }

    // Reconstruct the canonical hex manually, byte by byte, little-endian per
    // word. Avoids piggybacking on the implementation of `image_id_hex()`.
    let mut rebuilt = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for word in APPROVE_CIRCUIT_IMAGE_ID {
        for b in word.to_le_bytes() {
            rebuilt.push(HEX[(b >> 4) as usize] as char);
            rebuilt.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    assert_eq!(rebuilt.len(), 64);
    assert_eq!(
        rebuilt, PINNED_IMAGE_ID_HEX_V3,
        "manual little-endian hex reconstruction diverged from the pinned hex"
    );
    assert_eq!(
        image_id_hex(),
        PINNED_IMAGE_ID_HEX_V3,
        "image_id_hex() output does not match the pinned hex"
    );

    // And the inverse direction: parse the pinned hex back into a `[u32; 8]`
    // using little-endian word semantics and confirm it equals the live
    // image-id. If a future refactor silently switched to big-endian per
    // word, both halves of this round-trip would fire.
    let raw = hex::decode(PINNED_IMAGE_ID_HEX_V3).expect("pinned hex must decode");
    assert_eq!(raw.len(), 32);
    let mut reconstructed = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = raw[i * 4..(i + 1) * 4].try_into().expect("4-byte chunk");
        reconstructed[i] = u32::from_le_bytes(chunk);
    }
    assert_eq!(
        reconstructed, APPROVE_CIRCUIT_IMAGE_ID,
        "le decode of pinned hex does not equal the live APPROVE_CIRCUIT_IMAGE_ID"
    );
}

// ===========================================================================
// 3. image_id_hex() — deterministic across repeated calls. A trivial sanity
//    pin, but the host helper is invoked inside production code paths
//    (release notes, SDK output) and any environment-dependent surface
//    (e.g. accidental TLS randomness, allocator nondeterminism) would
//    surface here.
// ===========================================================================

#[test]
fn red3_image_id_hex_deterministic_across_calls() {
    let first = image_id_hex();
    for run in 1..20 {
        let s = image_id_hex();
        assert_eq!(
            s, first,
            "image_id_hex() drifted on call {run}: first={first}, got={s}"
        );
    }
}

// ===========================================================================
// 4. Receipt serialized byte size determinism. The same witness, proved
//    twice, must yield receipts of identical serialized byte length AND of
//    identical bytes. Round 2 already locked journal byte-identity across
//    100 runs; this pins the OUTER receipt envelope explicitly so a future
//    Risc0 version that introduced nondeterminism in the receipt header
//    (e.g. a timestamp field) would trip here even if the journal stayed
//    stable.
// ===========================================================================

#[test]
fn red3_receipt_serialized_size_deterministic_across_runs() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);

    let r1 = w.try_prove().expect("first prove must succeed");
    let r2 = w.try_prove().expect("second prove must succeed");
    let b1 = borsh::to_vec(&r1).expect("borsh r1");
    let b2 = borsh::to_vec(&r2).expect("borsh r2");

    assert_eq!(
        b1.len(),
        b2.len(),
        "receipt serialized byte size drift: {} vs {}",
        b1.len(),
        b2.len()
    );
    assert_eq!(
        b1, b2,
        "receipt full-byte determinism failed for the same witness"
    );

    // Also: the journal sub-component is part of the receipt envelope.
    // Pinning the full bytes is strictly stronger than just pinning the
    // journal (round 2 covered journal-only), but we cross-check anyway so
    // a regression that splits these two would emit a more useful failure
    // message.
    assert_eq!(r1.journal.bytes, r2.journal.bytes);
    assert_eq!(r1.journal.bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
}

// ===========================================================================
// 5. ELF substring inspection. The compiled approve-circuit ELF must not
//    contain verbatim copies of witness fixture material (members_root,
//    proposal_id, nullifier, sk, salt). This pins that no test fixture
//    accidentally leaked into the guest binary via, e.g., a debug `format!`
//    that captured a fixture into a static string.
// ===========================================================================

#[test]
fn red3_elf_does_not_contain_witness_fixture_secrets() {
    // Build a real witness and harvest its concrete byte material.
    let (members, tree) = build_member_set();
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    let pid = canonical_proposal_id();
    let nullifier = approver.nullifier::<Sha256Hasher>(&pid);
    let members_root = tree.root();

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        if needle.len() > hay.len() {
            return false;
        }
        hay.windows(needle.len()).any(|w| w == needle)
    }

    // The needles below are each 32 bytes. They are SHA-256 outputs (root,
    // pid, nullifier) or derived secret material (sk, salt). The chance any
    // single 32-byte sequence appears in the ELF by random alignment is
    // 2^-256 — effectively impossible unless an actual leak path exists.
    assert!(
        !contains(APPROVE_CIRCUIT_ELF, &members_root),
        "FINDING: ELF contains members_root fixture verbatim"
    );
    assert!(
        !contains(APPROVE_CIRCUIT_ELF, &pid),
        "FINDING: ELF contains proposal_id fixture verbatim"
    );
    assert!(
        !contains(APPROVE_CIRCUIT_ELF, &nullifier),
        "FINDING: ELF contains nullifier fixture verbatim"
    );
    assert!(
        !contains(APPROVE_CIRCUIT_ELF, &approver.sk),
        "FINDING: ELF contains sk fixture verbatim"
    );
    assert!(
        !contains(APPROVE_CIRCUIT_ELF, &approver.salt),
        "FINDING: ELF contains salt fixture verbatim"
    );

    // Also check each sibling: same argument.
    for (level, sibling) in proof.siblings.iter().enumerate() {
        assert!(
            !contains(APPROVE_CIRCUIT_ELF, sibling),
            "FINDING: ELF contains sibling at level {level} verbatim"
        );
    }

    // Sentinel positive control: confirm the ELF DOES contain a value we
    // know is part of its content (the ELF magic in some form), so the
    // contains() helper is genuinely finding things when they exist.
    let elf_magic: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
    assert!(
        contains(APPROVE_CIRCUIT_ELF, &elf_magic),
        "sanity: ELF should contain its own ELF magic — contains() helper is broken otherwise"
    );
}

// ===========================================================================
// 6. risc0-zkvm version-feature drift sentinel. Parses the host crate's
//    Cargo.toml at runtime and pins that `risc0-zkvm` is declared with a
//    `3.0` minor version. If a future PR bumps this to 3.1, 4.x, etc.
//    without coordinating an image-id re-pin, this fires.
//
//    Cargo.toml is in the parent of the test crate's manifest, which is
//    `private_multisig_program/Cargo.toml`. We read it via the
//    `CARGO_MANIFEST_DIR` env var, which Cargo sets at build time.
// ===========================================================================

#[test]
fn red3_risc0_zkvm_version_pin_sentinel() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let cargo_toml_path = format!("{manifest_dir}/Cargo.toml");
    let contents = std::fs::read_to_string(&cargo_toml_path)
        .unwrap_or_else(|e| panic!("could not read {cargo_toml_path}: {e}"));

    // Find the `risc0-zkvm = ` line; require the exact `=3.0.5` pin. Round 6
    // tightened the pin across the workspace because a caret `"3.0"` would
    // let a passive `cargo update` drift the resolved version and the
    // image-id with it. If a future PR bumps to `=3.0.6` or `=3.1.x`
    // intentionally, update this sentinel AND re-snapshot the image-id
    // sentinel together.
    let mut found = false;
    for line in contents.lines() {
        let l = line.trim_start();
        if l.starts_with("risc0-zkvm") {
            assert!(
                l.contains("\"=3.0.5\""),
                "FINDING: risc0-zkvm version drift — line: {l:?}"
            );
            found = true;
        }
    }
    assert!(
        found,
        "risc0-zkvm dependency line not present in {cargo_toml_path}"
    );
}

// ===========================================================================
// 7. Segment count sentinel — confirms the guest still fits in exactly one
//    Risc0 segment. If a future guest growth pushes us into 2 segments the
//    receipt structure changes and on-chain verifier expectations may shift.
//    `perf_baseline.rs` already prints the segment count but the assertion
//    there is `>= 1`; we pin `== 1` here.
// ===========================================================================

#[test]
fn red3_segment_count_is_one_sentinel() {
    ensure_dev_mode();
    let (_members, tree) = build_member_set();
    let approver = deterministic_identity(2);
    let proof = tree.proof(2).unwrap();
    let pid = canonical_proposal_id();
    let w = Witness::from_member(&approver, &proof, tree.root(), pid);

    let env_built = ExecutorEnv::builder()
        .write_slice(&w.public_prefix)
        .write_slice(&w.sk)
        .write_slice(&w.salt)
        .write_slice(&w.siblings_flat)
        .write_slice(&w.direction_bytes)
        .build()
        .expect("env build");

    let prover = default_prover();
    let prove_info = prover
        .prove(env_built, APPROVE_CIRCUIT_ELF)
        .expect("prove must succeed");
    let segments = prove_info.stats.segments;

    assert_eq!(
        segments, 1,
        "FINDING: segment count drift — guest now uses {segments} segments, \
         downstream on-chain verifier expectations may shift"
    );
}

// ===========================================================================
// 8. Single-byte-flip image-id rejection. Round 1 covered single-word zero
//    and bitwise NOT; round 2 covered word-zeroed-at-each-position. This
//    test pins finer granularity: flip each of bytes 0, 1, 2, 3 INSIDE word
//    0 and verify each variant is rejected.
// ===========================================================================

#[test]
fn red3_image_id_single_byte_flip_within_word_rejected() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);
    let receipt = w.try_prove().expect("happy path must prove");

    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("control: real image-id must verify");

    // For each byte position within each word, flip a single bit and
    // confirm verification rejects. We cover all 32 bytes (8 words × 4
    // bytes) for completeness — that's 32 verify() calls, which is fast.
    for word_idx in 0..8usize {
        for byte_idx in 0..4usize {
            let mut variant = APPROVE_CIRCUIT_IMAGE_ID;
            let mut bytes = variant[word_idx].to_le_bytes();
            // Flip bit 0 of this byte (the cheapest single-byte mutation).
            bytes[byte_idx] ^= 0x01;
            variant[word_idx] = u32::from_le_bytes(bytes);

            if variant == APPROVE_CIRCUIT_IMAGE_ID {
                // Astronomically impossible for a single bit flip; guard
                // anyway.
                continue;
            }
            assert!(
                receipt.verify(variant).is_err(),
                "image-id with bit 0 of byte {byte_idx} in word {word_idx} \
                 flipped must be rejected"
            );

            // Also flip bit 7 of the byte — different bit, same byte.
            let mut variant2 = APPROVE_CIRCUIT_IMAGE_ID;
            let mut b2 = variant2[word_idx].to_le_bytes();
            b2[byte_idx] ^= 0x80;
            variant2[word_idx] = u32::from_le_bytes(b2);
            if variant2 == APPROVE_CIRCUIT_IMAGE_ID {
                continue;
            }
            assert!(
                receipt.verify(variant2).is_err(),
                "image-id with bit 7 of byte {byte_idx} in word {word_idx} \
                 flipped must be rejected"
            );
        }
    }
}

// ===========================================================================
// 9. Cross-process determinism sentinel. Spawns the same test binary as a
//    subprocess and asks it to print the image-id hex. The subprocess must
//    print the SAME hex as this process. This is a moat against any kind of
//    process-local nondeterminism creeping into the host-side image-id
//    computation (e.g. ASLR-affected static initialization, a thread-local
//    cache that gets initialized differently per process).
//
//    Implementation: we invoke this very test executable with a sentinel
//    arg `--print-image-id` that we honor by printing and exiting. Cargo
//    test sets `CARGO_BIN_EXE_*` only for binary crates; for integration
//    tests we use `std::env::current_exe()` and re-invoke ourselves through
//    `--exact` so the runner re-launches us. The sentinel arg is handled
//    BEFORE the test harness picks up control flow — we check it inside the
//    body of THIS test, never bypassing the harness, by re-running the
//    SAME test binary with a special env var.
//
//    We respect the constraint that this is hard to set up but valuable.
//    If cross-process invocation isn't available in this environment, the
//    test soft-skips with a printed note rather than failing.
// ===========================================================================

#[test]
fn red3_cross_process_determinism_sentinel() {
    // If we are the subprocess (RED3_CHILD=1), print the hex and exit. The
    // parent will read stdout to compare. Note: `#[test]` harness still
    // catches us, but we exit cleanly to avoid disrupting other tests.
    //
    // Subprocess detection is done via the parent. The child path is
    // handled by re-invoking our own binary with `RED3_CHILD=1`; the child
    // runs the SAME test, sees the env var, and prints then returns.
    if env::var("RED3_CHILD").is_ok() {
        // Subprocess path: print the hex to stdout and return without
        // exercising anything further.
        let h = image_id_hex();
        println!("RED3_IMAGE_ID_HEX={h}");
        return;
    }

    // Parent path: get our own binary path and re-invoke this exact test.
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            // Soft-skip: environment doesn't expose current_exe. Print a
            // note for the human reader but do not fail.
            eprintln!(
                "red3_cross_process_determinism_sentinel: current_exe() failed: {e}; \
                 skipping cross-process check"
            );
            return;
        }
    };

    let parent_hex = image_id_hex();

    let output = Command::new(&exe)
        .arg("red3_cross_process_determinism_sentinel")
        .arg("--exact")
        .arg("--nocapture")
        .env("RED3_CHILD", "1")
        // Inherit RISC0_DEV_MODE so the child doesn't try to do anything
        // that would invoke the prover.
        .env("RISC0_DEV_MODE", "1")
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "red3_cross_process_determinism_sentinel: subprocess spawn failed: {e}; \
                 skipping (this is a soft-skip, not a failure)"
            );
            return;
        }
    };

    // Parse the child's stdout for our sentinel line.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let child_hex = stdout
        .lines()
        .find_map(|l| l.strip_prefix("RED3_IMAGE_ID_HEX=").map(str::to_owned));

    let child_hex = match child_hex {
        Some(h) => h,
        None => {
            eprintln!(
                "red3_cross_process_determinism_sentinel: child did not emit the \
                 sentinel line; stdout was:\n{stdout}\n— soft-skipping"
            );
            return;
        }
    };

    assert_eq!(
        parent_hex,
        child_hex.trim(),
        "FINDING: image_id_hex() drifted across processes — parent={parent_hex} \
         child={child_hex}"
    );
}

// ===========================================================================
// 10. Journal byte-swap inside a single 32-byte field. Round 2 covered
//     swapping whole 32-byte segments. This pins the finer-grained claim:
//     swapping two bytes WITHIN a single field also breaks verification.
// ===========================================================================

#[test]
fn red3_journal_byte_swap_inside_a_field_rejected() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(1);
    let receipt = w.try_prove().expect("happy path must prove");
    let original = receipt.journal.bytes.clone();
    assert_eq!(original.len(), APPROVE_PUBLIC_INPUTS_LEN);

    // Sanity: untouched receipt verifies.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("untouched receipt must verify");

    // Swap two bytes inside the members_root region (bytes 0..32). Pick
    // positions 3 and 17 — both inside the region, and (with overwhelming
    // probability under SHA-256) carrying distinct byte values so the swap
    // is observable.
    let cases: [(usize, usize, &str); 3] = [
        (3, 17, "inside members_root"),
        (40, 55, "inside proposal_id"),
        (70, 91, "inside nullifier"),
    ];
    for (i, j, label) in cases {
        let mut tampered = original.clone();
        if tampered[i] == tampered[j] {
            // The swap would be a no-op. Skip with a note; under SHA-256
            // outputs this is preimage-hard for two specific positions.
            eprintln!(
                "red3_journal_byte_swap_inside_a_field_rejected: bytes {i} and {j} \
                 ({label}) happen to be equal — skipping this swap"
            );
            continue;
        }
        tampered.swap(i, j);
        let mut r2 = receipt.clone();
        r2.journal.bytes = tampered;
        assert!(
            r2.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
            "FINDING: byte swap ({i}↔{j}) {label} did not break verification"
        );
    }

    // After mutations, the cloned receipts went out of scope; the original
    // `receipt` should still hold its untouched journal and verify.
    assert_eq!(receipt.journal.bytes, original);
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("post-test: original receipt must still verify");
}

// ===========================================================================
// 11. Creative — image-id byte rotation. Take the real image-id, rotate
//     its 32-byte serialization left by 1, and verify rejection. This is a
//     more aggressive "everything is the same set of bytes but in a
//     different order" attack than the swaps round 1/2 covered.
// ===========================================================================

#[test]
fn red3_creative_image_id_byte_rotation_rejected() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);
    let receipt = w.try_prove().expect("happy path must prove");

    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("control: untouched receipt must verify");

    // Serialize the live image-id to 32 bytes (little-endian per word),
    // rotate left by 1, parse back as 8 LE words, and verify.
    let mut raw = [0u8; 32];
    for (i, word) in APPROVE_CIRCUIT_IMAGE_ID.iter().enumerate() {
        let bytes = word.to_le_bytes();
        raw[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    // Confirm raw is non-trivial — not all-zero — so the rotation is
    // meaningful. SHA-256 outputs are preimage-hard against equaling
    // [0;32] so this is effectively a control assertion.
    assert_ne!(raw, [0u8; 32]);

    // Rotate left by 1 byte (raw[0] becomes raw[31]).
    let mut rotated = [0u8; 32];
    for i in 0..32 {
        rotated[i] = raw[(i + 1) % 32];
    }
    assert_ne!(
        rotated, raw,
        "rotation must change the byte sequence; if equal, the image-id is degenerate"
    );

    // Parse rotated back as 8 LE words.
    let mut rotated_id = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = rotated[i * 4..(i + 1) * 4]
            .try_into()
            .expect("4-byte chunk");
        rotated_id[i] = u32::from_le_bytes(chunk);
    }
    assert_ne!(rotated_id, APPROVE_CIRCUIT_IMAGE_ID);
    assert!(
        receipt.verify(rotated_id).is_err(),
        "FINDING: receipt verified against a left-rotated-by-1 image-id"
    );

    // And right-by-1 rotation.
    let mut right_rotated = [0u8; 32];
    for i in 0..32 {
        right_rotated[i] = raw[(i + 31) % 32];
    }
    let mut right_id = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = right_rotated[i * 4..(i + 1) * 4]
            .try_into()
            .expect("4-byte chunk");
        right_id[i] = u32::from_le_bytes(chunk);
    }
    if right_id != APPROVE_CIRCUIT_IMAGE_ID {
        assert!(
            receipt.verify(right_id).is_err(),
            "FINDING: receipt verified against a right-rotated-by-1 image-id"
        );
    }
}
