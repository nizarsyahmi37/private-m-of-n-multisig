//! Blue-team validator (round 4 — `pack_approve_witness` integration pass)
//! for the LP-0002 Risc0 approve circuit.
//!
//! Rounds 1, 2, and 3 confirmed the foundational defensive properties of
//! the receipt / journal surface, image-id stability, parallel-prover
//! safety, and the wire format `[64-byte public prefix ‖ sk ‖ salt ‖ 640-byte
//! siblings ‖ 20-byte directions]` (47 tests across blue/red/wire-format).
//!
//! Round 4 turns the spotlight on the NEW public helper that landed last
//! round:
//!
//! ```ignore
//! pub const APPROVE_WITNESS_LEN: usize = 788;
//! pub fn pack_approve_witness(
//!     identity: &crypto::Identity,
//!     proof: &crypto::MerkleProof,
//!     members_root: &[u8; 32],
//!     proposal_id: &[u8; 32],
//! ) -> [u8; APPROVE_WITNESS_LEN];
//! ```
//!
//! The aim is to pin THREE properties of the helper before downstream code
//! (the SDK / step-4 verifier program) consumes it:
//!
//! 1. It integrates cleanly with the existing 5-call `write_slice` flow.
//!    Anyone holding the old recipe can mechanically migrate to one
//!    `write_slice(&packed)` with byte-identical journals.
//! 2. Nothing regressed: the original `approve_circuit.rs` 5-call path
//!    still proves and verifies, image-id is unchanged, ELF unchanged.
//! 3. The helper's behavior matches what `src/lib.rs` documents:
//!    fixed-length `[u8; 788]`, byte layout pinned at `[0..32) root`,
//!    `[32..64) pid`, `[64..96) sk`, `[96..128) salt`,
//!    `[128..768) siblings`, `[768..788) directions`.
//!
//! Every test sets `RISC0_DEV_MODE=1` so the file runs in seconds. The
//! defensive assertions are identical under `RISC0_DEV_MODE=0`.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::identity_op)]

use std::env;

use crypto::{
    merkle::MerkleProof, Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH, SALT_LEN,
    SK_LEN,
};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id, ApprovePublicInputs, ChainId,
    APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{
    image_id_hex, pack_approve_witness, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID,
    APPROVE_WITNESS_LEN,
};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// ---------------------------------------------------------------------------
// Shared helpers — self-contained so this integration test file compiles
// independently of `blue_team_program{,_v2,_v3}.rs` and `witness_wire_format`.
// ---------------------------------------------------------------------------

fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: each `#[test]` runs in a fresh process; set once at the
        // top of every test that invokes the prover. Single-threaded with
        // respect to env until the prover (or our own threads) spawns.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

struct ProposalContext {
    chain_id: ChainId,
    state_pda: [u8; 32],
    target_program: [u8; 32],
}

fn default_proposal_context() -> ProposalContext {
    let program_id: [u8; 32] = [0x77; 32];
    let create_key: [u8; 32] = [0x42; 32];
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0x33; 32];
    let chain_id = ChainId::from_u64(0x1234_5678);
    ProposalContext {
        chain_id,
        state_pda,
        target_program,
    }
}

/// Bundle of everything the host needs to invoke `pack_approve_witness`.
/// Self-contained so a single helper call produces every input the prover
/// needs in one go.
struct WitnessBundle {
    identity: Identity,
    proof: MerkleProof,
    members_root: [u8; 32],
    proposal_id: [u8; 32],
}

fn build_witness_bundle(
    members: &[Identity],
    approver_index: usize,
    chain_id: &ChainId,
    state_pda: &[u8; 32],
    index: u64,
    action_bytes: &[u8],
    target_program: &[u8; 32],
) -> WitnessBundle {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .expect("tree.insert must succeed within capacity");
    }
    let members_root = tree.root();
    let proof = tree.proof(approver_index).expect("proof must exist");
    let proposal_id =
        derive_proposal_id(chain_id, state_pda, index, action_bytes, target_program);
    WitnessBundle {
        identity: members[approver_index].clone(),
        proof,
        members_root,
        proposal_id,
    }
}

/// Prove via the OLD 5-call `write_slice` pattern, mirroring exactly the
/// flow in `tests/approve_circuit.rs`. Returns the verified receipt.
fn prove_via_five_calls(w: &WitnessBundle) -> Receipt {
    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&w.members_root);
    public_prefix[32..].copy_from_slice(&w.proposal_id);

    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in w.proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in w.proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    let env_builder = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&w.identity.sk)
        .write_slice(&w.identity.salt)
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build()
        .expect("ExecutorEnv build (5-call) must succeed");

    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover (5-call) must produce a receipt for a valid witness");
    let receipt = prove_info.receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("5-call receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");
    receipt
}

/// Prove via the NEW helper + a single `write_slice(&packed)`. Returns the
/// verified receipt.
fn prove_via_packed_helper(w: &WitnessBundle) -> Receipt {
    let packed =
        pack_approve_witness(&w.identity, &w.proof, &w.members_root, &w.proposal_id);
    let env_builder = ExecutorEnv::builder()
        .write_slice(&packed)
        .build()
        .expect("ExecutorEnv build (helper) must succeed");

    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover (helper) must produce a receipt for a valid witness");
    let receipt = prove_info.receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("helper receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");
    receipt
}

fn decode_journal(receipt: &Receipt) -> ApprovePublicInputs {
    let bytes = receipt.journal.bytes.as_slice();
    assert_eq!(
        bytes.len(),
        APPROVE_PUBLIC_INPUTS_LEN,
        "journal length drift: expected {APPROVE_PUBLIC_INPUTS_LEN}, got {}",
        bytes.len()
    );
    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(bytes);
    ApprovePublicInputs::from_bytes(&arr)
}

// ---------------------------------------------------------------------------
// 1. Helper-packed witness vs OLD 5-call write_slice — both verify with
//    BYTE-IDENTICAL journals.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_parity_with_5_call_write_slice() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness_bundle(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"v4_parity_5call_vs_helper",
        &ctx.target_program,
    );

    // Prover A — the new one-shot helper.
    let receipt_a = prove_via_packed_helper(&w);
    let journal_a = receipt_a.journal.bytes.clone();

    // Prover B — the historical 5-call pattern from `approve_circuit.rs`.
    let receipt_b = prove_via_five_calls(&w);
    let journal_b = receipt_b.journal.bytes.clone();

    // Both receipts verify (already asserted inside `prove_via_*`) and the
    // journals are byte-identical: the helper produces a stream the guest
    // reads with the exact same semantics as the 5-call pattern.
    assert_eq!(
        journal_a, journal_b,
        "helper-packed witness must produce a byte-identical journal to the 5-call pattern"
    );

    // And the decoded bundles must agree on every field, with the
    // host-computed nullifier as a third-party witness.
    let d_a = decode_journal(&receipt_a);
    let d_b = decode_journal(&receipt_b);
    assert_eq!(d_a, d_b, "decoded journals must agree across packings");

    let expected_nullifier = w.identity.nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(d_a.members_root, w.members_root);
    assert_eq!(d_a.proposal_id, w.proposal_id);
    assert_eq!(d_a.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 2. Deterministic: pack the same inputs 100 times; all 100 buffers
//    byte-identical. No hidden RNG, no timestamps, no padding nondeterminism.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_is_deterministic_100x() {
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness_bundle(
        &members,
        3,
        &ctx.chain_id,
        &ctx.state_pda,
        7,
        b"v4_determinism_100x",
        &ctx.target_program,
    );

    let baseline =
        pack_approve_witness(&w.identity, &w.proof, &w.members_root, &w.proposal_id);

    for i in 0..100 {
        let again = pack_approve_witness(
            &w.identity,
            &w.proof,
            &w.members_root,
            &w.proposal_id,
        );
        assert_eq!(
            baseline, again,
            "pack_approve_witness drifted on iteration {i} (non-deterministic packing)"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Return type is a stack-allocated `[u8; APPROVE_WITNESS_LEN]` — not a
//    `Vec<u8>` or other heap-backed buffer. The size of `[u8; N]` equals
//    exactly `N` because there is no header, capacity, or padding.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_returns_array_not_vec() {
    // sizeof check — `[u8; 788]` is exactly 788 bytes on every platform.
    // A `Vec<u8>` would be sizeof(usize) * 3 (ptr + len + cap) = 24 bytes
    // on a 64-bit platform regardless of capacity.
    assert_eq!(
        std::mem::size_of::<[u8; APPROVE_WITNESS_LEN]>(),
        APPROVE_WITNESS_LEN,
        "[u8; APPROVE_WITNESS_LEN] must occupy exactly APPROVE_WITNESS_LEN bytes"
    );
    assert_eq!(
        std::mem::size_of::<[u8; APPROVE_WITNESS_LEN]>(),
        788,
        "[u8; 788] must be exactly 788 bytes — array, not heap-allocated"
    );

    // Also pin alignment: a byte array is 1-byte aligned (no padding), so a
    // pointer to it can be treated as `*const u8` directly.
    assert_eq!(
        std::mem::align_of::<[u8; APPROVE_WITNESS_LEN]>(),
        1,
        "byte array must be 1-byte aligned"
    );

    // Exercise the helper and pin that the value really IS an owned array
    // (compile-time check via the assignment / size_of_val).
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness_bundle(
        &members,
        0,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"v4_array_not_vec",
        &ctx.target_program,
    );
    let buf: [u8; APPROVE_WITNESS_LEN] =
        pack_approve_witness(&w.identity, &w.proof, &w.members_root, &w.proposal_id);
    assert_eq!(std::mem::size_of_val(&buf), APPROVE_WITNESS_LEN);
    assert_eq!(buf.len(), APPROVE_WITNESS_LEN);
}

// ---------------------------------------------------------------------------
// 4. Layout byte-for-byte: each field is a different repeated byte; the
//    packed buffer reflects each offset precisely.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_layout_byte_for_byte() {
    // Pick distinguishable bytes that don't collide across fields. The
    // siblings region uses an entire per-level marker pattern (`0x40 + level`)
    // so any silent level swap is also caught.
    let sk_byte = 0x11u8;
    let salt_byte = 0x22u8;
    let root_byte = 0x33u8;
    let pid_byte = 0x44u8;
    let dir_byte = 0x01u8;

    let identity = Identity::new([sk_byte; 32], [salt_byte; 32]);
    let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        let marker = 0x40u8.wrapping_add(level as u8);
        siblings[level] = [marker; HASH_LEN];
    }
    let indices = [true; MERKLE_DEPTH]; // every direction byte = 1
    let proof = MerkleProof { siblings, indices };
    let members_root = [root_byte; 32];
    let proposal_id = [pid_byte; 32];

    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);
    assert_eq!(buf.len(), APPROVE_WITNESS_LEN);
    assert_eq!(buf.len(), 788);

    // [0..32) members_root
    for i in 0..32 {
        assert_eq!(
            buf[i], root_byte,
            "buf[{i}] should be members_root marker 0x{root_byte:02x}, got 0x{:02x}",
            buf[i],
        );
    }
    // [32..64) proposal_id
    for i in 32..64 {
        assert_eq!(
            buf[i], pid_byte,
            "buf[{i}] should be proposal_id marker 0x{pid_byte:02x}, got 0x{:02x}",
            buf[i],
        );
    }
    // [64..96) sk
    for i in 64..96 {
        assert_eq!(
            buf[i], sk_byte,
            "buf[{i}] should be sk marker 0x{sk_byte:02x}, got 0x{:02x}",
            buf[i],
        );
    }
    // [96..128) salt
    for i in 96..128 {
        assert_eq!(
            buf[i], salt_byte,
            "buf[{i}] should be salt marker 0x{salt_byte:02x}, got 0x{:02x}",
            buf[i],
        );
    }
    // [128..768) siblings — 20 × 32 bytes, level-0 first, marker per level.
    for level in 0..MERKLE_DEPTH {
        let marker = 0x40u8.wrapping_add(level as u8);
        let start = 128 + level * HASH_LEN;
        for off in 0..HASH_LEN {
            assert_eq!(
                buf[start + off], marker,
                "siblings[level={level}][{off}] = 0x{:02x}, expected marker 0x{marker:02x}",
                buf[start + off],
            );
        }
    }
    // [768..788) directions — 20 bytes, all 1.
    for i in 768..788 {
        assert_eq!(
            buf[i], dir_byte,
            "buf[{i}] (direction) should be 0x{dir_byte:02x}, got 0x{:02x}",
            buf[i],
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Full pipeline using ONLY the public API: enroll → derive proposal_id →
//    pack_approve_witness → ExecutorEnv::builder().write_slice → prove →
//    verify → decode. No internal types, no `private_multisig_program::*`
//    indirection — just the published surface.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_then_prove_then_verify_full_flow() {
    ensure_dev_mode();

    // Enroll members and freeze the root.
    let members: Vec<Identity> = (0..7u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .expect("insert must succeed");
    }
    let members_root = tree.root();

    // Derive proposal_id via the canonical core helper.
    let program_id: [u8; 32] = [0xAA; 32];
    let create_key: [u8; 32] = [0xBB; 32];
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCC; 32];
    let action_bytes = b"v4_full_flow_action".to_vec();
    let chain_id = ChainId::from_u64(0xDEAD_BEEF);
    let proposal_id =
        derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program);

    // Pick an approving member and derive its Merkle proof.
    let approver_index = 4usize;
    let approver = members[approver_index].clone();
    let proof = tree.proof(approver_index).expect("proof must exist");

    // Pack via the new public helper.
    let packed = pack_approve_witness(&approver, &proof, &members_root, &proposal_id);
    assert_eq!(packed.len(), APPROVE_WITNESS_LEN);

    // Build env, prove, verify.
    let env_builder = ExecutorEnv::builder()
        .write_slice(&packed)
        .build()
        .expect("ExecutorEnv build must succeed");
    let prover = default_prover();
    let receipt = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must succeed under full-flow witness")
        .receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify against pinned image-id");

    // Decode and cross-check every field independently.
    let bytes = receipt.journal.bytes.clone();
    assert_eq!(bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
    let mut journal_arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    journal_arr.copy_from_slice(&bytes);
    let decoded = ApprovePublicInputs::from_bytes(&journal_arr);

    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&proposal_id);
    assert_eq!(decoded.members_root, members_root);
    assert_eq!(decoded.proposal_id, proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 6. Same member, two different proposals — two packed witnesses → two
//    receipts → two distinct journals (proposal_id and nullifier differ).
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_same_member_different_proposals_different_journals() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let w_a = build_witness_bundle(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"v4_proposal_alpha",
        &ctx.target_program,
    );
    let w_b = build_witness_bundle(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        1,
        b"v4_proposal_beta",
        &ctx.target_program,
    );

    // Sanity: same member at the host layer, but different proposal_ids.
    assert_eq!(w_a.identity.sk, w_b.identity.sk);
    assert_eq!(w_a.identity.salt, w_b.identity.salt);
    assert_eq!(w_a.members_root, w_b.members_root);
    assert_ne!(w_a.proposal_id, w_b.proposal_id);

    // Pack each via the helper.
    let packed_a =
        pack_approve_witness(&w_a.identity, &w_a.proof, &w_a.members_root, &w_a.proposal_id);
    let packed_b =
        pack_approve_witness(&w_b.identity, &w_b.proof, &w_b.members_root, &w_b.proposal_id);
    // They share root and sk/salt regions but differ on proposal_id.
    assert_eq!(&packed_a[..32], &packed_b[..32], "members_root regions");
    assert_ne!(&packed_a[32..64], &packed_b[32..64], "proposal_id regions");
    assert_eq!(&packed_a[64..128], &packed_b[64..128], "sk||salt regions");

    let r_a = prove_via_packed_helper(&w_a);
    let r_b = prove_via_packed_helper(&w_b);

    let d_a = decode_journal(&r_a);
    let d_b = decode_journal(&r_b);

    // Two distinct journals — proposal_id and nullifier differ; root agrees.
    assert_eq!(d_a.members_root, d_b.members_root);
    assert_ne!(d_a.proposal_id, d_b.proposal_id);
    assert_ne!(
        d_a.nullifier, d_b.nullifier,
        "same member on different proposals must yield different nullifiers"
    );
    assert_ne!(
        r_a.journal.bytes, r_b.journal.bytes,
        "two distinct (member, proposal) pairs must yield two distinct journals"
    );
}

// ---------------------------------------------------------------------------
// 7. Helper's output passes through `ExecutorEnv::builder().write_slice` and
//    matches the guest's 5-read pattern: a one-shot 788-byte write is the
//    SAME buffer the guest would read if the host had written five slices.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_with_helper_buffer_in_executor_env() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness_bundle(
        &members,
        1,
        &ctx.chain_id,
        &ctx.state_pda,
        42,
        b"v4_helper_buffer_in_env",
        &ctx.target_program,
    );

    let packed =
        pack_approve_witness(&w.identity, &w.proof, &w.members_root, &w.proposal_id);

    // 1) Pass `packed` directly into `ExecutorEnv::builder().write_slice` —
    //    the helper's output must be acceptable to the prover unmodified.
    let env_builder = ExecutorEnv::builder()
        .write_slice(&packed)
        .build()
        .expect("ExecutorEnv must accept the helper's 788-byte buffer directly");
    let prover = default_prover();
    let receipt = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must succeed on helper-packed buffer")
        .receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify");

    // 2) The buffer order must match the guest's 5-read pattern. Reconstruct
    //    the 5-call view (public_prefix ‖ sk ‖ salt ‖ siblings_flat ‖ dirs)
    //    by concatenating the per-field slices and compare to `packed`.
    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&w.members_root);
    public_prefix[32..].copy_from_slice(&w.proposal_id);
    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in w.proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in w.proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    let mut concat = Vec::with_capacity(APPROVE_WITNESS_LEN);
    concat.extend_from_slice(&public_prefix);
    concat.extend_from_slice(&w.identity.sk);
    concat.extend_from_slice(&w.identity.salt);
    concat.extend_from_slice(&siblings_flat);
    concat.extend_from_slice(&direction_bytes);
    assert_eq!(concat.len(), APPROVE_WITNESS_LEN);
    assert_eq!(
        concat.as_slice(),
        packed.as_slice(),
        "helper-packed buffer must equal the 5-call concatenation, byte for byte"
    );

    // 3) Sanity: journal decodes cleanly with host-computed nullifier.
    let decoded = decode_journal(&receipt);
    let expected_nullifier = w.identity.nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 8. `APPROVE_WITNESS_LEN` matches the hand-computed sum across crypto
//    constants. If any crypto constant drifts (MERKLE_DEPTH bumps, HASH_LEN
//    changes), this test is the loud signal.
// ---------------------------------------------------------------------------

#[test]
fn v4_approve_witness_len_consistent_across_crates() {
    // Direct equality with the documented total.
    assert_eq!(APPROVE_WITNESS_LEN, 788);

    // Reconstruction from `crypto::*` constants — this is the formula that
    // the doc-block in `src/lib.rs` advertises.
    let reconstructed = 64 + SK_LEN + SALT_LEN + MERKLE_DEPTH * HASH_LEN + MERKLE_DEPTH;
    assert_eq!(
        APPROVE_WITNESS_LEN, reconstructed,
        "APPROVE_WITNESS_LEN ({}) ≠ 64 + crypto::SK_LEN ({}) + crypto::SALT_LEN ({}) + \
         crypto::MERKLE_DEPTH ({}) * crypto::HASH_LEN ({}) + crypto::MERKLE_DEPTH ({}) = {}",
        APPROVE_WITNESS_LEN, SK_LEN, SALT_LEN, MERKLE_DEPTH, HASH_LEN, MERKLE_DEPTH,
        reconstructed,
    );

    // Pin the individual crypto constants too — each contributes to the
    // formula, so any silent drift is highlighted directly.
    assert_eq!(SK_LEN, 32);
    assert_eq!(SALT_LEN, 32);
    assert_eq!(MERKLE_DEPTH, 20);
    assert_eq!(HASH_LEN, 32);
}

// ---------------------------------------------------------------------------
// 9. Sentinel: the existing `approve_circuit` flow still works. Re-runs the
//    EXACT pattern from `tests/approve_circuit.rs` inline to prove the new
//    helper did not regress the historical path.
// ---------------------------------------------------------------------------

#[test]
fn v4_existing_5_call_approve_circuit_test_path_still_works() {
    ensure_dev_mode();

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

    // Synthetic proposal — mirrors the parameters in `approve_circuit.rs`.
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let proposal_id = derive_proposal_id(
        &chain_id,
        &state_pda,
        0,
        &action_bytes,
        &target_program,
    );

    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&proposal_id);
    let expected_bundle = ApprovePublicInputs {
        members_root,
        proposal_id,
        nullifier: expected_nullifier,
    };

    // 5-call witness layout — exactly what approve_circuit.rs uses.
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

    let env_builder = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&approver.sk)
        .write_slice(&approver.salt)
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build()
        .expect("ExecutorEnv build must succeed (legacy 5-call path)");
    let prover = default_prover();
    let receipt = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("legacy 5-call prove must still succeed")
        .receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("legacy 5-call receipt must verify");

    let journal_bytes = receipt.journal.bytes.as_slice();
    assert_eq!(journal_bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
    let mut journal_arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    journal_arr.copy_from_slice(journal_bytes);
    let decoded = ApprovePublicInputs::from_bytes(&journal_arr);
    assert_eq!(decoded, expected_bundle, "legacy 5-call journal disagreed");
}

// ---------------------------------------------------------------------------
// 10. Documentation accuracy: the doc-block above `pack_approve_witness` in
//     `src/lib.rs` must (a) mention each byte range and (b) field names must
//     match the implementation. Reads `src/lib.rs` via `include_str!`.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_documentation_is_accurate() {
    let src: &str = include_str!("../src/lib.rs");

    // Doc-block markers — every documented offset range.
    let required_ranges =
        ["[0..32)", "[32..64)", "[64..96)", "[96..128)", "[128..768)", "[768..788)"];
    for marker in &required_ranges {
        assert!(
            src.contains(marker),
            "lib.rs doc-block must mention byte range {marker} for pack_approve_witness; \
             searched in:\n{src}"
        );
    }

    // Field names mentioned in the doc-block — they must match the actual
    // parameter list / impl-side `out[..].copy_from_slice(...)` choices.
    let required_field_names = ["members_root", "proposal_id", "sk", "salt", "siblings", "directions"];
    for name in &required_field_names {
        assert!(
            src.contains(name),
            "lib.rs must mention the field name `{name}` somewhere — \
             pack_approve_witness doc-block uses it"
        );
    }

    // The function signature must take exactly the four named params we expect.
    assert!(
        src.contains("pub fn pack_approve_witness("),
        "pack_approve_witness must be a pub fn (the helper is public API)"
    );
    assert!(
        src.contains("identity: &crypto::Identity"),
        "pack_approve_witness must take `identity: &crypto::Identity`"
    );
    assert!(
        src.contains("proof: &crypto::MerkleProof"),
        "pack_approve_witness must take `proof: &crypto::MerkleProof`"
    );
    assert!(
        src.contains("members_root: &[u8; 32]"),
        "pack_approve_witness must take `members_root: &[u8; 32]`"
    );
    assert!(
        src.contains("proposal_id: &[u8; 32]"),
        "pack_approve_witness must take `proposal_id: &[u8; 32]`"
    );

    // The return type must be a fixed-size array of APPROVE_WITNESS_LEN.
    assert!(
        src.contains("-> [u8; APPROVE_WITNESS_LEN]"),
        "pack_approve_witness must return `[u8; APPROVE_WITNESS_LEN]`"
    );

    // APPROVE_WITNESS_LEN must be a public constant equal to 788.
    assert!(
        src.contains("pub const APPROVE_WITNESS_LEN: usize = 788;"),
        "APPROVE_WITNESS_LEN must be `pub const ... usize = 788`"
    );
}

// ---------------------------------------------------------------------------
// 11. Two unrelated members → distinct sk regions. Bytes at [64..96) must
//     differ.
// ---------------------------------------------------------------------------

#[test]
fn v4_two_unrelated_members_two_packed_buffers_have_distinct_sk_regions() {
    // Two identities with disjoint `sk` values; same salt to isolate the
    // sk-region check (the salt window must agree, only sk must differ).
    let id_a = Identity::new([0xAAu8; 32], [0x10u8; 32]);
    let id_b = Identity::new([0xBBu8; 32], [0x10u8; 32]);
    assert_ne!(id_a.sk, id_b.sk);

    // Inputs for the rest of the witness — identical for both packings so
    // the ONLY observable difference between the two buffers is the sk
    // region. Sentinel that the helper writes sk to the correct offset.
    let siblings = [[0x77u8; HASH_LEN]; MERKLE_DEPTH];
    let indices = [false; MERKLE_DEPTH];
    let proof = MerkleProof { siblings, indices };
    let members_root = [0x55u8; 32];
    let proposal_id = [0x66u8; 32];

    let packed_a = pack_approve_witness(&id_a, &proof, &members_root, &proposal_id);
    let packed_b = pack_approve_witness(&id_b, &proof, &members_root, &proposal_id);

    // [0..64) — public prefix identical.
    assert_eq!(&packed_a[..64], &packed_b[..64]);
    // [64..96) — sk region must differ.
    assert_ne!(
        &packed_a[64..96],
        &packed_b[64..96],
        "different sk values must produce different bytes at offset [64..96)"
    );
    // Spot-check the actual bytes are exactly sk.
    assert_eq!(&packed_a[64..96], &id_a.sk);
    assert_eq!(&packed_b[64..96], &id_b.sk);
    // [96..128) — salt region identical (same salt input).
    assert_eq!(&packed_a[96..128], &packed_b[96..128]);
    // [128..) — siblings and directions identical.
    assert_eq!(&packed_a[128..], &packed_b[128..]);
}

// ---------------------------------------------------------------------------
// 12. Wider-integration sentinel: pack a witness for a deep member in a 5000-
//     member tree. Output is 788 bytes; receipt verifies.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_with_5000_member_tree() {
    ensure_dev_mode();

    // 5000 members under MERKLE_DEPTH=20 (capacity 1<<20) — well within
    // bounds. Approver at index 4999 — the deepest reachable position.
    let members: Vec<Identity> = (0..5000u32)
        .map(|i| deterministic_identity((i % 251 + 1) as u8))
        .collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .expect("insert within capacity must succeed");
    }
    let members_root = tree.root();

    let approver_index = 4999usize;
    let approver = members[approver_index].clone();
    let proof = tree.proof(approver_index).expect("proof for deep member");

    let ctx = default_proposal_context();
    let proposal_id = derive_proposal_id(
        &ctx.chain_id,
        &ctx.state_pda,
        4999,
        b"v4_5000_member_action",
        &ctx.target_program,
    );

    let packed = pack_approve_witness(&approver, &proof, &members_root, &proposal_id);
    assert_eq!(
        packed.len(),
        APPROVE_WITNESS_LEN,
        "packed buffer must be 788 bytes regardless of tree size"
    );
    assert_eq!(packed.len(), 788);

    // Prove and verify — exercises the full path with a non-trivial tree.
    let env_builder = ExecutorEnv::builder()
        .write_slice(&packed)
        .build()
        .expect("env build must succeed");
    let prover = default_prover();
    let receipt = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prove for 5000-member tree must succeed")
        .receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("5000-member receipt must verify");

    let decoded = decode_journal(&receipt);
    assert_eq!(decoded.members_root, members_root);
    assert_eq!(decoded.proposal_id, proposal_id);
    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 13. Image-id UNCHANGED after the helper addition. The helper is host-side
//     only — the guest source is untouched, so the image-id MUST be the
//     pinned value from round-1 image-id-stability.
// ---------------------------------------------------------------------------

#[test]
fn v4_image_id_unchanged_after_helper_addition() {
    // Pinned hex from `tests/image_id_stability.rs::PINNED_IMAGE_ID_HEX`.
    const PINNED_IMAGE_ID_HEX: &str =
        "5569a424071f302a8c66a41285828618866d58f3d09f6241be9bd1ed3a20053d";

    let actual = image_id_hex();
    assert_eq!(
        actual.len(),
        64,
        "image_id_hex() length must remain 64 hex chars (32 bytes)"
    );
    assert_eq!(
        actual, PINNED_IMAGE_ID_HEX,
        "image_id_hex() drifted after `pack_approve_witness` was added! \
         The helper is HOST-SIDE only — adding it must NOT change the guest \
         ELF or its image-id. Expected: {PINNED_IMAGE_ID_HEX}, actual: {actual}"
    );

    // Cross-check via the word array: same constant in two representations.
    let bytes = hex::decode(&actual).expect("image_id_hex must be valid hex");
    assert_eq!(bytes.len(), 32);
    let mut words = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4]
            .try_into()
            .expect("4-byte chunk slice");
        words[i] = u32::from_le_bytes(chunk);
    }
    assert_eq!(
        words, APPROVE_CIRCUIT_IMAGE_ID,
        "APPROVE_CIRCUIT_IMAGE_ID drifted from the pinned LE-decoded word array"
    );
}

// ---------------------------------------------------------------------------
// 14. Direction encoding implicit in the helper: member at index 5 has
//     binary `101` → direction bytes `[1, 0, 1, 0, 0, …, 0]`, LSB-first.
// ---------------------------------------------------------------------------

#[test]
fn v4_pack_approve_witness_uses_le_index_bit_extraction_implicitly() {
    // 11 leaves so indices 0..=10 are reachable; we want index 5 = 0b101.
    let members: Vec<Identity> = (0..11u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let members_root = tree.root();
    let approver_index = 5usize;
    let approver = members[approver_index].clone();
    let proof = tree.proof(approver_index).expect("proof for index 5");

    let ctx = default_proposal_context();
    let proposal_id = derive_proposal_id(
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"v4_le_index_bit_extraction",
        &ctx.target_program,
    );

    let packed = pack_approve_witness(&approver, &proof, &members_root, &proposal_id);

    // Directions live at offset 768..788.
    // Expected, LSB-first: 5 = 0b...00101 → bit0=1, bit1=0, bit2=1, rest 0.
    assert_eq!(
        packed[768], 1u8,
        "direction[0] (LSB of index 5) should be 1, got {}",
        packed[768],
    );
    assert_eq!(
        packed[768 + 1],
        0u8,
        "direction[1] (bit 1 of index 5) should be 0, got {}",
        packed[768 + 1],
    );
    assert_eq!(
        packed[768 + 2],
        1u8,
        "direction[2] (bit 2 of index 5) should be 1, got {}",
        packed[768 + 2],
    );
    for level in 3..MERKLE_DEPTH {
        assert_eq!(
            packed[768 + level], 0u8,
            "direction[{level}] should be 0 (index 5 only has bits 0 and 2 set), got {}",
            packed[768 + level],
        );
    }

    // Full equality vs the hand-computed expected.
    let mut expected = [0u8; MERKLE_DEPTH];
    expected[0] = 1;
    expected[2] = 1;
    assert_eq!(
        &packed[768..788],
        &expected[..],
        "direction bytes for index 5 must be [1,0,1,0,…,0]"
    );
}
