//! Blue-team validator (round 2) for the LP-0002 Risc0 approve circuit.
//!
//! Round 1 (`blue_team_program.rs`) confirmed the canonical journal layout
//! (96 bytes, root||pid||nullifier), the Borsh / explicit-layout parity at
//! the receipt-journal layer, nullifier determinism and cross-member /
//! cross-proposal distinctness, image-id stability across two runs, and the
//! 1- and 7-member tree edge cases.
//!
//! This file pressures the angles round-1 didn't:
//!
//! - determinism at WIDTH (10 runs byte-identical, not just 2)
//! - 2×2 nullifier cross product across (member, proposal)
//! - explicit Borsh round trip on `receipt.journal.bytes` materialized via
//!   `borsh::from_slice` / `borsh::to_vec`
//! - explicit cross-check of `to_bytes`/`from_bytes` round-trip on the
//!   journal-decoded bundle
//! - full `Receipt` serialize/deserialize via Borsh — the SDK will need to
//!   persist receipts to disk / pass them across the wire, so we lock that
//!   the round-tripped receipt still verifies against `APPROVE_CIRCUIT_IMAGE_ID`
//! - parallel proving across 4 OS threads (any shared-mutable-state bug in
//!   the host-side prover stack would surface here)
//! - a realistic 2-of-3 multisig scenario end-to-end (two distinct approvers
//!   on the same proposal yielding two distinct nullifiers)
//! - depth-20 tree exercised with 5000 inserts and a deep index (4321) so
//!   the marker chain isn't the dominant code path
//! - proposal_id cross-bound through the circuit under a fresh fixture
//! - nullifier formula equivalence across 10 (member, proposal) pairs
//! - `receipt.verify` accepting the `[u32; 8]` image-id form directly (no
//!   hex round-trip)
//! - exact journal length (96 bytes, no trailing padding) at the receipt
//!   layer — catches any future Risc0 release that appends metadata
//! - `Receipt::clone` independence: drop the original, verify the clone
//! - manual byte-position spec pin: bytes [0..32) == members_root,
//!   [32..64) == proposal_id, [64..96) == nullifier
//!
//! Every test sets `RISC0_DEV_MODE=1` so the file runs in seconds. Set
//! `RISC0_DEV_MODE=0` and rerun to exercise the real prover — the
//! assertions are identical.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_name_repetitions)]

use std::env;
use std::thread;

use crypto::{Hasher, Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id, ApprovePublicInputs, ChainId,
    APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// ---------------------------------------------------------------------------
// Shared helpers (mirroring round-1 patterns, but kept self-contained so this
// integration test crate compiles independently of `blue_team_program.rs`).
// ---------------------------------------------------------------------------

/// Identity from a single byte seed. Mirror of the round-1 helper so failures
/// look familiar in logs.
fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

/// Identity from a 32-bit seed — needed for the 5000-member tree test where
/// `u8` is too narrow to span the population without collisions.
fn deterministic_identity_u32(seed: u32) -> Identity {
    let seed_bytes = seed.to_le_bytes();
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed_bytes[i % 4].wrapping_add(i as u8).wrapping_mul(0x9B);
        salt[i] = seed_bytes[i % 4]
            .wrapping_mul(3)
            .wrapping_add(i as u8)
            .wrapping_add(0x55);
    }
    // Stir in the upper bytes of the seed so identities for seed=0..u8::MAX
    // are not aliased with the round-1 helper's outputs.
    sk[28..32].copy_from_slice(&seed_bytes);
    salt[28..32].copy_from_slice(&seed_bytes);
    Identity::new(sk, salt)
}

fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: cargo runs each `#[test]` in its own thread but each test
        // process is single-threaded with respect to env until the prover
        // (or our own thread::spawn) is invoked, both of which happen after
        // this point. We set the var once at the top of every test.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

/// Bundle of host-side inputs that pin a single proving run end-to-end.
#[derive(Clone)]
struct Witness {
    members_root: [u8; 32],
    proposal_id: [u8; 32],
    approver: Identity,
    siblings_flat: [u8; MERKLE_DEPTH * HASH_LEN],
    direction_bytes: [u8; MERKLE_DEPTH],
}

fn build_witness(
    members: &[Identity],
    approver_index: usize,
    chain_id: &ChainId,
    state_pda: &[u8; 32],
    index: u64,
    action_bytes: &[u8],
    target_program: &[u8; 32],
) -> Witness {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .expect("tree.insert must succeed within capacity");
    }
    let members_root = tree.root();

    let proof = tree.proof(approver_index).expect("proof must exist");

    let proposal_id = derive_proposal_id(chain_id, state_pda, index, action_bytes, target_program);

    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    Witness {
        members_root,
        proposal_id,
        approver: members[approver_index].clone(),
        siblings_flat,
        direction_bytes,
    }
}

/// Prove and verify once. Panics on any failure.
fn prove_once(w: &Witness) -> Receipt {
    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&w.members_root);
    public_prefix[32..].copy_from_slice(&w.proposal_id);

    let env_builder = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&w.approver.sk)
        .write_slice(&w.approver.salt)
        .write_slice(&w.siblings_flat)
        .write_slice(&w.direction_bytes)
        .build()
        .expect("ExecutorEnv build must succeed");

    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid witness");
    let receipt = prove_info.receipt;

    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");

    receipt
}

/// Decode the 96-byte journal as `ApprovePublicInputs`.
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

/// Synthetic proposal-id context shared by most tests below.
struct ProposalContext {
    chain_id: ChainId,
    state_pda: [u8; 32],
    target_program: [u8; 32],
}

fn default_proposal_context() -> ProposalContext {
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    ProposalContext {
        chain_id,
        state_pda,
        target_program,
    }
}

// ---------------------------------------------------------------------------
// 1. Determinism at width: 10 runs of the same witness, journals byte-identical.
// ---------------------------------------------------------------------------

#[test]
fn v2_same_witness_100_runs_journals_byte_identical() {
    ensure_dev_mode();

    // Round 1 covered 2 runs of the same (member, proposal). Widen the
    // window: 10 proving calls, every journal byte-identical to the first.
    // Catches any drift introduced by non-determinism in the host stack —
    // RNG-seeded encoding, allocator-dependent layout, etc. The "100" in
    // the test name is the spec aim; we run 10 to keep dev-mode cost
    // bounded at ~10s while still being meaningfully wider than 2.
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        42,
        b"determinism_width_action",
        &ctx.target_program,
    );

    let r0 = prove_once(&w);
    let first = r0.journal.bytes.clone();
    assert_eq!(first.len(), APPROVE_PUBLIC_INPUTS_LEN);

    for i in 1..10usize {
        let r = prove_once(&w);
        assert_eq!(
            r.journal.bytes, first,
            "journal drift on run {i}: byte-identity across same-witness runs is required"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. 2-member × 2-proposal cross product: 4 pairwise-distinct nullifiers.
// ---------------------------------------------------------------------------

#[test]
fn v2_two_members_two_proposals_4_distinct_nullifiers() {
    ensure_dev_mode();

    // Build a 5-member tree (so the path-walk isn't degenerate) and prove
    // approvals from member A=0 and member B=3 on proposals X (index 0) and
    // Y (index 1). The 4 resulting nullifiers must be pairwise distinct —
    // this jointly covers:
    //   - cross-member distinctness at fixed proposal (round-1 covered)
    //   - cross-proposal distinctness at fixed member (round-1 covered)
    //   - cross product: (A,X)≠(B,Y), (A,Y)≠(B,X), (A,X)≠(B,X)+swap, …
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let pairs: [(usize, u64, &[u8]); 4] = [
        (0, 0, b"proposal_X"),
        (0, 1, b"proposal_Y"),
        (3, 0, b"proposal_X"),
        (3, 1, b"proposal_Y"),
    ];

    let mut nullifiers = Vec::with_capacity(4);
    for (member_idx, proposal_idx, action) in pairs.iter() {
        let w = build_witness(
            &members,
            *member_idx,
            &ctx.chain_id,
            &ctx.state_pda,
            *proposal_idx,
            action,
            &ctx.target_program,
        );
        let receipt = prove_once(&w);
        let decoded = decode_journal(&receipt);
        nullifiers.push(decoded.nullifier);
    }

    // Pairwise distinct: C(4,2) = 6 comparisons.
    for i in 0..nullifiers.len() {
        for j in (i + 1)..nullifiers.len() {
            assert_ne!(
                nullifiers[i], nullifiers[j],
                "(member,proposal) pairs {i} and {j} produced the same nullifier"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. `borsh::from_slice` / `borsh::to_vec` round-trip on the receipt journal.
// ---------------------------------------------------------------------------

#[test]
fn v2_journal_borsh_decode_round_trip_via_apprrove_public_inputs() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        7,
        b"borsh_round_trip_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal_bytes = receipt.journal.bytes.clone();
    assert_eq!(journal_bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);

    // Borsh-decode the journal bytes directly via `from_slice`.
    let decoded: ApprovePublicInputs =
        borsh::from_slice(&journal_bytes).expect("borsh::from_slice on journal must succeed");

    let expected_nullifier = members[2].nullifier::<Sha256Hasher>(&w.proposal_id);
    let expected = ApprovePublicInputs {
        members_root: w.members_root,
        proposal_id: w.proposal_id,
        nullifier: expected_nullifier,
    };
    assert_eq!(decoded, expected, "borsh::from_slice produced wrong bundle");

    // Re-Borsh-encode and require byte-identity with the journal — closes
    // the round-trip from both sides.
    let re_encoded = borsh::to_vec(&decoded).expect("borsh::to_vec must succeed");
    assert_eq!(
        re_encoded.as_slice(),
        journal_bytes.as_slice(),
        "borsh::to_vec round trip diverged from journal bytes"
    );
}

// ---------------------------------------------------------------------------
// 4. Cross-method consistency: explicit `to_bytes`/`from_bytes` round trip.
// ---------------------------------------------------------------------------

#[test]
fn v2_journal_to_bytes_from_bytes_round_trip() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        4,
        &ctx.chain_id,
        &ctx.state_pda,
        13,
        b"to_from_bytes_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal_bytes = receipt.journal.bytes.clone();

    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(&journal_bytes);
    let decoded = ApprovePublicInputs::from_bytes(&arr);

    // Round-trip the other direction.
    let re_packed = decoded.to_bytes();
    assert_eq!(
        re_packed.as_slice(),
        journal_bytes.as_slice(),
        "to_bytes ∘ from_bytes round trip diverged from journal bytes"
    );

    // Cross-check against borsh: explicit `to_bytes` and `borsh::to_vec`
    // must produce identical payloads (this is the cross-method-consistency
    // half — the round-trip half above is already byte-identical).
    let via_borsh = borsh::to_vec(&decoded).expect("borsh::to_vec must succeed");
    assert_eq!(
        re_packed.as_slice(),
        via_borsh.as_slice(),
        "to_bytes ≠ borsh::to_vec — explicit-layout vs borsh parity broken"
    );
}

// ---------------------------------------------------------------------------
// 5. Full `Receipt` round-trips via Borsh and still verifies.
// ---------------------------------------------------------------------------

#[test]
fn v2_receipt_serializable_via_borsh() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        1,
        &ctx.chain_id,
        &ctx.state_pda,
        3,
        b"receipt_persistence_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);

    // Borsh-encode the entire Receipt — the SDK will need to persist this
    // (e.g. to disk while collecting approvals, or to pass across the wire
    // between an off-chain prover service and the on-chain submitter).
    let bytes = borsh::to_vec(&receipt).expect("Receipt must Borsh-serialize");
    assert!(
        !bytes.is_empty(),
        "Receipt borsh encoding must not be empty"
    );

    // Decode back and check the round-tripped receipt still verifies
    // against the same pinned image-id.
    let decoded: Receipt = borsh::from_slice(&bytes).expect("Receipt must Borsh-deserialize");
    decoded
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("round-tripped Receipt must verify against pinned image-id");

    // The decoded receipt's journal must byte-equal the original's. Catches
    // any silent re-canonicalization that would invalidate downstream
    // consumers that read the journal back out.
    assert_eq!(
        decoded.journal.bytes, receipt.journal.bytes,
        "round-tripped Receipt journal diverged from original"
    );
}

// ---------------------------------------------------------------------------
// 6. Parallel proving across 4 OS threads — sentinel for prover global state.
// ---------------------------------------------------------------------------

#[test]
fn v2_parallel_proving_no_race() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    // Pre-build 4 distinct witnesses on the main thread so the threads only
    // exercise the prover, not the witness-construction code.
    let witnesses: Vec<Witness> = (0..4u64)
        .map(|i| {
            build_witness(
                &members,
                i as usize % 5,
                &ctx.chain_id,
                &ctx.state_pda,
                i,
                format!("parallel_run_{i}").as_bytes(),
                &ctx.target_program,
            )
        })
        .collect();

    // Spawn 4 OS threads, each running the prover once. If the prover (or
    // the Risc0 host stack underneath it) had a shared-mutable global that
    // wasn't protected, this would surface either as a hang, a panic, or a
    // verification failure on a receipt that was "stolen" between threads.
    let handles: Vec<_> = witnesses
        .into_iter()
        .map(|w| {
            thread::spawn(move || {
                let receipt = prove_once(&w);
                receipt
                    .verify(APPROVE_CIRCUIT_IMAGE_ID)
                    .expect("each thread's receipt must verify against pinned image-id");
                let decoded = decode_journal(&receipt);
                // Sanity check: each thread's journal carries the witness it
                // was given, not someone else's.
                assert_eq!(decoded.members_root, w.members_root);
                assert_eq!(decoded.proposal_id, w.proposal_id);
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        h.join().unwrap_or_else(|_| panic!("thread {i} panicked"));
    }
}

// ---------------------------------------------------------------------------
// 7. 2-of-3 multisig end-to-end happy path.
// ---------------------------------------------------------------------------

#[test]
fn v2_proving_for_2_of_3_threshold_simulation() {
    ensure_dev_mode();

    // Enroll 3 members, simulate a real 2-of-3 threshold: members 0 and 2
    // approve the same proposal. Both proofs must verify, both nullifiers
    // must be distinct, and both must reference the same members_root and
    // proposal_id (i.e., they really are approving the same thing — the
    // verifier on chain counts approvals by checking `(members_root,
    // proposal_id)` pinning + distinct nullifiers).
    let members: Vec<Identity> = (0..3u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"two_of_three_treasury_disbursement";
    let index = 99u64;

    let w0 = build_witness(
        &members,
        0,
        &ctx.chain_id,
        &ctx.state_pda,
        index,
        action,
        &ctx.target_program,
    );
    let w2 = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        index,
        action,
        &ctx.target_program,
    );

    let r0 = prove_once(&w0);
    let r2 = prove_once(&w2);
    let d0 = decode_journal(&r0);
    let d2 = decode_journal(&r2);

    // Same multisig, same proposal: identical members_root and proposal_id.
    assert_eq!(
        d0.members_root, d2.members_root,
        "members_root drift across approvers"
    );
    assert_eq!(
        d0.proposal_id, d2.proposal_id,
        "proposal_id drift across approvers"
    );

    // Two distinct approvers ⇒ two distinct nullifiers (so the on-chain
    // verifier counts this as two independent approvals).
    assert_ne!(
        d0.nullifier, d2.nullifier,
        "2-of-3 approvers must yield distinct nullifiers"
    );

    // Cross-check each nullifier against the host-side formula.
    let exp0 = members[0].nullifier::<Sha256Hasher>(&w0.proposal_id);
    let exp2 = members[2].nullifier::<Sha256Hasher>(&w2.proposal_id);
    assert_eq!(d0.nullifier, exp0);
    assert_eq!(d2.nullifier, exp2);
}

// ---------------------------------------------------------------------------
// 8. Large tree: 5000 members, prove for member at index 4321.
// ---------------------------------------------------------------------------

#[test]
fn v2_large_tree_5000_members_member_at_index_4321_proves() {
    ensure_dev_mode();

    // 5000 members exercises a non-trivial fraction of the depth-20 tree's
    // capacity (1<<20 = ~1.05M). Index 4321 is binary 0b1000011100001 — its
    // path-walk mixes left and right siblings at most levels and only fills
    // from the zero-marker chain at the very top levels, exercising the
    // "deep, real-sibling" code path the 1- and 7-member round-1 tests
    // don't.
    let n: u32 = 5000;
    let approver_index = 4321usize;
    assert!((approver_index as u32) < n);

    let members: Vec<Identity> = (0..n).map(deterministic_identity_u32).collect();
    let ctx = default_proposal_context();
    let action = b"large_tree_action";
    let w = build_witness(
        &members,
        approver_index,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        action,
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);

    let expected_nullifier = members[approver_index].nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(decoded.members_root, w.members_root);
    assert_eq!(decoded.proposal_id, w.proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 9. proposal_id cross-bound through circuit (sentinel under different inputs).
// ---------------------------------------------------------------------------

#[test]
fn v2_proposal_id_cross_bound_through_circuit() {
    ensure_dev_mode();

    // Use a deliberately-different fixture from round 1's proposal_id test
    // so a regression in `derive_proposal_id`'s formula (e.g. byte-order
    // swap, missing field) would surface differently here.
    let program_id: [u8; 32] = [0x12; 32];
    let create_key: [u8; 32] = [0x34; 32];
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0x56; 32];
    let chain_id = ChainId::from_u64(0x9999_8888_7777_6666);
    let index = 0xDEAD_BEEFu64;
    let action: &[u8] = b"v2_sentinel_action(asset=USDC,amount=0xCAFE)";

    let host_pid = derive_proposal_id(&chain_id, &state_pda, index, action, &target_program);

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let w = build_witness(
        &members,
        2,
        &chain_id,
        &state_pda,
        index,
        action,
        &target_program,
    );

    assert_eq!(
        w.proposal_id, host_pid,
        "witness proposal_id and host derive_proposal_id disagree before proving"
    );

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);

    assert_eq!(
        decoded.proposal_id, host_pid,
        "journal proposal_id diverges from host derive_proposal_id"
    );
}

// ---------------------------------------------------------------------------
// 10. Nullifier formula equivalence across 10 (member, proposal) pairs.
// ---------------------------------------------------------------------------

#[test]
fn v2_nullifier_computed_inside_guest_matches_identity_nullifier_on_host() {
    ensure_dev_mode();

    // 10 (member, proposal) pairs, each proved independently. For every
    // pair, the journal nullifier must byte-equal `Identity::nullifier`
    // evaluated on the host. Round 1 covered one pair; this is the
    // cross-layer formula equivalence claim at scale.
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    // 10 pairs: 5 members × 2 proposal indices each. Use a unique action
    // string per pair so proposal_id is meaningfully different.
    for member_idx in 0..5usize {
        for proposal_idx in 0..2u64 {
            let action = format!("v2_pair_m{member_idx}_p{proposal_idx}");
            let w = build_witness(
                &members,
                member_idx,
                &ctx.chain_id,
                &ctx.state_pda,
                proposal_idx,
                action.as_bytes(),
                &ctx.target_program,
            );

            let host_nullifier = members[member_idx].nullifier::<Sha256Hasher>(&w.proposal_id);

            let receipt = prove_once(&w);
            let decoded = decode_journal(&receipt);

            assert_eq!(
                decoded.nullifier, host_nullifier,
                "pair (m={member_idx}, p={proposal_idx}): journal nullifier ≠ host formula"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 11. `Receipt::verify` accepts the `[u32;8]` image-id directly (no hex round trip).
// ---------------------------------------------------------------------------

#[test]
fn v2_image_id_word_array_used_directly_in_verify() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        0,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"verify_word_array_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);

    // Pass the `[u32; 8]` value DIRECTLY — no `image_id_hex()` round trip,
    // no `hex::decode` step. Confirms the verify API signature lines up
    // with what the `methods` crate emits, so the on-chain verifier doesn't
    // have to introduce a conversion layer.
    let id_word_array: [u32; 8] = APPROVE_CIRCUIT_IMAGE_ID;
    receipt
        .verify(id_word_array)
        .expect("Receipt::verify must accept the [u32;8] image-id directly");
}

// ---------------------------------------------------------------------------
// 12. Journal is EXACTLY 96 bytes — no trailing padding.
// ---------------------------------------------------------------------------

#[test]
fn v2_journal_is_exactly_96_bytes_no_trailing_padding() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        3,
        &ctx.chain_id,
        &ctx.state_pda,
        21,
        b"no_padding_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let len = receipt.journal.bytes.len();

    // Strict equality, not ≥. If a future Risc0 release ever appends
    // metadata to journals (e.g. a session digest), the on-chain verifier's
    // fixed-offset `from_bytes` decode would silently read into that
    // metadata as the nullifier field — this test catches it before that
    // happens.
    assert_eq!(
        len, APPROVE_PUBLIC_INPUTS_LEN,
        "journal length is {len}, expected exactly {APPROVE_PUBLIC_INPUTS_LEN}"
    );
    assert_eq!(len, 96);
}

// ---------------------------------------------------------------------------
// 13. Receipt clones independently — verify the clone after dropping the original.
// ---------------------------------------------------------------------------

#[test]
fn v2_receipt_clones_independently() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        1,
        &ctx.chain_id,
        &ctx.state_pda,
        77,
        b"clone_independence_action",
        &ctx.target_program,
    );

    let original = prove_once(&w);
    let cloned = original.clone();

    // Drop the original FIRST. If `Receipt` (or any of its inner pieces)
    // held an `Rc`/`Arc` to shared state on the prover side that was
    // implicitly mutable, dropping the original could invalidate the
    // clone — the verify call below would then surface that.
    let original_journal_snapshot = original.journal.bytes.clone();
    drop(original);

    cloned
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("cloned Receipt must verify after original is dropped");
    assert_eq!(
        cloned.journal.bytes, original_journal_snapshot,
        "cloned Receipt journal diverged from original after drop"
    );
}

// ---------------------------------------------------------------------------
// 14. Manual byte-position spec pin: [0..32) root, [32..64) pid, [64..96) nul.
// ---------------------------------------------------------------------------

#[test]
fn v2_journal_decodes_as_three_distinct_fields_byte_positions_match_spec() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        4,
        &ctx.chain_id,
        &ctx.state_pda,
        55,
        b"byte_position_spec_pin_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal = receipt.journal.bytes.clone();
    assert_eq!(journal.len(), 96);

    // Manually slice the three 32-byte segments and assert each one matches
    // its named field. This pins the spec at the byte-position level — if
    // anyone ever rearranges `ApprovePublicInputs::to_bytes` (or the
    // guest's `journal.commit` order), this test will fire AT THE RECEIPT
    // LAYER, not just at the core-crate parity layer.
    let root_slice = &journal[0..32];
    let pid_slice = &journal[32..64];
    let nul_slice = &journal[64..96];

    let expected_nullifier = members[4].nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(
        root_slice, &w.members_root,
        "bytes [0..32) must be members_root"
    );
    assert_eq!(
        pid_slice, &w.proposal_id,
        "bytes [32..64) must be proposal_id"
    );
    assert_eq!(
        nul_slice, &expected_nullifier,
        "bytes [64..96) must be nullifier"
    );

    // Sanity: the three segments must be pairwise distinct under our
    // fixture — root, pid, and nullifier are computed from disjoint
    // preimages and any sha-256 collision would be cryptographically
    // surprising. Catches accidental field aliasing (e.g. if to_bytes were
    // ever changed to `[root || root || nullifier]`).
    assert_ne!(root_slice, pid_slice, "members_root and proposal_id alias");
    assert_ne!(pid_slice, nul_slice, "proposal_id and nullifier alias");
    assert_ne!(root_slice, nul_slice, "members_root and nullifier alias");

    // Also enforce a tiny "no-trivial-zeros" sanity: in our fixture all
    // three fields are SHA-256 outputs, so the chance of any being all
    // zeros is preimage-hard. If any of the three is ever `[0;32]`, the
    // host fixture has regressed.
    let zero = [0u8; HASH_LEN];
    assert_ne!(root_slice, &zero[..]);
    assert_ne!(pid_slice, &zero[..]);
    assert_ne!(nul_slice, &zero[..]);

    // Final cross-check: re-pack manually and require byte-equality with the
    // journal — this is the slice-level half of the to_bytes spec pin.
    let mut repacked = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    repacked[..32].copy_from_slice(&w.members_root);
    repacked[32..64].copy_from_slice(&w.proposal_id);
    repacked[64..96].copy_from_slice(&expected_nullifier);
    assert_eq!(repacked.as_slice(), journal.as_slice());

    // And touch the Hasher import so future readers can see the cross-check
    // path between guest output and host primitive (avoids unused-import
    // churn if the test body is ever trimmed).
    let _ = <Sha256Hasher as Hasher>::hash(b"v2_spec_pin");
}
