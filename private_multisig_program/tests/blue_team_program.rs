//! Blue-team validator (round 1) for the LP-0002 Risc0 approve circuit.
//!
//! Each `#[test]` here is a named defense that pins a specific property of
//! the prove-and-verify pipeline:
//!
//! - happy-path sanity (a real member's witness produces a verifying receipt)
//! - canonical journal layout (96 bytes, `[root || pid || nullifier]`)
//! - Borsh / explicit-layout parity at the receipt-journal layer
//! - nullifier uniqueness across members and across proposals
//! - nullifier determinism for the same (member, proposal) pair (the
//!   sentinel for the on-chain `NullifierEntry` init-fails-if-exists check)
//! - image-id stability across prover runs
//! - `ApprovePublicInputs::from_bytes` round-trip at the receipt layer
//! - host-side formula parity for `proposal_id`, `members_root`, `nullifier`
//! - non-power-of-2 (7-member) tree
//! - degenerate 1-member tree
//!
//! Every test sets `RISC0_DEV_MODE=1` the same way the existing
//! `approve_circuit.rs` test does so this file runs in seconds instead of
//! the multi-minute real-prover path. Set `RISC0_DEV_MODE=0` and rerun to
//! re-validate under the real prover — the assertions are identical.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]

use std::env;

use crypto::{Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id, ApprovePublicInputs, ChainId,
    APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Mirror of the existing happy-path test's helper: produce a fully
/// determined `Identity` from a single byte seed so every test in the file
/// can be re-run with byte-exact reproducibility.
fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

/// Set `RISC0_DEV_MODE=1` if the caller hasn't already pinned it. Single-
/// threaded by Cargo's default test harness wiring (`#[test]` runs in their
/// own thread but `env::set_var` only races other code that ALSO touches
/// the same key — none of our tests read `RISC0_DEV_MODE`, only the prover
/// does, and the prover reads it once per run). Mirrors the same pattern
/// the existing test uses.
fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: same justification as the existing approve_circuit.rs test:
        // the test harness has not yet spawned a thread that reads this var,
        // and once we set it the value never changes within this process.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

/// Bundle of host-side inputs that pin a proving run end-to-end. Every test
/// constructs one (or several) of these and feeds them into [`prove_once`].
struct Witness {
    members_root: [u8; 32],
    proposal_id: [u8; 32],
    approver: Identity,
    siblings_flat: [u8; MERKLE_DEPTH * HASH_LEN],
    direction_bytes: [u8; MERKLE_DEPTH],
}

/// Build a `Witness` for `approver_index` in a tree populated from
/// `members`. Computes `proposal_id` from the supplied bundle so the host
/// has an independent expectation to compare against the journal.
#[allow(clippy::too_many_arguments)]
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
            .unwrap();
    }
    let members_root = tree.root();

    let proof = tree.proof(approver_index).unwrap();

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

/// Run the prover once over `w`, verify against the pinned image-id, and
/// return the receipt. Panics on any failure with the same message text the
/// existing test uses so failures here look familiar to anyone reading the
/// log.
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

/// Decode a 96-byte journal into `ApprovePublicInputs`. Panics if the
/// journal isn't exactly the canonical length — that itself is a defense
/// we want to pin (see `blue_journal_layout_matches_to_bytes_canonical`).
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

/// Synthetic but realistic proposal-id context shared by most tests below.
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
// 1. Happy-path sanity baseline.
// ---------------------------------------------------------------------------

#[test]
fn blue_honest_member_proves_and_verifies() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let w = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        &action,
        &ctx.target_program,
    );

    let expected_nullifier = members[2].nullifier::<Sha256Hasher>(&w.proposal_id);
    let expected = ApprovePublicInputs {
        members_root: w.members_root,
        proposal_id: w.proposal_id,
        nullifier: expected_nullifier,
    };

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);

    assert_eq!(decoded, expected, "journal disagreed with host expectation");
    assert_eq!(decoded.members_root, w.members_root);
    assert_eq!(decoded.proposal_id, w.proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 2. Journal layout = ApprovePublicInputs::to_bytes() (96 bytes, root||pid||nul).
// ---------------------------------------------------------------------------

#[test]
fn blue_journal_layout_matches_to_bytes_canonical() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"set_threshold(3)".to_vec();
    let w = build_witness(
        &members,
        1,
        &ctx.chain_id,
        &ctx.state_pda,
        7,
        &action,
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal = receipt.journal.bytes.as_slice();

    // Length pin: exactly 96 bytes.
    assert_eq!(journal.len(), APPROVE_PUBLIC_INPUTS_LEN);
    assert_eq!(APPROVE_PUBLIC_INPUTS_LEN, 96);

    // Layout pin: [root || pid || nullifier]. Reconstruct the host bundle
    // and re-pack via `to_bytes`; require byte-identity with the journal.
    let expected_nullifier = members[1].nullifier::<Sha256Hasher>(&w.proposal_id);
    let host_bundle = ApprovePublicInputs {
        members_root: w.members_root,
        proposal_id: w.proposal_id,
        nullifier: expected_nullifier,
    };
    let host_bytes = host_bundle.to_bytes();
    assert_eq!(
        journal,
        host_bytes.as_slice(),
        "journal bytes diverge from ApprovePublicInputs::to_bytes()"
    );

    // Slice-level pin in case `to_bytes` is ever changed: each 32-byte
    // segment of the journal must equal its named field.
    assert_eq!(&journal[..32], &w.members_root);
    assert_eq!(&journal[32..64], &w.proposal_id);
    assert_eq!(&journal[64..96], &expected_nullifier);
}

// ---------------------------------------------------------------------------
// 3. Journal layout = borsh::to_vec(&public_inputs).
// ---------------------------------------------------------------------------

#[test]
fn blue_journal_layout_matches_borsh() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"borsh_parity_action".to_vec();
    let w = build_witness(
        &members,
        4,
        &ctx.chain_id,
        &ctx.state_pda,
        11,
        &action,
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal = receipt.journal.bytes.as_slice();

    let expected_nullifier = members[4].nullifier::<Sha256Hasher>(&w.proposal_id);
    let host_bundle = ApprovePublicInputs {
        members_root: w.members_root,
        proposal_id: w.proposal_id,
        nullifier: expected_nullifier,
    };
    let borsh_bytes = borsh::to_vec(&host_bundle).expect("borsh encode must succeed");

    // Borsh must produce the same 96-byte payload the journal carries —
    // if a future Borsh release ever adds a length prefix or version tag,
    // this test catches it at the Risc0-receipt layer (in addition to
    // the core-side `borsh_encoding_matches_explicit_layout` parity).
    assert_eq!(borsh_bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
    assert_eq!(
        journal,
        borsh_bytes.as_slice(),
        "journal bytes diverge from borsh::to_vec(&ApprovePublicInputs)"
    );
}

// ---------------------------------------------------------------------------
// 4. Three distinct members → three distinct nullifiers (same proposal).
// ---------------------------------------------------------------------------

#[test]
fn blue_three_distinct_members_three_distinct_nullifiers() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"three_members_action".to_vec();

    let indices = [0usize, 2, 4];
    let mut decoded = Vec::with_capacity(indices.len());
    for &i in &indices {
        let w = build_witness(
            &members,
            i,
            &ctx.chain_id,
            &ctx.state_pda,
            0,
            &action,
            &ctx.target_program,
        );
        let receipt = prove_once(&w);
        decoded.push(decode_journal(&receipt));
    }

    // Same members_root, same proposal_id across all three approvals — the
    // approvers are voting on the same proposal in the same multisig
    // instance.
    let root0 = decoded[0].members_root;
    let pid0 = decoded[0].proposal_id;
    for d in &decoded {
        assert_eq!(d.members_root, root0, "members_root drift across approvals");
        assert_eq!(d.proposal_id, pid0, "proposal_id drift across approvals");
    }

    // Three nullifiers must be pairwise distinct — that's how the on-chain
    // verifier program counts "three independent approvals" instead of one
    // approver replaying their own nullifier.
    assert_ne!(decoded[0].nullifier, decoded[1].nullifier);
    assert_ne!(decoded[0].nullifier, decoded[2].nullifier);
    assert_ne!(decoded[1].nullifier, decoded[2].nullifier);
}

// ---------------------------------------------------------------------------
// 5. One member approves two proposals → two distinct nullifiers.
// ---------------------------------------------------------------------------

#[test]
fn blue_same_member_different_proposals_different_nullifiers() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let w_a = build_witness(
        &members,
        3,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"proposal_a_action",
        &ctx.target_program,
    );
    let w_b = build_witness(
        &members,
        3,
        &ctx.chain_id,
        &ctx.state_pda,
        1,
        b"proposal_b_action",
        &ctx.target_program,
    );

    let r_a = prove_once(&w_a);
    let r_b = prove_once(&w_b);

    let d_a = decode_journal(&r_a);
    let d_b = decode_journal(&r_b);

    // The two proposals must actually differ — otherwise the test is vacuous.
    assert_ne!(
        d_a.proposal_id, d_b.proposal_id,
        "test precondition: proposals must differ"
    );
    // The members_root is unchanged across proposals.
    assert_eq!(d_a.members_root, d_b.members_root);
    // The nullifiers MUST differ — this is what unlinkability across proposals
    // looks like at the wire level (THREAT_MODEL T2.x).
    assert_ne!(
        d_a.nullifier, d_b.nullifier,
        "same member voting on different proposals must produce different nullifiers"
    );
}

// ---------------------------------------------------------------------------
// 6. Same member, same proposal, two prover runs → byte-identical nullifier.
// ---------------------------------------------------------------------------

#[test]
fn blue_same_member_same_proposal_same_nullifier_byte_identical() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let w = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        42,
        b"deterministic_action",
        &ctx.target_program,
    );

    // Build a second, fresh `Witness` rather than reusing the same value, so
    // two completely independent proving paths converge on the same
    // nullifier rather than this being a re-read of the same struct.
    let w2 = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        42,
        b"deterministic_action",
        &ctx.target_program,
    );

    let r1 = prove_once(&w);
    let r2 = prove_once(&w2);
    let d1 = decode_journal(&r1);
    let d2 = decode_journal(&r2);

    assert_eq!(
        d1.nullifier, d2.nullifier,
        "nullifier must be byte-identical across prover runs for the same (member, proposal)"
    );
    // Sanity: every other field is also byte-identical — this is the
    // sentinel the verifier's NullifierEntry init-fails-if-exists check
    // relies on. If the proposal_id or members_root drifted across runs,
    // the on-chain replay-protection PDA wouldn't collide.
    assert_eq!(d1, d2);
}

// ---------------------------------------------------------------------------
// 7. Image-id is stable across two proving runs.
// ---------------------------------------------------------------------------

#[test]
fn blue_image_id_is_stable_across_two_provings() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let w1 = build_witness(
        &members,
        0,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"first_run",
        &ctx.target_program,
    );
    let w2 = build_witness(
        &members,
        1,
        &ctx.chain_id,
        &ctx.state_pda,
        1,
        b"second_run",
        &ctx.target_program,
    );

    let r1 = prove_once(&w1);
    let r2 = prove_once(&w2);

    // Both receipts must verify against the SAME pinned image-id. If the
    // ELF or image-id drifted mid-run (e.g. due to a rebuild on the second
    // proving call), one of these would fail with E2001 ImageIdMismatch
    // on-chain — this catches that at the host level.
    r1.verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("first receipt must verify against pinned image-id");
    r2.verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("second receipt must verify against pinned image-id");
}

// ---------------------------------------------------------------------------
// 8. Round-trip through ApprovePublicInputs::from_bytes at the receipt layer.
// ---------------------------------------------------------------------------

#[test]
fn blue_journal_decodes_via_apprrove_public_inputs_from_bytes() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"from_bytes_round_trip".to_vec();
    let w = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        99,
        &action,
        &ctx.target_program,
    );

    let receipt = prove_once(&w);

    // Pull raw journal bytes, materialize into a `[u8; 96]`, and pass
    // through `ApprovePublicInputs::from_bytes` — exactly what the on-chain
    // verifier will do when it reads the receipt journal field.
    let journal_bytes = receipt.journal.bytes.as_slice();
    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(journal_bytes);
    let decoded = ApprovePublicInputs::from_bytes(&arr);

    let expected_nullifier = members[2].nullifier::<Sha256Hasher>(&w.proposal_id);
    let expected = ApprovePublicInputs {
        members_root: w.members_root,
        proposal_id: w.proposal_id,
        nullifier: expected_nullifier,
    };
    assert_eq!(decoded, expected);

    // Round-trip the other direction: re-pack the decoded bundle and
    // require byte-identity with the journal. Pins both halves of the
    // to/from bytes invariant at the receipt layer.
    let repacked = decoded.to_bytes();
    assert_eq!(repacked.as_slice(), journal_bytes);
}

// ---------------------------------------------------------------------------
// 9. proposal_id matches host-side derive_proposal_id at the journal layer.
// ---------------------------------------------------------------------------

#[test]
fn blue_proposal_id_matches_host_derive_proposal_id() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"proposal_id_formula_action".to_vec();
    let index = 17u64;
    let w = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        index,
        &action,
        &ctx.target_program,
    );

    // Recompute proposal_id on the host with no cached intermediates —
    // fresh inputs into `derive_proposal_id`. The journal must agree.
    let host_pid = derive_proposal_id(
        &ctx.chain_id,
        &ctx.state_pda,
        index,
        &action,
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);
    assert_eq!(
        decoded.proposal_id, host_pid,
        "journal proposal_id diverges from host-side derive_proposal_id"
    );
    // And the witness's `proposal_id` (which the guest reads as public input)
    // must equal the host derivation too — otherwise the witness builder
    // and the formula have drifted apart.
    assert_eq!(w.proposal_id, host_pid);
}

// ---------------------------------------------------------------------------
// 10. members_root matches host MerkleTree<Sha256Hasher>::root() at journal.
// ---------------------------------------------------------------------------

#[test]
fn blue_members_root_matches_host_merkle_tree_root() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"members_root_formula_action".to_vec();
    let w = build_witness(
        &members,
        3,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        &action,
        &ctx.target_program,
    );

    // Independently recompute members_root: new tree, same inserts, .root().
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for m in &members {
        tree.insert(*m.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let host_root = tree.root();

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);

    assert_eq!(
        decoded.members_root, host_root,
        "journal members_root diverges from host-side MerkleTree::root()"
    );
    assert_eq!(w.members_root, host_root);
}

// ---------------------------------------------------------------------------
// 11. nullifier matches Identity::nullifier::<Sha256Hasher> at journal.
// ---------------------------------------------------------------------------

#[test]
fn blue_nullifier_matches_identity_nullifier_helper() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"nullifier_formula_action".to_vec();
    let w = build_witness(
        &members,
        1,
        &ctx.chain_id,
        &ctx.state_pda,
        5,
        &action,
        &ctx.target_program,
    );

    let host_nullifier = members[1].nullifier::<Sha256Hasher>(&w.proposal_id);

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);

    assert_eq!(
        decoded.nullifier, host_nullifier,
        "journal nullifier diverges from Identity::nullifier helper"
    );
}

// ---------------------------------------------------------------------------
// 12. 7-member (non-power-of-2) tree, member 5 approves.
// ---------------------------------------------------------------------------

#[test]
fn blue_seven_member_tree_approval_works() {
    ensure_dev_mode();

    // Non-power-of-2 size exercises the zero-chain fill at every level
    // whose right subtree is unmaterialized — for index 5 (binary 0b101),
    // the path-walk touches sibling positions that don't exist as real
    // leaves, so the tree must substitute its precomputed zero-marker
    // chain or the proof would silently misrepresent membership.
    let members: Vec<Identity> = (0..7u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let action = b"seven_member_action".to_vec();
    let w = build_witness(
        &members,
        5,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        &action,
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);

    let expected_nullifier = members[5].nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(decoded.members_root, w.members_root);
    assert_eq!(decoded.proposal_id, w.proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 13. Degenerate 1-member tree, the lone member approves.
// ---------------------------------------------------------------------------

#[test]
fn blue_one_member_tree_approval_works() {
    ensure_dev_mode();

    // Tree of size 1: the lone member at index 0 must still produce a
    // verifying proof. Every sibling position the proof walk visits is
    // unmaterialized, so the tree fills siblings entirely from its
    // zero-marker chain. Sibling at level 0 is `H::hash_leaf(&[0;32])`
    // (NOT [0;32], thanks to domain separation — the FINDING-1 fix).
    let members: Vec<Identity> = vec![deterministic_identity(0xAA)];
    let ctx = default_proposal_context();
    let action = b"one_member_action".to_vec();
    let w = build_witness(
        &members,
        0,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        &action,
        &ctx.target_program,
    );

    // Sanity precondition: the level-0 sibling really IS the post-domain
    // zero-leaf marker, not [0;32]. If this ever flips, FINDING-1's
    // domain-separation fix has regressed — catch it here before we even
    // run the prover.
    let expected_marker = <Sha256Hasher as crypto::Hasher>::hash_leaf(&[0u8; HASH_LEN]);
    assert_eq!(
        &w.siblings_flat[..HASH_LEN],
        &expected_marker,
        "level-0 sibling must be the domain-separated zero-leaf marker"
    );

    let receipt = prove_once(&w);
    let decoded = decode_journal(&receipt);

    let expected_nullifier = members[0].nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(decoded.members_root, w.members_root);
    assert_eq!(decoded.proposal_id, w.proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}
