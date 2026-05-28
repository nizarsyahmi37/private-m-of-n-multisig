//! Layer-A end-to-end happy path: SDK → ApprovalProver → Risc0 receipt →
//! local verify + replay rejection.
//!
//! This test exercises the inner ZK composition without standing up a
//! LEZ sequencer. It models the on-chain `propose → 2×approve` flow
//! against the SDK's `ApprovalProver` and checks the three properties
//! the on-chain verifier relies on:
//!
//! - **A.1** Each approve receipt verifies against the pinned
//!   `APPROVE_CIRCUIT_IMAGE_ID`. If the inner image-id ever drifts from
//!   the prover's view of it, `Receipt::verify` here fails before the
//!   on-chain verifier ever sees the receipt.
//! - **A.2** The 96-byte journal bytes the guest commits are byte-identical
//!   to the SDK-computed `ApprovePublicInputs::to_bytes()`. The on-chain
//!   verifier reads the journal and cross-checks against the same layout;
//!   any divergence here is what `E2002 PublicInputsMismatch` would catch
//!   in production.
//! - **A.3** All three members share the same `members_root` and
//!   `proposal_id` but produce three distinct nullifiers. This is what
//!   makes the m-of-n quorum private — nullifiers cannot be linked back
//!   to identity, only to "this member has voted on this proposal".
//! - **A.4** A replay of Alice's nullifier on the same proposal is rejected
//!   when modeled as a `HashSet` insert — mirroring the on-chain
//!   `NullifierEntry` PDA's init-fails-if-exists semantics. PLAN.md's
//!   step-7 spec calls for "third member's later approval is rejected
//!   with a reused nullifier"; we interpret that as a same-member replay
//!   (the only path that legitimately reuses a nullifier) since a
//!   distinct member always produces a distinct `H(sk‖proposal_id)`.
//!
//! ## Layer B is gated separately
//!
//! The full LEZ sequencer harness (Bedrock + sequencer + indexer +
//! wallet via `testcontainers`) lives at `src/harness.rs` behind the
//! `lez-integration` feature flag. It requires `logos-blockchain-circuits`
//! v0.4.2 on disk and so doesn't run in CI; see `e2e_tests/README.md`.

use std::collections::HashSet;

use private_multisig_core::pda::derive_proposal_pda;
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use private_multisig_sdk::{ApprovalProver, Member, MultisigBuilder, MultisigStateSnapshot};
use risc0_zkvm::Receipt;

use private_multisig_e2e_tests::NOOP_ID;

/// Fixed test program id — Layer A is pure crypto, the on-chain program
/// id never round-trips. Picked outside [0u8; 32] / [0xFFu8; 32] so any
/// accidental zero-buffer or all-ones bug surfaces immediately.
const TEST_PROGRAM_ID: [u8; 32] = [0xA1; 32];

/// Deterministic create_key so the test is byte-reproducible if rerun
/// with `RISC0_DEV_MODE=1`.
const TEST_CREATE_KEY: [u8; 32] = [0xB2; 32];

/// Convert a Risc0 image id (`[u32; 8]` little-endian words) into the
/// 32-byte form the on-chain `target_program` field expects.
fn image_id_to_account_id(id: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in id.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[test]
fn create_propose_two_approve_layer_a() {
    // ---- Setup: three members, 2-of-3 multisig ----
    let alice = Member::new().expect("alice keygen");
    let bob = Member::new().expect("bob keygen");
    let carol = Member::new().expect("carol keygen");

    let mut builder = MultisigBuilder::new(2);
    builder.add_member(alice.commitment()).expect("add alice");
    builder.add_member(bob.commitment()).expect("add bob");
    builder.add_member(carol.commitment()).expect("add carol");
    let finalized = builder.finalize().expect("finalize 2-of-3");

    // Snapshot mirrors what the SDK would read off-chain after `propose`
    // committed proposal index 0 — proposal_count = 1 means index 0 is
    // the freshest valid target.
    let snapshot = MultisigStateSnapshot::new(
        TEST_PROGRAM_ID,
        TEST_CREATE_KEY,
        finalized.members_root,
        finalized.m,
        finalized.n,
        1, // proposal_count after a single `propose`
    )
    .expect("snapshot");

    let target_program = image_id_to_account_id(NOOP_ID);
    let action_bytes = b"layer-a-happy-path-action".to_vec();
    let proposal_index: u64 = 0;

    // Cross-check the proposal PDA derivation lands the same address
    // both the SDK and the on-chain verifier would compute. Not
    // exercised by the inner circuit but sanity-checks the snapshot.
    let proposal_pda = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, proposal_index);
    assert_ne!(proposal_pda, [0u8; 32]);

    // ---- Prove for all three members so we can also exercise A.4 ----
    let mut receipts: Vec<(String, Receipt, [u8; 32])> = Vec::with_capacity(3);
    for (name, member) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let merkle_proof = finalized
            .merkle_proof(&member.commitment())
            .expect("merkle proof");
        let mut prover = ApprovalProver::new(
            member,
            &snapshot,
            proposal_index,
            &action_bytes,
            &target_program,
            &merkle_proof,
            APPROVE_CIRCUIT_ELF,
        )
        .expect("prover ctor");

        let receipt_bytes = prover.prove().expect("prove");
        let receipt: Receipt = bincode::deserialize(&receipt_bytes).expect("bincode receipt");

        // A.2 — journal byte-equality with the SDK's public-inputs packer.
        let expected_journal = prover.public_inputs_bytes();
        assert_eq!(
            receipt.journal.bytes.as_slice(),
            expected_journal.as_slice(),
            "{name}: journal must match SDK-computed public inputs (96B)"
        );
        assert_eq!(
            receipt.journal.bytes.len(),
            96,
            "{name}: journal must be exactly the 96-byte ApprovePublicInputs"
        );

        // A.1 — local verify against the pinned image id. The SDK's
        // own `run_risc0_prover` already verifies in non-dev mode; we
        // re-verify unconditionally here so the test catches
        // image-id drift even under `RISC0_DEV_MODE=1`.
        receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .unwrap_or_else(|e| panic!("{name}: receipt.verify failed: {e}"));

        let nullifier = prover.nullifier();
        receipts.push((name.to_string(), receipt, nullifier));
    }

    // ---- A.3 — public-inputs agreement across members ----
    let first_pi = receipts[0].1.journal.bytes.clone();
    let first_members_root = &first_pi[..32];
    let first_proposal_id = &first_pi[32..64];
    for (name, receipt, _) in &receipts[1..] {
        assert_eq!(
            &receipt.journal.bytes[..32],
            first_members_root,
            "{name}: members_root must agree across all member receipts"
        );
        assert_eq!(
            &receipt.journal.bytes[32..64],
            first_proposal_id,
            "{name}: proposal_id must agree across all member receipts"
        );
    }

    // Three distinct nullifiers — same proposal, different secrets.
    let nullifier_set: HashSet<[u8; 32]> = receipts.iter().map(|(_, _, n)| *n).collect();
    assert_eq!(
        nullifier_set.len(),
        3,
        "three members on the same proposal must yield three distinct nullifiers"
    );

    // ---- A.4 — replay rejection model ----
    // The on-chain `NullifierEntry` PDA is keyed by `(proposal_pda, nullifier)`
    // and uses init-fails-if-exists, so a second approval from the same
    // member targets a collision and the instruction is rejected. We
    // model that here with a `HashSet`: the first insert wins, the
    // second returns `false`.
    //
    // PLAN.md step 7 calls for "third member's later approval is
    // rejected with a reused nullifier". A distinct member always
    // produces a distinct nullifier (since `H(sk‖proposal_id)` binds
    // to the secret), so the only path that reuses a nullifier is a
    // same-member replay — Alice signing twice. That's what we model.
    let mut chain_nullifiers: HashSet<[u8; 32]> = HashSet::new();
    let alice_nullifier = receipts[0].2;
    assert!(
        chain_nullifiers.insert(alice_nullifier),
        "alice's first approval should be accepted (empty nullifier set)"
    );
    let bob_nullifier = receipts[1].2;
    assert!(
        chain_nullifiers.insert(bob_nullifier),
        "bob's first approval should be accepted (distinct nullifier from alice)"
    );
    assert!(
        !chain_nullifiers.insert(alice_nullifier),
        "alice's replay must be rejected — models on-chain NullifierEntry collision"
    );
}
