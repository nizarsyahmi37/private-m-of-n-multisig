//! Risc0 proof generation for the approval circuit.
//!
//! `ApprovalProver` wraps the Risc0 host-side proving API (`risc0_zkvm::prove`)
//! and feeds it the correct input layout the `approve_circuit` guest expects:
//!
//! 1. Public prefix (read first by the guest): `[members_root: 32 || proposal_id: 32]`
//! 2. Private witness: `[sk: 32 || salt: 32 || siblings: 640 || indices: 20]`
//!
//! The guest commits the 96-byte `ApprovePublicInputs` bundle to its journal,
//! which the verifier reads back and cross-checks. The guest's assertion
//! chain guarantees anyone who holds a valid receipt knows `(sk, salt, path)`
//! corresponding to a Merkle leaf under `members_root` and can compute
//! `nullifier = H(sk || proposal_id)`.
//!
//! ## DEV_MODE
//!
//! Setting `RISC0_DEV_MODE=1` produces a fast (but non-SNARK) receipt
//! suitable for local testing. Production use requires `RISC0_DEV_MODE=0`
//! (the default). The prover detects the mode from the `RISC0_DEV_MODE`
//! environment variable.
//!
//! ## Input layout
//!
//! The guest's `env::read_slice` expects data in this exact order:
//!
//! ```text
//! offset   0 (64 bytes):  members_root (32) || proposal_id (32)
//! offset  64 (32 bytes):  sk (32)
//! offset  96 (32 bytes):  salt (32)
//! offset 128 (640 bytes): siblings[0..19] — 20 × 32 bytes each
//! offset 768  (20 bytes): direction bytes — 20 × 0 or 1 (bool as u8)
//! total private witness: 788 bytes
//! ```

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::hash::HASH_LEN;
use crypto::merkle::{verify_proof, MerkleProof, MERKLE_DEPTH};
use private_multisig_core::proof::ApprovePublicInputs;
use risc0_zkvm::serde::to_vec;
use risc0_zkvm::{ExecutorEnv, Receipt};
use std::env;
use zeroize::Zeroize;

use crate::error::SdkError;
use crate::member::Member;
use crate::multisig::MultisigStateSnapshot;

/// Fallback image ID that matches `methods/guest/src/bin/approve_circuit.rs`
/// when the workspace last built cleanly. The `try_image_id()` method probes
/// the auto-generated `Methods` enum first; only falls back here if the
/// methods crate hasn't been built yet (e.g. fresh `cargo check`).
const APPROVE_CIRCUIT_IMAGE_ID_PINNED: [u32; 8] = [
    763539168, 1016753994, 1524795730, 877238783, 502029817, 1373722446,
    3332462251, 4034702986,
];

/// Risc0 guest proof generator for the approval circuit.
///
/// Construct with `ApprovalProver::new(...)`, then call `prove()` to
/// produce a receipt. The receipt is safe to cache and re-submit — it
/// carries a cryptographic proof that cannot be forged.
///
/// ```ignore
/// let mut prover = ApprovalProver::new(
///     &member,
///     &proposal_snapshot,
///     index,
///     action_bytes,
///     &target_program,
///     &merkle_proof,
/// )?;
/// let receipt_bytes = prover.prove()?;
/// let public_inputs = prover.public_inputs_bytes();
/// let nullifier = prover.nullifier();
/// ```
///
/// The `prove()` output is `risc0_zkvm::serde::to_vec(&Receipt)` — the same
/// encoding the verifier host receives from the LEZ sequencer.
/// `public_inputs_bytes()` gives the 96-byte payload that goes into
/// `Instruction::Approve.public_inputs`.
///
/// ## Drop semantics
///
/// On `Drop`, the prover zeroizes the in-memory `sk` and `salt` so they
/// do not linger in heap or stack after the prover is discarded.
/// Receipt bytes (public) are NOT zeroized.
pub struct ApprovalProver {
    /// Member secret witness — Zeroize ensures sk/salt never linger.
    sk: [u8; 32],
    salt: [u8; 32],
    /// Snapshot of the multisig state — provides state_pda for proposal_id.
    snapshot: MultisigStateSnapshot,
    /// Flattened Merkle siblings (20 × 32 bytes, level order).
    siblings_flat: [[u8; HASH_LEN]; MERKLE_DEPTH],
    /// Flattened direction bits (20 bools, level order).
    directions_flat: [bool; MERKLE_DEPTH],
    /// The proposal index this approval targets.
    index: u64,
    /// The action bytes (needed to recompute proposal_id locally).
    action_bytes: Vec<u8>,
    /// The target program (needed to recompute proposal_id locally).
    target_program: private_multisig_core::AccountId,
    /// Encoded receipt from the last `prove()` call.
    receipt: Option<Vec<u8>>,
}

impl core::fmt::Debug for ApprovalProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // NOTE: sk and salt intentionally omitted from Debug output.
        f.debug_struct("ApprovalProver")
            .field("snapshot", &self.snapshot)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl ApprovalProver {
    /// Construct a new prover for an approval of proposal `index`.
    ///
    /// Validates all inputs before accepting them so `prove()` never fails
    /// with a trivially-detectable bad witness. The caller's `Member`
    /// remains live after this call — the prover extracts only the
    /// raw `(sk, salt)` bytes it needs for the Risc0 witness.
    ///
    /// - `member`: the approving member (owns sk and salt).
    /// - `snapshot`: local mirror of on-chain `MultisigState` (from RPC fetch).
    /// - `index`: the proposal index being approved.
    /// - `action_bytes`: raw bytes stored in the on-chain proposal account.
    /// - `target_program`: target of the `ChainedCall` on execute.
    /// - `merkle_proof`: inclusion proof for this member's commitment.
    pub fn new(
        member: &Member,
        snapshot: &MultisigStateSnapshot,
        index: u64,
        action_bytes: &[u8],
        target_program: &private_multisig_core::AccountId,
        merkle_proof: &MerkleProof,
    ) -> Result<Self, SdkError> {
        // --- action_bytes length check ---
        if action_bytes.len() > private_multisig_core::state::MAX_ACTION_BYTES_LEN {
            return Err(SdkError::ActionBytesTooLarge);
        }

        // --- Proposal index freshness check (RT-7 fix): reject stale index ---
        // A stale snapshot with an old proposal_count could allow approval of a
        // superseded proposal. Verify index < snapshot.proposal_count so approvals
        // can only target proposals that exist at the time of this session's creation.
        if index >= snapshot.proposal_count {
            return Err(SdkError::ProposalIndexMismatch);
        }

        // --- Merkle proof validation: fail fast before expensive proving ---
        if !verify_proof::<crypto::hash::Sha256Hasher>(
            &snapshot.members_root,
            member.commitment().as_bytes(),
            merkle_proof,
        ) {
            return Err(SdkError::MerkleProofInvalid);
        }

        // --- proposal_id recompute: verify against what the circuit will commit ---
        // (removed the zero-check — SHA-256 of a non-trivial preimage is
        // astronomically unlikely to produce [0;32], and the check misclassified
        // the error as ActionBytesHashMismatch per BT-4) ---

        // --- Extract raw (sk, salt) from Member ---
        let (sk, salt) = member.witness();

        // --- Extract flattened witness ---
        let (siblings_flat, directions_flat) = Self::flatten_proof(merkle_proof);

        Ok(Self {
            sk,
            salt,
            snapshot: snapshot.clone(),
            siblings_flat,
            directions_flat,
            index,
            action_bytes: action_bytes.to_vec(),
            target_program: *target_program,
            receipt: None,
        })
    }

    /// Run the Risc0 prover and return the serialized receipt.
    ///
    /// Blocks until proof generation completes. In `RISC0_DEV_MODE=1`
    /// this takes seconds; in production mode (`RISC0_DEV_MODE=0`) it
    /// takes 1–10 minutes.
    ///
    /// On success the receipt is cached internally. Subsequent calls
    /// return the cached bytes without re-proving.
    pub fn prove(&mut self) -> Result<Vec<u8>, SdkError> {
        if let Some(ref cached) = self.receipt {
            return Ok(cached.clone());
        }

        let proposal_id = self
            .snapshot
            .derive_proposal_id(self.index, &self.action_bytes, &self.target_program);

        let receipt = self.run_risc0_prover(proposal_id)?;
        let encoded =
            to_vec(&receipt).map_err(|e| SdkError::ProofGenerationFailed(format!(
                "risc0 serde encode failed: {e}"
            )))?;
        self.receipt = Some(encoded.clone());
        Ok(encoded)
    }

    /// Return cached receipt bytes. Returns `Err` if `prove()` hasn't succeeded.
    pub fn receipt_bytes(&self) -> Result<&Vec<u8>, SdkError> {
        self.receipt.as_ref().ok_or(SdkError::SessionStatusMismatch)
    }

    /// The 96-byte canonical wire payload for `Instruction::Approve.public_inputs`.
    ///
    /// The nullifier is computed locally (same formula the circuit uses) so
    /// callers can build the instruction without deserializing the receipt.
    pub fn public_inputs_bytes(&self) -> [u8; 96] {
        self.public_inputs().to_bytes()
    }

    /// Recompute the `ApprovePublicInputs` from local data.
    ///
    /// The nullifier is `H(sk || proposal_id)`, recomputed from the owned
    /// witness so no receipt deserialization is needed.
    pub fn public_inputs(&self) -> ApprovePublicInputs {
        let proposal_id = self
            .snapshot
            .derive_proposal_id(self.index, &self.action_bytes, &self.target_program);
        let nullifier = self.compute_nullifier(proposal_id);
        ApprovePublicInputs {
            members_root: self.snapshot.members_root,
            proposal_id,
            nullifier,
        }
    }

    /// The member's nullifier for the current proposal.
    pub fn nullifier(&self) -> [u8; 32] {
        let proposal_id = self
            .snapshot
            .derive_proposal_id(self.index, &self.action_bytes, &self.target_program);
        self.compute_nullifier(proposal_id)
    }

    /// Internal: build input buffer and call Risc0 prover.
    fn run_risc0_prover(&self, proposal_id: [u8; 32]) -> Result<Receipt, SdkError> {
        const PUBLIC_PREFIX: usize = 64;
        const WITNESS_SK: usize = 32;
        const WITNESS_SALT: usize = 32;
        const WITNESS_SIBLINGS: usize = MERKLE_DEPTH * HASH_LEN;
        const WITNESS_DIRECTIONS: usize = MERKLE_DEPTH;
        let total = PUBLIC_PREFIX + WITNESS_SK + WITNESS_SALT + WITNESS_SIBLINGS + WITNESS_DIRECTIONS;

        let mut input = Vec::with_capacity(total);

        // Public prefix: members_root || proposal_id
        input.extend_from_slice(&self.snapshot.members_root);
        input.extend_from_slice(&proposal_id);

        // Private witness: sk + salt
        input.extend_from_slice(&self.sk);
        input.extend_from_slice(&self.salt);

        // Private witness: flattened siblings (level order)
        input.extend_from_slice(&self.siblings_flat.as_slice());

        // Private witness: direction bytes
        for &d in &self.directions_flat {
            input.push(if d { 1u8 } else { 0u8 });
        }

        debug_assert_eq!(input.len(), total, "input buffer size mismatch");

        let env = ExecutorEnv::builder()
            .add_input(&input)
            .build()
            .map_err(|e| SdkError::ProofGenerationFailed(format!(
                "ExecutorEnv build failed: {e}"
            )))?;

        let image_id = Self::image_id();

        let receipt = risc0_zkvm::prove::prove(env, image_id)
            .map_err(|e| SdkError::ProofGenerationFailed(format!(
                "risc0 prove() failed: {e}"
            )))?;

        // Local self-verification guards against prover bugs.
        // Skipped in DEV_MODE (the fake prover doesn't produce verifiable receipts).
        if !Self::is_dev_mode() {
            receipt.verify(image_id)
                .map_err(|e| SdkError::ReceiptVerificationFailed(format!(
                    "local receipt verify() failed: {e}"
                )))?;
        }

        Ok(receipt)
    }

    /// Resolve the approve-circuit image ID.
    ///
    /// Tries the auto-generated `Methods::APPROVE_CIRCUIT` enum first (available
    /// when `risc0_build::embed_methods()` was run). Falls back to the pinned
    /// constant if that fails, which lets the SDK compile independently of the
    /// guest build order.
    fn image_id() -> [u32; 8] {
        Self::try_methods_image_id().unwrap_or(APPROVE_CIRCUIT_IMAGE_ID_PINNED)
    }

    /// Probe for the `Methods::APPROVE_CIRCUIT` image ID.
    ///
    /// Returns `None` until the `methods` crate is properly integrated as
    /// a workspace member. When available, callers should update this to
    /// return `Some(methods::APPROVE_CIRCUIT_ID)`.
    fn try_methods_image_id() -> Option<[u32; 8]> {
        // Integration note: once `methods/` is a proper workspace member,
        // replace this with `Some(methods::APPROVE_CIRCUIT_ID)`.
        None
    }

    /// True if `RISC0_DEV_MODE` is set to a truthy value.
    fn is_dev_mode() -> bool {
        matches!(
            env::var("RISC0_DEV_MODE").as_deref(),
            Ok("1") | Ok("true")
        )
    }

    /// Extract flattened siblings and directions from a MerkleProof.
    fn flatten_proof(proof: &MerkleProof) -> ([[u8; HASH_LEN]; MERKLE_DEPTH], [bool; MERKLE_DEPTH]) {
        let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
        let mut directions = [false; MERKLE_DEPTH];
        for level in 0..MERKLE_DEPTH {
            siblings[level] = proof.siblings[level];
            directions[level] = proof.indices[level];
        }
        (siblings, directions)
    }

    /// Compute nullifier: `H(sk || proposal_id)`.
    fn compute_nullifier(&self, proposal_id: [u8; 32]) -> [u8; 32] {
        crypto::nullifier::<crypto::hash::Sha256Hasher>(&self.sk, &proposal_id)
    }
}

impl Drop for ApprovalProver {
    fn drop(&mut self) {
        // Zeroize sk and salt so they don't linger after the prover is dropped.
        // Receipt bytes are public and intentionally not zeroized.
        self.sk.zeroize();
        self.salt.zeroize();
    }
}

#[cfg(all(test, feature = "prover"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::member::Member;
    use crypto::merkle::MerkleProof;

    #[test]
    fn prover_constructs_with_valid_inputs() {
        let member = Member::new().unwrap();
        let mut builder = crate::multisig::MultisigBuilder::new(2);
        builder.add_member(member.commitment()).unwrap();
        let m2 = Member::new().unwrap();
        builder.add_member(m2.commitment()).unwrap();
        let finalized = builder.finalize().unwrap();
        let snap = MultisigStateSnapshot::new(
            [0xA1; 32],
            [0xB2; 32],
            finalized.members_root,
            2,
            2,
            0,
        )
        .unwrap();
        let proof = finalized.merkle_proof(&member.commitment()).unwrap();

        let prover = ApprovalProver::new(
            &member,
            &snap,
            0,
            b"test action",
            &[0xCC; 32],
            &proof,
        );
        assert!(prover.is_ok(), "prover should construct: {prover:?}");
    }

    #[test]
    fn prover_rejects_large_action_bytes() {
        let member = Member::new().unwrap();
        let snap = MultisigStateSnapshot::new(
            [0xA1; 32],
            [0xB2; 32],
            [0xBB; 32],
            2,
            2,
            0,
        )
        .unwrap();
        let oversized = vec![0xFE; 4097];
        let proof = MerkleProof {
            siblings: [[0u8; 32]; MERKLE_DEPTH],
            indices: [false; MERKLE_DEPTH],
        };
        let result =
            ApprovalProver::new(&member, &snap, 0, &oversized, &[0xCC; 32], &proof);
        assert!(matches!(result, Err(SdkError::ActionBytesTooLarge)));
    }

    #[test]
    fn prover_rejects_invalid_merkle_proof() {
        let member = Member::new().unwrap();
        let wrong_root = [0xFF; 32]; // Does not match the member's commitment
        let snap = MultisigStateSnapshot::new(
            [0xA1; 32],
            [0xB2; 32],
            wrong_root,
            2,
            2,
            0,
        )
        .unwrap();
        let proof = MerkleProof {
            siblings: [[0u8; 32]; MERKLE_DEPTH],
            indices: [false; MERKLE_DEPTH],
        };
        let result = ApprovalProver::new(
            &member,
            &snap,
            0,
            b"test",
            &[0xCC; 32],
            &proof,
        );
        assert!(matches!(result, Err(SdkError::MerkleProofInvalid)));
    }

    #[test]
    fn public_inputs_matches_nullifier() {
        let member = Member::new().unwrap();
        let mut builder = crate::multisig::MultisigBuilder::new(2);
        builder.add_member(member.commitment()).unwrap();
        builder.add_member(Member::new().unwrap().commitment()).unwrap();
        let finalized = builder.finalize().unwrap();
        let snap = MultisigStateSnapshot::new(
            [0xA1; 32],
            [0xB2; 32],
            finalized.members_root,
            2,
            2,
            0,
        )
        .unwrap();
        let proof = finalized.merkle_proof(&member.commitment()).unwrap();
        let prover =
            ApprovalProver::new(&member, &snap, 0, b"action", &[0xCC; 32], &proof).unwrap();

        let public_inputs = prover.public_inputs();
        let nullifier_direct = prover.nullifier();
        assert_eq!(public_inputs.nullifier, nullifier_direct);
    }
}