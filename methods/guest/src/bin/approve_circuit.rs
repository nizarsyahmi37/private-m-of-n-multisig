//! Risc0 guest: LP-0002 approval circuit.
//!
//! Inputs (private witness, read via `env::read_slice`):
//!   - `sk`            : 32 bytes — the approving member's secret
//!   - `salt`          : 32 bytes — the approving member's commitment salt
//!   - `siblings`      : 20 × 32 bytes — the Merkle path's sibling hashes
//!   - `indices`       : 20 bytes — each byte is a 0/1 direction bit at that level
//!
//! Inputs (committed-to-journal public bundle, read first 64 bytes via `env::read_slice`):
//!   - `members_root`  : 32 bytes — the frozen member-set root the client is approving against
//!   - `proposal_id`   : 32 bytes — the canonical `derive_proposal_id` output for the proposal
//!
//! Assertions inside the guest:
//!   1. `leaf = H(sk ‖ salt)` using `crypto::Sha256Hasher` (`Identity::commitment`).
//!   2. `verify_proof(members_root, leaf, MerkleProof { siblings, indices })` returns `true`.
//!   3. `nullifier = H(sk ‖ proposal_id)` using the same hasher.
//!
//! Journal output (read by the verifier program):
//!   - The canonical 96-byte `ApprovePublicInputs::to_bytes()` bundle:
//!     `[members_root: 32 || proposal_id: 32 || nullifier: 32]`.
//!
//! If any assertion fails the guest panics and no receipt is produced; a
//! receipt that DOES exist therefore carries a cryptographic proof that
//! someone with knowledge of `(sk, salt)` matching a leaf in `members_root`
//! computed `nullifier` for `proposal_id`. The verifier program (step 4)
//! independently recomputes `proposal_id` from on-chain state and cross-
//! checks against the journal.

#![no_main]
#![no_std]

use crypto::{
    merkle::{verify_proof, MerkleProof, MERKLE_DEPTH},
    nullifier, Identity, Sha256Hasher, HASH_LEN, SALT_LEN, SK_LEN,
};
use private_multisig_core::{ApprovePublicInputs, APPROVE_PUBLIC_INPUTS_LEN};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // ----- Read public-input prefix (members_root || proposal_id). ----------
    let mut public_buf = [0u8; 64];
    env::read_slice(&mut public_buf);
    let mut members_root = [0u8; HASH_LEN];
    let mut proposal_id = [0u8; HASH_LEN];
    members_root.copy_from_slice(&public_buf[..32]);
    proposal_id.copy_from_slice(&public_buf[32..64]);

    // ----- Read private witness (sk || salt || siblings || indices). --------
    let mut sk = [0u8; SK_LEN];
    let mut salt = [0u8; SALT_LEN];
    env::read_slice(&mut sk);
    env::read_slice(&mut salt);

    // Merkle path: depth-20 siblings (20 × 32 = 640 bytes) and 20 direction
    // bytes (each 0 or 1). Allocate the proof on the stack and fill from the
    // witness; the guest never allocates.
    let mut siblings_buf = [0u8; MERKLE_DEPTH * HASH_LEN];
    env::read_slice(&mut siblings_buf);
    let mut direction_buf = [0u8; MERKLE_DEPTH];
    env::read_slice(&mut direction_buf);

    let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for (level, slot) in siblings.iter_mut().enumerate() {
        let start = level * HASH_LEN;
        slot.copy_from_slice(&siblings_buf[start..start + HASH_LEN]);
    }
    let mut indices = [false; MERKLE_DEPTH];
    for (level, slot) in indices.iter_mut().enumerate() {
        // Strict: direction bytes are 0 or 1; anything else is a corrupt
        // witness that should not be silently accepted.
        match direction_buf[level] {
            0 => *slot = false,
            1 => *slot = true,
            other => {
                env::log("invalid direction byte");
                let _ = other;
                panic!("merkle path direction byte must be 0 or 1");
            }
        }
    }
    let proof = MerkleProof { siblings, indices };

    // ----- Recompute leaf, verify Merkle membership. ------------------------
    let identity = Identity::new(sk, salt);
    let commitment = identity.commitment::<Sha256Hasher>();
    assert!(
        verify_proof::<Sha256Hasher>(&members_root, commitment.as_bytes(), &proof),
        "merkle path does not verify against members_root"
    );

    // ----- Recompute nullifier. --------------------------------------------
    let computed_nullifier = nullifier::<Sha256Hasher>(&sk, &proposal_id);

    // ----- Commit canonical 96-byte public-input bundle to the journal. -----
    let public_inputs = ApprovePublicInputs {
        members_root,
        proposal_id,
        nullifier: computed_nullifier,
    };
    let journal: [u8; APPROVE_PUBLIC_INPUTS_LEN] = public_inputs.to_bytes();
    env::commit_slice(&journal);
}
