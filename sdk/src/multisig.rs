//! Multisig instance and proposal builders.
//!
//! ## MultisigBuilder
//!
//! Collects member `IdentityCommitment`s and computes the Merkle `members_root`.
//! The creator calls this locally to produce the `members_root` they embed
//! in the `CreateMultisig` instruction. Callers who use the CLI's interactive
//! enrollment flow (not implemented in this module — see `cli/`) will use this.
//!
//! ## ProposalBuilder
//!
//! Computes the canonical `proposal_id` for a proposed action and assembles
//! the data needed by `ApprovalProver`. The `proposal_id` is derived from
//! on-chain-fetched `MultisigState` (specifically `create_key`) and local
//! `action_bytes`/`target_program` — so the SDK recomputes it independently
//! and never trusts the proposal account's data.
//!
//! ## MultisigStateSnapshot
//!
//! A local mirror of the on-chain `MultisigState` that the SDK caches so
//! `ApprovalProver` has all inputs without an extra round-trip on each
//! approval. Refresh via `refresh()`.

use crypto::hash::Sha256Hasher;
use crypto::merkle::MerkleTree;
use private_multisig_core::proof::{derive_proposal_id, ChainId, DEPLOYMENT_CHAIN_ID_U64};
use private_multisig_core::pda::derive_multisig_state_pda;

use crate::error::SdkError;
use crate::member::IdentityCommitment;

/// Builder that gathers member `IdentityCommitment`s and produces the
/// Merkle `members_root` for `CreateMultisig`.
///
/// Construct with [`MultisigBuilder::new(m)`] where `m` is the threshold,
/// then call [`add_member`](Self::add_member) with each enrolled member's
/// commitment, then call [`finalize`](Self::finalize) once all N members
/// are added.
///
/// ```ignore
/// use private_multisig_sdk::{Member, MultisigBuilder};
///
/// let alice = Member::new()?;
/// let bob = Member::new()?;
/// let builder = MultisigBuilder::new(2)
///     .add_member(alice.commitment())?
///     .add_member(bob.commitment())?;
/// let members_root = builder.finalize()?;
/// ```
pub struct MultisigBuilder {
    m: u8,
    tree: MerkleTree<Sha256Hasher>,
    added: alloc::vec::Vec<IdentityCommitment>,
}

impl MultisigBuilder {
    /// Begin a builder for an M-of-N multisig with threshold `m`.
    pub fn new(m: u8) -> Self {
        Self {
            m,
            tree: MerkleTree::new(),
            added: alloc::vec::Vec::new(),
        }
    }

    /// Enroll one member's identity commitment.
    ///
    /// Returns an error if `commitment` was already added (duplicate enrollment
    /// would give that member double voting weight).
    pub fn add_member(&mut self, commitment: IdentityCommitment) -> Result<&mut Self, SdkError> {
        if self.added.contains(&commitment) {
            return Err(SdkError::DuplicateMember);
        }
        self.added.push(commitment);
        self.tree
            .insert(commitment.0)
            .map_err(|_| SdkError::ThresholdExceedsMembers)?;
        Ok(self)
    }

    /// Consume the builder and return the Merkle `members_root`.
    ///
    /// Returns `Err(InsufficientMembers { m, n })` if fewer than `m` members
    /// have been added. Returns `Err(ThresholdExceedsMembers)` if more than
    /// `u32::MAX` members were added (overflow in `n`).
    pub fn finalize(&self) -> Result<MultisigFinalized, SdkError> {
        let n = u32::try_from(self.added.len())
            .map_err(|_| SdkError::ThresholdExceedsMembers)?;

        // Check m == 0 or n == 0 first (BT-2 fix: dedicated InvalidThreshold)
        if self.m == 0 || n == 0 {
            return Err(SdkError::InvalidThreshold);
        }

        // InsufficientMembers: check after m/n validity so the error code is accurate
        if self.added.len() < self.m as usize {
            return Err(SdkError::InsufficientMembers {
                m: self.m,
                n,
            });
        }

        // m > n: distinct error
        if u32::from(self.m) > n {
            return Err(SdkError::ThresholdExceedsMembers);
        }

        let members_root = self.tree.root();
        Ok(MultisigFinalized {
            members_root,
            m: self.m,
            n,
            commitments: self.added.clone(),
            tree: self.tree.clone(),
        })
    }
}

/// Result of [`MultisigBuilder::finalize`]. Holds the frozen Merkle root
/// and the per-member index map (needed for `ApprovalProver` to know
/// which Merkle path to use).
#[derive(Clone)]
pub struct MultisigFinalized {
    /// Merkle root to embed in `CreateMultisig`.
    pub members_root: [u8; 32],
    /// Threshold M.
    pub m: u8,
    /// Total member count N.
    pub n: u32,
    /// Ordered list of member commitments in insertion order.
    commitments: alloc::vec::Vec<IdentityCommitment>,
    /// The underlying Merkle tree (needed for proof extraction).
    tree: MerkleTree<Sha256Hasher>,
}

impl core::fmt::Debug for MultisigFinalized {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultisigFinalized")
            .field("members_root", &self.members_root)
            .field("m", &self.m)
            .field("n", &self.n)
            .field("n_members", &self.commitments.len())
            .finish()
    }
}

impl MultisigFinalized {
    /// Returns the member's index in the Merkle tree (the position
    /// `MerkleTree::insert` assigned when they were added). The SDK uses
    /// this to retrieve the correct Merkle path before calling
    /// `ApprovalProver`.
    pub fn member_index(&self, commitment: &IdentityCommitment) -> Option<usize> {
        self.commitments.iter().position(|c| c == commitment)
    }

    /// Returns the Merkle path for a given member's commitment.
    /// Used by the SDK to construct the witness for `ApprovalProver`.
    pub fn merkle_proof(&self, commitment: &IdentityCommitment) -> Result<crypto::merkle::MerkleProof, SdkError> {
        let idx = self
            .member_index(commitment)
            .ok_or(SdkError::SessionStatusMismatch)?;
        self.tree
            .proof(idx)
            .map_err(|_| SdkError::MerkleProofInvalid)
    }
}

/// Local snapshot of the on-chain `MultisigState` needed to set up
/// `ApprovalProver` without extra round-trips.
///
/// Construct from `MultisigFinalized` plus the `program_id` and `create_key`
/// (fetched from the on-chain instance):
///
/// ```ignore
/// let snapshot = MultisigStateSnapshot::new(
///     program_id,
///     create_key,
///     finalized.members_root,
///     finalized.m,
///     finalized.n,
///     proposal_count, // from on-chain fetch
/// )?;
/// ```
#[derive(Clone, Debug)]
pub struct MultisigStateSnapshot {
    /// The LEZ program ID of this multisig instance (from the verifier program).
    pub program_id: private_multisig_core::ProgramId,
    /// The salt that identifies this instance.
    pub create_key: private_multisig_core::CreateKey,
    /// The Merkle root frozen at creation.
    pub members_root: [u8; 32],
    /// Threshold M.
    pub m: u8,
    /// Total members N.
    pub n: u32,
    /// Current proposal count (next proposal index = proposal_count).
    pub proposal_count: u64,
    /// Derived on-chain state PDA address.
    state_pda: private_multisig_core::AccountId,
}

impl MultisigStateSnapshot {
    /// Construct a local snapshot. `program_id` and `create_key` must be
    /// fetched from the on-chain `MultisigState` account (the SDK does this
    /// via the LEZ RPC when setting up a session).
    pub fn new(
        program_id: private_multisig_core::ProgramId,
        create_key: private_multisig_core::CreateKey,
        members_root: [u8; 32],
        m: u8,
        n: u32,
        proposal_count: u64,
    ) -> Result<Self, SdkError> {
        let state_pda = derive_multisig_state_pda(&program_id, &create_key);
        Ok(Self {
            program_id,
            create_key,
            members_root,
            m,
            n,
            proposal_count,
            state_pda,
        })
    }

    /// Derive the canonical on-chain `proposal_id` for the given index.
    ///
    /// This recomputes from local inputs only — no trust in the proposal account.
    pub fn derive_proposal_id(
        &self,
        index: u64,
        action_bytes: &[u8],
        target_program: &private_multisig_core::AccountId,
    ) -> [u8; 32] {
        let chain_id = ChainId::from_u64(DEPLOYMENT_CHAIN_ID_U64);
        derive_proposal_id(
            &chain_id,
            &self.state_pda,
            index,
            action_bytes,
            target_program,
        )
    }

    /// The on-chain `MultisigState` PDA address.
    pub fn state_pda(&self) -> private_multisig_core::AccountId {
        self.state_pda
    }
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_finalizes_with_valid_threshold() {
        let mut builder = MultisigBuilder::new(2);
        let alice = crate::member::Member::new().unwrap();
        let bob = crate::member::Member::new().unwrap();
        builder.add_member(alice.commitment()).unwrap();
        builder.add_member(bob.commitment()).unwrap();
        let result = builder.finalize().unwrap();
        assert_eq!(result.m, 2);
        assert_eq!(result.n, 2);
    }

    #[test]
    fn builder_rejects_insufficient_members() {
        let mut builder = MultisigBuilder::new(2);
        let alice = crate::member::Member::new().unwrap();
        builder.add_member(alice.commitment()).unwrap();
        let result = builder.finalize();
        assert!(matches!(result, Err(SdkError::InsufficientMembers { m: 2, n: 1 })));
    }

    #[test]
    fn builder_rejects_duplicate_member() {
        let mut builder = MultisigBuilder::new(2);
        let alice = crate::member::Member::new().unwrap();
        let commitment = alice.commitment();
        builder.add_member(commitment).unwrap();
        let result = builder.add_member(commitment);
        assert!(matches!(result, Err(SdkError::DuplicateMember)));
    }

    #[test]
    fn snapshot_proposal_id_is_deterministic() {
        let member = crate::member::Member::new().unwrap();
        let mut builder = MultisigBuilder::new(2);
        builder.add_member(member.commitment()).unwrap();
        builder.add_member(crate::member::Member::new().unwrap().commitment()).unwrap();
        let finalized = builder.finalize().unwrap();

        let program_id = [0xA1; 32];
        let create_key = [0xB2; 32];
        let action = b"transfer 100 tokens";
        let target = [0xCC; 32];

        let snap = MultisigStateSnapshot::new(program_id, create_key, finalized.members_root, 2, 2, 0).unwrap();
        let pid1 = snap.derive_proposal_id(0, action, &target);
        let pid2 = snap.derive_proposal_id(0, action, &target);
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn snapshot_proposal_id_changes_with_index() {
        let member = crate::member::Member::new().unwrap();
        let mut builder = MultisigBuilder::new(2);
        builder.add_member(member.commitment()).unwrap();
        builder.add_member(crate::member::Member::new().unwrap().commitment()).unwrap();
        let finalized = builder.finalize().unwrap();

        let program_id = [0xA1; 32];
        let create_key = [0xB2; 32];
        let action = b"transfer 100 tokens";
        let target = [0xCC; 32];

        let snap = MultisigStateSnapshot::new(program_id, create_key, finalized.members_root, 2, 2, 0).unwrap();
        let pid0 = snap.derive_proposal_id(0, action, &target);
        let pid1 = snap.derive_proposal_id(1, action, &target);
        assert_ne!(pid0, pid1);
    }

    // BT-5: extreme threshold boundary tests

    #[test]
    fn builder_accepts_max_threshold_min_members() {
        // m = u8::MAX (255), n = 255 — maximal threshold with tight membership
        let mut builder = crate::multisig::MultisigBuilder::new(255);
        for _ in 0..255 {
            builder.add_member(crate::member::Member::new().unwrap().commitment()).unwrap();
        }
        let result = builder.finalize().unwrap();
        assert_eq!(result.m, 255);
        assert_eq!(result.n, 255);
    }

    #[test]
    fn builder_accepts_minimal_1_of_1() {
        // Minimal valid multisig: m=1, n=1
        let mut builder = crate::multisig::MultisigBuilder::new(1);
        builder.add_member(crate::member::Member::new().unwrap().commitment()).unwrap();
        let result = builder.finalize().unwrap();
        assert_eq!(result.m, 1);
        assert_eq!(result.n, 1);
    }

    #[test]
    fn builder_rejects_m_zero() {
        let mut builder = crate::multisig::MultisigBuilder::new(0);
        builder.add_member(crate::member::Member::new().unwrap().commitment()).unwrap();
        let result = builder.finalize();
        assert!(matches!(result, Err(SdkError::InvalidThreshold)));
    }

    #[test]
    fn builder_rejects_n_zero() {
        let builder = crate::multisig::MultisigBuilder::new(1);
        // 0 members for a 1-of-N multisig — n == 0
        let result = builder.finalize();
        assert!(matches!(result, Err(SdkError::InvalidThreshold)));
    }
}