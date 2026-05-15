//! Account state structs.
//!
//! Each struct corresponds to one account class the verifier program owns:
//!
//! - [`MultisigState`] — one per multisig instance. Stores threshold, member
//!   count, the frozen `members_root`, and a monotonically increasing
//!   `proposal_count`.
//! - [`Proposal`] — one per `(instance, index)`. Stores the action being
//!   approved, the running approval count, and an `executed` flag.
//! - [`NullifierEntry`] — one per `(proposal, nullifier)`. Empty payload;
//!   the bit is the existence of the PDA. Init-fails-if-exists is the
//!   double-vote check.
//! - [`Vault`] — one per multisig. Holds funds disbursed by `execute`.
//!
//! Serialization is Borsh — same encoding the SPEL framework and the
//! lez-multisig PoC use. Every struct here has fixed serialized size EXCEPT
//! `Proposal.action_bytes`, which is variable-length and capped at
//! [`MAX_ACTION_BYTES_LEN`].

use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::CoreError;
use crate::pda::{AccountId, CreateKey};

/// Maximum inline `action_bytes` length. Larger payloads must be committed
/// via `H(action_bytes)` only with the bytes stored in a content-addressed
/// off-chain store — PLAN.md step 2.
pub const MAX_ACTION_BYTES_LEN: usize = 4096;

/// State of one multisig instance. Created by `CreateMultisig`, never
/// updated except `proposal_count` which increments on each `Propose`.
///
/// `members_root` is immutable after creation — the v1 verifier has no
/// `update_root` instruction. Anyone who needs to add or remove members
/// must create a new instance.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MultisigState {
    /// Caller-chosen salt that distinguishes this instance from any other
    /// `(program_id, create_key)`. Stored so the verifier can re-derive
    /// child PDAs without trusting instruction inputs.
    pub create_key: CreateKey,
    /// Poseidon-or-SHA-256 Merkle root over the N member commitments.
    pub members_root: [u8; 32],
    /// Threshold of approvals required to execute (M).
    pub m: u8,
    /// Total members in the instance (N).
    pub n: u32,
    /// Number of proposals created so far; next proposal index is exactly
    /// this value, then this is incremented in the same instruction.
    pub proposal_count: u64,
}

/// One proposal under a multisig instance. The action and target stay
/// write-once after `Propose`; only `approvals_count` and `executed`
/// change as the lifecycle proceeds.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    /// Bytes of the action the multisig will execute via `ChainedCall` once
    /// threshold approvals are collected. Capped at [`MAX_ACTION_BYTES_LEN`].
    pub action_bytes: alloc::vec::Vec<u8>,
    /// Program the `ChainedCall` is dispatched to.
    pub target_program: AccountId,
    /// Number of distinct members that have approved so far.
    pub approvals_count: u32,
    /// Single-shot flag flipped by `Execute`. Set-then-read-elsewhere
    /// prevents re-execution.
    pub executed: bool,
}

impl Proposal {
    /// Validate `action_bytes` length against [`MAX_ACTION_BYTES_LEN`]. The
    /// verifier calls this on every `Propose` and `Execute`; callers should
    /// gate on it before submission.
    pub fn validate_action_bytes(action_bytes: &[u8]) -> Result<(), CoreError> {
        if action_bytes.len() > MAX_ACTION_BYTES_LEN {
            Err(CoreError::ActionBytesTooLong)
        } else {
            Ok(())
        }
    }
}

/// Empty PDA whose existence is the only data: present means "this
/// nullifier has been used for this proposal." The verifier `init`s this
/// PDA inside the `Approve` handler — if it already exists the init
/// instruction fails and the approval is rejected as a double-vote.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NullifierEntry;

/// Per-multisig vault account. Holds funds that the `Execute` action can
/// disburse. v1 stores just the binding `create_key` so the verifier can
/// re-derive the PDA without trusting the caller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub create_key: CreateKey,
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use borsh::to_vec;

    fn sample_state() -> MultisigState {
        MultisigState {
            create_key: [0xAA; 32],
            members_root: [0xBB; 32],
            m: 3,
            n: 5,
            proposal_count: 42,
        }
    }

    fn sample_proposal() -> Proposal {
        Proposal {
            action_bytes: vec![0x01, 0x02, 0x03, 0x04],
            target_program: [0xCC; 32],
            approvals_count: 2,
            executed: false,
        }
    }

    #[test]
    fn multisig_state_borsh_round_trip() {
        let state = sample_state();
        let bytes = to_vec(&state).unwrap();
        let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn multisig_state_borsh_serialized_size_is_fixed() {
        // 32 (create_key) + 32 (members_root) + 1 (m) + 4 (n) + 8 (proposal_count) = 77
        let bytes = to_vec(&sample_state()).unwrap();
        assert_eq!(bytes.len(), 77, "MultisigState wire size drifted: got {}", bytes.len());
    }

    #[test]
    fn proposal_borsh_round_trip() {
        let p = sample_proposal();
        let bytes = to_vec(&p).unwrap();
        let decoded: Proposal = Proposal::try_from_slice(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn proposal_borsh_round_trip_with_empty_action_bytes() {
        let p = Proposal {
            action_bytes: Vec::new(),
            ..sample_proposal()
        };
        let bytes = to_vec(&p).unwrap();
        let decoded: Proposal = Proposal::try_from_slice(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn proposal_borsh_round_trip_with_max_size_action_bytes() {
        let p = Proposal {
            action_bytes: vec![0xFE; MAX_ACTION_BYTES_LEN],
            ..sample_proposal()
        };
        let bytes = to_vec(&p).unwrap();
        let decoded: Proposal = Proposal::try_from_slice(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn validate_action_bytes_accepts_under_cap() {
        for len in [0usize, 1, 32, 1024, MAX_ACTION_BYTES_LEN] {
            let data = vec![0u8; len];
            assert!(Proposal::validate_action_bytes(&data).is_ok(), "len {len}");
        }
    }

    #[test]
    fn validate_action_bytes_rejects_over_cap() {
        let data = vec![0u8; MAX_ACTION_BYTES_LEN + 1];
        assert!(Proposal::validate_action_bytes(&data).is_err());
    }

    #[test]
    fn nullifier_entry_round_trip_is_zero_bytes() {
        let bytes = to_vec(&NullifierEntry).unwrap();
        assert!(bytes.is_empty(), "NullifierEntry must serialize to zero bytes");
        let decoded: NullifierEntry = NullifierEntry::try_from_slice(&bytes).unwrap();
        assert_eq!(NullifierEntry, decoded);
    }

    #[test]
    fn vault_round_trip_is_32_bytes() {
        let v = Vault { create_key: [0x77; 32] };
        let bytes = to_vec(&v).unwrap();
        assert_eq!(bytes.len(), 32);
        let decoded: Vault = Vault::try_from_slice(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn max_action_bytes_len_matches_plan_md() {
        // PLAN.md step 2 explicitly says 4 KiB.
        assert_eq!(MAX_ACTION_BYTES_LEN, 4096);
    }
}
