//! Verifier-program instruction enum.
//!
//! The on-chain SPEL program dispatches on the variant in this enum.
//! `Reject` is post-MVP per PLAN.md step 4 — we ship the four-variant set
//! that is sufficient for the MVP foundation. New variants get appended,
//! never inserted, so the Borsh discriminant for existing variants stays
//! stable across versions.
//!
//! Variants:
//! - [`Instruction::CreateMultisig`] — initialize a fresh instance.
//! - [`Instruction::Propose`] — open a new proposal at the next free index.
//! - [`Instruction::Approve`] — submit a Risc0 receipt asserting member
//!   approval. Per PLAN.md step 4, the verifier extracts `public_inputs`
//!   from the receipt journal, recomputes `proposal_id`, and inserts a
//!   `NullifierEntry` PDA.
//! - [`Instruction::Execute`] — fire the `ChainedCall` once threshold is met.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{AccountId, CreateKey};
use crate::proof::ApprovePublicInputs;

/// Top-level instruction dispatched by the SPEL verifier program. Borsh-
/// serialized with a single-byte discriminant: `CreateMultisig=0`,
/// `Propose=1`, `Approve=2`, `Execute=3`. Discriminants are part of the
/// on-chain ABI and must never be reordered; new variants append.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Initialize a new multisig instance under `create_key`, frozen at
    /// member-set commitment `members_root`, with threshold `m` of `n`
    /// members.
    CreateMultisig {
        create_key: CreateKey,
        members_root: [u8; 32],
        m: u8,
        n: u32,
    },
    /// Open proposal at `index` (which must equal the instance's current
    /// `proposal_count`). `action_bytes` is the payload that `Execute`
    /// will hand to `target_program`; capped at
    /// [`crate::state::MAX_ACTION_BYTES_LEN`].
    Propose {
        create_key: CreateKey,
        index: u64,
        action_bytes: alloc::vec::Vec<u8>,
        target_program: AccountId,
    },
    /// Submit an approval receipt for proposal `index`. `public_inputs`
    /// is the 96-byte tuple the verifier cross-checks against on-chain
    /// state.
    ///
    /// The Risc0 receipt itself is NOT carried on the instruction wire —
    /// it is attached out-of-band by the host via
    /// `ExecutorEnv::add_assumption(approve_receipt)` and discharged by
    /// the verifier's `env::verify(APPROVE_CIRCUIT_IMAGE_ID, public_inputs)`
    /// call. Sending it inline would bloat every approve tx by the receipt
    /// size (KB-range) with no on-chain consumer — see BLUE-3 in the
    /// round-5 audit.
    Approve {
        create_key: CreateKey,
        index: u64,
        public_inputs: ApprovePublicInputs,
    },
    /// Execute proposal `index` if `approvals_count >= m` and `!executed`.
    Execute {
        create_key: CreateKey,
        index: u64,
    },
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use borsh::to_vec;

    fn sample_inputs() -> ApprovePublicInputs {
        ApprovePublicInputs {
            members_root: [0x11; 32],
            proposal_id: [0x22; 32],
            nullifier: [0x33; 32],
        }
    }

    #[test]
    fn create_multisig_borsh_round_trip() {
        let ix = Instruction::CreateMultisig {
            create_key: [0xAA; 32],
            members_root: [0xBB; 32],
            m: 3,
            n: 5,
        };
        let bytes = to_vec(&ix).unwrap();
        let decoded = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(ix, decoded);
    }

    #[test]
    fn propose_borsh_round_trip() {
        let ix = Instruction::Propose {
            create_key: [0xAA; 32],
            index: 7,
            action_bytes: vec![0x01, 0x02, 0x03],
            target_program: [0xCC; 32],
        };
        let bytes = to_vec(&ix).unwrap();
        let decoded = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(ix, decoded);
    }

    #[test]
    fn approve_borsh_round_trip() {
        let ix = Instruction::Approve {
            create_key: [0xAA; 32],
            index: 7,
            public_inputs: sample_inputs(),
        };
        let bytes = to_vec(&ix).unwrap();
        let decoded = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(ix, decoded);
    }

    #[test]
    fn execute_borsh_round_trip() {
        let ix = Instruction::Execute {
            create_key: [0xAA; 32],
            index: 12345,
        };
        let bytes = to_vec(&ix).unwrap();
        let decoded = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(ix, decoded);
    }

    #[test]
    fn discriminants_are_stable() {
        // Borsh enum encoding: first byte is the variant index.
        // CreateMultisig = 0, Propose = 1, Approve = 2, Execute = 3.
        // If a future PR inserts a variant in the middle of the enum this
        // assertion catches the wire-breaking change.
        fn first_byte(ix: &Instruction) -> u8 {
            to_vec(ix).unwrap()[0]
        }
        assert_eq!(
            first_byte(&Instruction::CreateMultisig {
                create_key: [0; 32],
                members_root: [0; 32],
                m: 0,
                n: 0,
            }),
            0
        );
        assert_eq!(
            first_byte(&Instruction::Propose {
                create_key: [0; 32],
                index: 0,
                action_bytes: Vec::new(),
                target_program: [0; 32],
            }),
            1
        );
        assert_eq!(
            first_byte(&Instruction::Approve {
                create_key: [0; 32],
                index: 0,
                public_inputs: sample_inputs(),
            }),
            2
        );
        assert_eq!(
            first_byte(&Instruction::Execute {
                create_key: [0; 32],
                index: 0,
            }),
            3
        );
    }

    #[test]
    fn approve_carries_canonical_public_inputs_layout() {
        // The Approve instruction embeds the 96-byte public inputs.
        // Round-trip and confirm the embedded bytes match the explicit
        // ApprovePublicInputs::to_bytes layout — protects against any
        // future Borsh-vs-canonical drift sneaking in via Instruction.
        let inputs = sample_inputs();
        let ix = Instruction::Approve {
            create_key: [0; 32],
            index: 0,
            public_inputs: inputs,
        };
        let bytes = to_vec(&ix).unwrap();
        let canonical = inputs.to_bytes();
        // The canonical 96-byte bundle must appear verbatim somewhere
        // in the instruction encoding.
        let mut found = false;
        for w in bytes.windows(canonical.len()) {
            if w == canonical.as_slice() {
                found = true;
                break;
            }
        }
        assert!(found, "canonical public-inputs layout missing from Approve encoding");
    }
}
