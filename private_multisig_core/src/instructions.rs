//! Verifier-program instruction enum.
//!
//! The same enum is used on both sides of the SDK boundary. The SPEL
//! verifier program in `methods/guest/src/bin/private_multisig.rs` opts in
//! via `#[lez_program(instruction = "private_multisig_core::Instruction")]`,
//! so the on-chain wire is `risc0_zkvm::serde::to_vec(&Instruction)` of
//! exactly this type. The Borsh derives are kept for off-chain SDK
//! persistence (`ApprovalSession` storage in step 5).
//!
//! Variant order is the canonical wire ordering — never reorder, append
//! only. The matching SPEL handler dispatch is by variant NAME so the
//! source order in the guest file does not affect on-chain semantics, but
//! it does affect the discriminant the serde wire format emits.
//!
//! Variants:
//! - [`Instruction::CreateMultisig`] — initialize a fresh instance.
//! - [`Instruction::Propose`] — open a new proposal at the next free index.
//! - [`Instruction::Approve`] — submit an approval; verifier discharges
//!   the receipt assumption via `env::verify` and inserts a
//!   `NullifierEntry` PDA.
//! - [`Instruction::Execute`] — fire the `ChainedCall` once threshold is met.
//! - [`Instruction::CreateVault`] — initialize the vault PDA and claim it
//!   under the multisig program (round-5 R5-T1 fix).
//! - [`Instruction::Reject`] — placeholder that requires a state-PDA seed
//!   so the receipt cannot be emitted against a nonexistent instance
//!   (round-5 R5-T5 fix).

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{AccountId, CreateKey};

/// Top-level instruction dispatched by the SPEL verifier program.
///
/// Two encodings are simultaneously supported:
///
/// - **On-chain wire**: `risc0_zkvm::serde::to_vec(&Instruction)` produces
///   the `Vec<u32>` payload the verifier's macro-generated dispatcher
///   reads via `risc0_zkvm::serde::Deserializer`. The single-u32
///   discriminants are `CreateMultisig=0`, `Propose=1`, `Approve=2`,
///   `Execute=3`, `CreateVault=4`, `Reject=5`.
/// - **Off-chain SDK persistence**: `borsh::to_vec(&Instruction)` produces
///   a single-byte-discriminant Borsh encoding the SDK can write to its
///   resumable session store.
///
/// Discriminants for variants 0..=4 are part of the on-chain ABI and must
/// never be reordered; new variants append.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
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
    /// Submit an approval for proposal `index`. `nullifier` is the
    /// member-bound nullifier (also embedded inside `public_inputs[64..96]`,
    /// but supplied as a top-level field so the verifier macro can use it
    /// as a `NullifierEntry` PDA seed). `public_inputs` is the 96-byte
    /// fixed-layout bundle `[members_root || proposal_id || nullifier]`.
    ///
    /// The Risc0 receipt itself is NOT carried on the instruction wire —
    /// the host attaches it via `ExecutorEnv::add_assumption(approve_receipt)`
    /// and the verifier discharges it via
    /// `env::verify(APPROVE_CIRCUIT_IMAGE_ID, public_inputs)`.
    Approve {
        create_key: CreateKey,
        index: u64,
        nullifier: [u8; 32],
        public_inputs: alloc::vec::Vec<u8>,
    },
    /// Execute proposal `index` if `approvals_count >= m` and `!executed`.
    Execute { create_key: CreateKey, index: u64 },
    /// Initialize the vault PDA for an instance and claim its ownership
    /// for the verifier program. Round-5 fix for R5-T1: without this
    /// instruction the vault would have `program_owner = DEFAULT_PROGRAM_ID`
    /// and the chained call in `Execute` would silently no-op at the
    /// runtime's balance-authorization check.
    CreateVault { create_key: CreateKey },
    /// Reject a proposal. Post-MVP placeholder; the on-chain handler is a
    /// no-op gated behind a state-PDA seed so emitted receipts always
    /// refer to a live multisig instance (round-5 R5-T5 fix).
    Reject { create_key: CreateKey },
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::ApprovePublicInputs;
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
        let inputs = sample_inputs();
        let ix = Instruction::Approve {
            create_key: [0xAA; 32],
            index: 7,
            nullifier: inputs.nullifier,
            public_inputs: inputs.to_bytes().to_vec(),
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
    fn create_vault_borsh_round_trip() {
        let ix = Instruction::CreateVault {
            create_key: [0xAA; 32],
        };
        let bytes = to_vec(&ix).unwrap();
        let decoded = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(ix, decoded);
    }

    #[test]
    fn reject_borsh_round_trip() {
        let ix = Instruction::Reject {
            create_key: [0xAA; 32],
        };
        let bytes = to_vec(&ix).unwrap();
        let decoded = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(ix, decoded);
    }

    #[test]
    fn discriminants_are_stable() {
        // Borsh enum encoding: first byte is the variant index.
        // CreateMultisig = 0, Propose = 1, Approve = 2, Execute = 3,
        // CreateVault = 4, Reject = 5. If a future PR inserts a variant
        // in the middle of the enum this assertion catches the
        // wire-breaking change.
        fn first_byte(ix: &Instruction) -> u8 {
            to_vec(ix).unwrap()[0]
        }
        let inputs = sample_inputs();
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
                nullifier: [0; 32],
                public_inputs: inputs.to_bytes().to_vec(),
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
        assert_eq!(
            first_byte(&Instruction::CreateVault {
                create_key: [0; 32],
            }),
            4
        );
        assert_eq!(
            first_byte(&Instruction::Reject {
                create_key: [0; 32],
            }),
            5
        );
    }

    #[test]
    fn approve_carries_canonical_public_inputs_layout() {
        // The Approve instruction's `public_inputs` field is the canonical
        // 96-byte ApprovePublicInputs layout, passed as `Vec<u8>` so the
        // SPEL verifier handler can length-check it before decoding.
        let inputs = sample_inputs();
        let ix = Instruction::Approve {
            create_key: [0; 32],
            index: 0,
            nullifier: inputs.nullifier,
            public_inputs: inputs.to_bytes().to_vec(),
        };
        let bytes = to_vec(&ix).unwrap();
        let canonical = inputs.to_bytes();
        let mut found = false;
        for w in bytes.windows(canonical.len()) {
            if w == canonical.as_slice() {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "canonical public-inputs layout missing from Approve encoding"
        );
    }
}
