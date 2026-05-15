//! Shared types for the LP-0002 Private M-of-N Multisig on the Logos Execution Zone.
//!
//! This crate is consumed by THREE peers — the client SDK, the Risc0 approval
//! circuit, and the SPEL verifier program — and is the single source of truth
//! for instruction encoding, account layouts, PDA derivation, the
//! `proposal_id` formula, and the on-chain error catalog. Every byte one of
//! those peers produces or consumes flows through this crate, so any drift
//! here breaks consensus.
//!
//! Modules:
//! - [`error`] — `CoreError` and the deterministic E1xxx–E4xxx code catalog
//!   the verifier returns. Matches PLAN.md step 4 verbatim.
//! - [`pda`] — `b"pmsig_state__"` / `b"pmsig_prop___"` / `b"pmsig_vault__"` /
//!   `b"pmsig_nulli__"` seed constants plus derivation helpers.
//! - [`state`] — account structs (`MultisigState`, `Proposal`,
//!   `NullifierEntry`, `Vault`) serialized via Borsh.
//! - [`instructions`] — the four MVP instructions (`CreateMultisig`,
//!   `Propose`, `Approve`, `Execute`); `Reject` is deferred post-MVP.
//! - [`proof`] — `ApprovePublicInputs` with its fixed 96-byte canonical
//!   layout (PLAN.md step 2 spec), plus `derive_proposal_id` which encodes
//!   the cross-chain / action-binding formula from PLAN.md.
//!
//! ## no_std readiness
//!
//! Today this crate links against `std` by default (matching the host build).
//! Step 3 will switch `crypto`, `borsh`, and `thiserror` to
//! `default-features = false` and add an `alloc` feature gate so the Risc0
//! guest can link the same crate. The code paths the guest actually calls
//! (`derive_proposal_id`, `ApprovePublicInputs`, `CoreError`,
//! `pda::derive_*`) are already free of `std::` items so the refactor will
//! be Cargo.toml plumbing, not logic changes.

pub mod error;
pub mod instructions;
pub mod pda;
pub mod proof;
pub mod state;

pub use error::CoreError;
pub use instructions::Instruction;
pub use pda::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_pda, derive_vault_pda,
    AccountId, CreateKey, ProgramId, SEED_MULTISIG_STATE, SEED_NULLIFIER, SEED_PROPOSAL,
    SEED_VAULT,
};
pub use proof::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
};
pub use state::{
    MultisigState, NullifierEntry, Proposal, Vault, MAX_ACTION_BYTES_LEN,
};
