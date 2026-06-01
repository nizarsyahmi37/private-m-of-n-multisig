//! Shared types for the LP-0002 Private M-of-N Multisig on the Logos Execution Zone.
//!
//! This crate is consumed by THREE peers — the client SDK, the Risc0 approval
//! circuit, and the SPEL verifier program — and is the single source of truth
//! for instruction encoding, account layouts, PDA derivation, the
//! `proposal_id` formula, and the on-chain error catalog. Every byte one of
//! those peers produces or consumes flows through this crate, so any drift
//! here breaks consensus.
//!
//! # Feature gates
//!
//! - `std` (default) — full host-side surface as documented below.
//! - Without `std` — only the guest-required subset compiles:
//!   [`proof::ApprovePublicInputs`], [`proof::ChainId`],
//!   [`proof::derive_proposal_id`], and the 96-byte
//!   [`proof::APPROVE_PUBLIC_INPUTS_LEN`] constant. The Risc0 approve
//!   circuit depends on this crate with `default-features = false`.
//!
//! # Modules
//!
//! - [`error`] (std) — `CoreError` and the deterministic E1xxx–E4xxx code
//!   catalog the verifier returns. Matches PLAN.md step 4 verbatim.
//! - [`pda`] (std) — `b"pmsig_state__"` / `b"pmsig_prop___"` /
//!   `b"pmsig_vault__"` / `b"pmsig_nulli__"` seed constants plus derivation
//!   helpers. Uses `Vec` internally so it lives behind `std`.
//! - [`state`] (std) — account structs (`MultisigState`, `Proposal`,
//!   `NullifierEntry`, `Vault`) serialized via Borsh.
//! - [`instructions`] (std) — the four MVP instructions (`CreateMultisig`,
//!   `Propose`, `Approve`, `Execute`); `Reject` is deferred post-MVP.
//! - [`proof`] (unconditional) — `ApprovePublicInputs` with its fixed
//!   96-byte canonical layout (PLAN.md step 2 spec), plus
//!   `derive_proposal_id` which encodes the cross-chain / action-binding
//!   formula from PLAN.md.

#![cfg_attr(not(feature = "std"), no_std)]

/// 32-byte LEZ program identifier. Mirrors the runtime's program-id type.
pub type ProgramId = [u8; 32];
/// 32-byte LEZ account address — the value returned by every PDA derivation
/// helper in [`pda`].
pub type AccountId = [u8; 32];
/// 32-byte caller-chosen salt that distinguishes a multisig instance from
/// every other `(program_id, create_key)` pair. Stored in `MultisigState`
/// and threaded through every child PDA derivation.
pub type CreateKey = [u8; 32];

#[cfg(feature = "std")]
pub mod error;
#[cfg(feature = "std")]
pub mod instructions;
#[cfg(feature = "std")]
pub mod pda;
pub mod proof;
#[cfg(feature = "std")]
pub mod state;

#[cfg(feature = "std")]
pub use error::CoreError;
#[cfg(feature = "std")]
pub use instructions::Instruction;
#[cfg(feature = "std")]
pub use pda::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_pda, derive_vault_pda,
    SEED_MULTISIG_STATE, SEED_NULLIFIER, SEED_PROPOSAL, SEED_VAULT,
};
pub use proof::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
    DEPLOYMENT_CHAIN_ID_U64,
};
#[cfg(feature = "std")]
pub use state::{MultisigState, NullifierEntry, Proposal, Vault, MAX_ACTION_BYTES_LEN};
