//! Client SDK for the LP-0002 Private M-of-N Multisig on the Logos Execution Zone.
//!
//! This crate provides the high-level API that member devices and relayers use
//! to interact with the on-chain verifier program (`private_multisig_program`).
//! It handles:
//! - **Identity**: key generation, secret storage, and identity commitment
//! - **Multisig lifecycle**: creating instances, proposing actions, building
//!   approval transactions, executing proposals
//! - **Proof generation**: wrapping the Risc0 approval circuit with
//!   `ApprovalProver`, which produces receipts compatible with the verifier's
//!   `env::verify` call
//! - **Resumable sessions**: `ApprovalSession` persisted to a local sled
//!   database so partial approvals survive client restarts
//!
//! # Feature gates
//!
//! - `std` (default) — full surface including `ApprovalProver` (requires the
//!   Risc0 toolchain via `risc0-zkvm/std`) and session persistence (requires
//!   `sled`). Without `std`, only the `Member`, `IdentityCommitment`, and
//!   builder types compile.
//!
//! # Example (high-level flow)
//!
//! ```ignore
//! use private_multisig_sdk::{Member, MultisigBuilder, ApprovalProver};
//!
//! // Alice generates her identity
//! let alice = Member::new()?;
//! let bob = Member::new()?;
//! let carol = Member::new()?;
//!
//! // Multisig creator gathers commitments and builds the instance
//! let members_root = MultisigBuilder::new(2) // m=2 threshold
//!     .add_member(alice.commitment())
//!     .add_member(bob.commitment())
//!     .add_member(carol.commitment())
//!     .finalize()?;
//!
//! // Bob creates a proposal
//! let proposal = ProposalBuilder::new(create_key, 0, action_bytes, target)
//!     .build(&state_pda)?;
//!
//! // Alice approves — Risc0 proves in the background
//! let prover = ApprovalProver::new(
//!     alice.secret_key(),
//!     alice.salt(),
//!     merkle_path,
//!     indices,
//!     proposal.proposal_id(),
//!     members_root,
//! )?;
//! let receipt = prover.prove()?; // blocks until Risc0 finishes
//! ```
//!
//! For the full end-to-end flow including session recovery, see the CLI
//! (`cli/`) which wires this SDK to the LEZ IDL-driven transaction interface.

pub mod error;
pub mod member;
pub mod multisig;
#[cfg(feature = "prover")]
pub mod prover;
pub mod session;

pub use error::SdkError;
pub use member::{IdentityCommitment, Member};
pub use multisig::{MultisigBuilder, MultisigStateSnapshot};
#[cfg(feature = "prover")]
pub use prover::ApprovalProver;
pub use session::{ApprovalSession, SessionStatus};

/// Re-export the core types the SDK needs to reference.
pub use private_multisig_core::proof::ApprovePublicInputs;
