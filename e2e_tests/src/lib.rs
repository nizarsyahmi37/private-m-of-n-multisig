//! LP-0002 end-to-end test harness for PLAN.md step 7.
//!
//! Exports the compiled `noop` guest's ELF + image-id so the integration
//! test at `tests/create_propose_approve_execute.rs` can deploy it as
//! the chained-call target.
//!
//! ## Layer A vs Layer B
//!
//! Two test layers ship in this crate:
//!
//! - **Layer A** (always compiled): pure Risc0 cryptographic
//!   composition. Drives the SDK's `ApprovalProver` for three members,
//!   verifies each receipt against `APPROVE_CIRCUIT_IMAGE_ID`, asserts
//!   the same-member-replay rejection that the on-chain
//!   `NullifierEntry` PDA enforces. No LEZ deps; runs in CI under
//!   `RISC0_DEV_MODE=1`.
//!
//! - **Layer B** (gated by `--features lez-integration` AND the
//!   `LOGOS_BLOCKCHAIN_CIRCUITS` env var): full LEZ sequencer harness.
//!   Spins Bedrock + sequencer + indexer + wallet via `testcontainers`
//!   and the LEZ in-process pattern, deploys `private_multisig.bin` +
//!   `noop.bin`, drives the entire `create_multisig → create_vault →
//!   propose → 2×approve → execute` flow. Closes THREAT_MODEL §10
//!   item 9's deferred capability gap by exercising the outer prover
//!   in-process with the inner approve receipt attached as an
//!   assumption. Dev-machine-only; CI doesn't have the circuits prereq.

// The build script emits `NOOP_ELF` and `NOOP_ID` into `methods.rs`.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(feature = "lez-integration")]
pub mod harness;
