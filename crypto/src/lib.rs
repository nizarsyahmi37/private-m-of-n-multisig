//! Scheme-agnostic cryptographic primitives for the LP-0002 Private M-of-N Multisig.
//!
//! Independent of Risc0 and LEZ so it can be exercised standalone. Implements:
//! - `Hasher` trait + `Sha256Hasher` default impl (see `hash`)
//! - `Identity` and `IdentityCommitment` (see `identity`)
//! - Fixed-depth `MerkleTree` with append, root, path, and verification (see `merkle`)
//! - `nullifier` derivation (see `nullifier`)
//!
//! Per PLAN.md §Open decisions, the hash choice is deferred to step 1 of the
//! implementation spike: SHA-256 wins for STARK-only Risc0 verification, Poseidon
//! wins if a Groth16 wrap is required. The `Hasher` trait keeps both paths reachable.
//!
//! # Feature gates
//!
//! - `std` (default) — full host-side surface: `MerkleTree`, `MerkleError`,
//!   and the SHA-256 std-targeted code paths.
//! - Without `std` — only the guest-required subset is reachable. The Risc0
//!   approve circuit and any other no_std consumer should depend on this crate
//!   with `default-features = false`.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod hash;
pub mod identity;
pub mod merkle;
pub mod nullifier;

pub use hash::{Hash, Hasher, Sha256Hasher, DOMAIN_LEAF, DOMAIN_NODE, HASH_LEN};
pub use identity::{Identity, IdentityCommitment, SALT_LEN, SK_LEN};
pub use merkle::{verify_proof, MerkleProof, MAX_LEAVES, MERKLE_DEPTH};
#[cfg(feature = "std")]
pub use merkle::{MerkleError, MerkleTree};
pub use nullifier::nullifier;
