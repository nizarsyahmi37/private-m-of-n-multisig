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

pub mod hash;
pub mod identity;
pub mod merkle;
pub mod nullifier;

pub use hash::{Hash, Hasher, Sha256Hasher, HASH_LEN};
pub use identity::{Identity, IdentityCommitment};
pub use merkle::{MerkleError, MerkleProof, MerkleTree, MERKLE_DEPTH};
pub use nullifier::nullifier;
