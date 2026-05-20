//! Deterministic SDK error types with E5xxx codes.
//!
//! E1xxx–E4xxx are owned by the on-chain verifier (defined in
//! `private_multisig_core::error::CoreError`). SDK-specific errors use
//! E5xxx to avoid any collision.

use thiserror::Error;

/// Top-level SDK error type.
///
/// Every variant carries a deterministic error code (E5xxx) so callers
/// that consume errors across process boundaries (e.g. CLI → SDK via IPC)
/// can match codes reliably without parsing error messages.
#[derive(Error, Debug)]
pub enum SdkError {
    // --- Cryptographic / identity ---
    #[error("E5001: invalid secret key length (expected 32 bytes)")]
    InvalidSecretKeyLength,

    #[error("E5002: invalid identity commitment")]
    InvalidIdentityCommitment,

    #[error("E5003: Merkle proof verification failed")]
    MerkleProofInvalid,

    #[error("E5004: nullifier derivation failed")]
    NullifierDerivationFailed,

    // --- Proposal ---
    #[error("E5010: action_bytes exceeds maximum length")]
    ActionBytesTooLarge,

    #[error("E5011: action_bytes hash mismatch (proposal_id recomputation)")]
    ActionBytesHashMismatch,

    #[error("E5012: target_program hash mismatch (proposal_id recomputation)")]
    TargetProgramHashMismatch,

    #[error("E5013: invalid proposal index (does not match instance proposal_count)")]
    ProposalIndexMismatch,

    // --- Multisig ---
    #[error("E5019: invalid threshold (m == 0 or n == 0)")]
    InvalidThreshold,

    #[error("E5020: member count below threshold (need m members)")]
    InsufficientMembers { m: u8, n: u32 },

    #[error("E5021: member count exceeds maximum (m <= n violated)")]
    ThresholdExceedsMembers,

    #[error("E5022: member already added (duplicate commitment)")]
    DuplicateMember,

    #[error("E5023: builder already finalized")]
    BuilderAlreadyFinalized,

    // --- Risc0 proving ---
    #[error("E5030: Risc0 proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("E5031: Risc0 receipt verification failed: {0}")]
    ReceiptVerificationFailed(String),

    #[error("E5032: image ID mismatch (pinned vs. computed)")]
    ImageIdMismatch,

    #[error("E5033: DEV_MODE=1 receipt passed to non-dev-mode prover")]
    DevModeReceiptInProdProver,

    // --- Session persistence ---
    #[error("E5040: session store open failed: {0}")]
    SessionStoreOpenFailed(String),

    #[error("E5041: session not found for (instance, proposal, commitment)")]
    SessionNotFound,

    #[error("E5042: session corrupted (deserialization failed)")]
    SessionCorrupted,

    #[error("E5043: session in unexpected status for requested operation")]
    SessionStatusMismatch,

    // --- Keystore ---
    #[error("E5050: keystore file open failed: {0}")]
    KeystoreOpenFailed(String),

    #[error("E5051: keystore decryption failed (wrong password or corrupted file)")]
    KeystoreDecryptionFailed,

    #[error("E5052: keystore serialization failed")]
    KeystoreSerializationFailed,

    #[error("E5053: no keystore found at {0}")]
    NoKeystoreFound(String),

    // --- Serialization ---
    #[error("E5060: Borsh serialization failed")]
    BorshSerializationFailed,

    #[error("E5061: Borsh deserialization failed")]
    BorshDeserializationFailed,

    // --- I/O ---
    #[error("E5070: home directory not found (cannot resolve ~/.private-multisig)")]
    HomeDirNotFound,
}

impl SdkError {
    /// Returns the deterministic numeric error code.
    pub fn code(&self) -> u32 {
        match self {
            SdkError::InvalidSecretKeyLength => 5001,
            SdkError::InvalidIdentityCommitment => 5002,
            SdkError::MerkleProofInvalid => 5003,
            SdkError::NullifierDerivationFailed => 5004,
            SdkError::ActionBytesTooLarge => 5010,
            SdkError::ActionBytesHashMismatch => 5011,
            SdkError::TargetProgramHashMismatch => 5012,
            SdkError::ProposalIndexMismatch => 5013,
            SdkError::InvalidThreshold => 5019,
            SdkError::InsufficientMembers { .. } => 5020,
            SdkError::ThresholdExceedsMembers => 5021,
            SdkError::DuplicateMember => 5022,
            SdkError::BuilderAlreadyFinalized => 5023,
            SdkError::ProofGenerationFailed(_) => 5030,
            SdkError::ReceiptVerificationFailed(_) => 5031,
            SdkError::ImageIdMismatch => 5032,
            SdkError::DevModeReceiptInProdProver => 5033,
            SdkError::SessionStoreOpenFailed(_) => 5040,
            SdkError::SessionNotFound => 5041,
            SdkError::SessionCorrupted => 5042,
            SdkError::SessionStatusMismatch => 5043,
            SdkError::KeystoreOpenFailed(_) => 5050,
            SdkError::KeystoreDecryptionFailed => 5051,
            SdkError::KeystoreSerializationFailed => 5052,
            SdkError::NoKeystoreFound(_) => 5053,
            SdkError::BorshSerializationFailed => 5060,
            SdkError::BorshDeserializationFailed => 5061,
            SdkError::HomeDirNotFound => 5070,
        }
    }
}