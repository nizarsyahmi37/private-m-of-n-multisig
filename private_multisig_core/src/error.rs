//! Deterministic error catalog.
//!
//! Every error the verifier program can return surfaces as a stable numeric
//! code so on-chain consumers (block explorers, integration tests, the SDK's
//! retry logic) can match on the code without parsing free-form text. The
//! codes are grouped by class:
//!
//! - `E1xxx` — state-machine violations (instance not active, proposal
//!   expired or executed).
//! - `E2xxx` — proof-verification failures (bad receipt, image-ID mismatch,
//!   root mismatch, proposal-id mismatch).
//! - `E3xxx` — double-vote detection.
//! - `E4xxx` — execution preconditions.
//!
//! Codes are stable: never renumber, never reuse a retired number, never
//! change the (code → meaning) mapping. New errors get fresh codes in the
//! next-free slot of their class.

/// Error codes returned by the verifier program. The discriminants are kept
/// stable by the `code()` method — adding a variant in the middle of the
/// enum is fine, removing one is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error("E1000: instance not active")]
    InstanceNotActive,
    #[error("E1001: proposal expired or executed")]
    ProposalExpiredOrExecuted,
    #[error("E1002: action bytes too long")]
    ActionBytesTooLong,
    #[error("E1003: invalid threshold")]
    InvalidThreshold,

    #[error("E2000: invalid receipt")]
    InvalidReceipt,
    #[error("E2001: image id mismatch")]
    ImageIdMismatch,
    #[error("E2002: root mismatch")]
    RootMismatch,
    #[error("E2003: proposal id mismatch")]
    ProposalIdMismatch,

    #[error("E3000: nullifier already used")]
    NullifierAlreadyUsed,

    #[error("E4000: threshold not met")]
    ThresholdNotMet,
    #[error("E4001: already executed")]
    AlreadyExecuted,
}

impl CoreError {
    /// Stable numeric code. Each variant maps to one value; the mapping is
    /// part of the on-chain ABI and must never change.
    pub const fn code(self) -> u32 {
        match self {
            Self::InstanceNotActive => 1000,
            Self::ProposalExpiredOrExecuted => 1001,
            Self::ActionBytesTooLong => 1002,
            Self::InvalidThreshold => 1003,
            Self::InvalidReceipt => 2000,
            Self::ImageIdMismatch => 2001,
            Self::RootMismatch => 2002,
            Self::ProposalIdMismatch => 2003,
            Self::NullifierAlreadyUsed => 3000,
            Self::ThresholdNotMet => 4000,
            Self::AlreadyExecuted => 4001,
        }
    }

    /// Inverse of `code()`. Returns `None` for unknown codes so callers
    /// cannot accidentally synthesize a variant from arbitrary input.
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1000 => Some(Self::InstanceNotActive),
            1001 => Some(Self::ProposalExpiredOrExecuted),
            1002 => Some(Self::ActionBytesTooLong),
            1003 => Some(Self::InvalidThreshold),
            2000 => Some(Self::InvalidReceipt),
            2001 => Some(Self::ImageIdMismatch),
            2002 => Some(Self::RootMismatch),
            2003 => Some(Self::ProposalIdMismatch),
            3000 => Some(Self::NullifierAlreadyUsed),
            4000 => Some(Self::ThresholdNotMet),
            4001 => Some(Self::AlreadyExecuted),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stable-mapping regression: every variant must have the exact code
    /// PLAN.md step 4 documents. If this test ever has to be edited to make
    /// it pass, that is a breaking ABI change and demands a major version
    /// bump.
    #[test]
    fn codes_match_plan_md_catalog() {
        assert_eq!(CoreError::InstanceNotActive.code(), 1000);
        assert_eq!(CoreError::ProposalExpiredOrExecuted.code(), 1001);
        assert_eq!(CoreError::ActionBytesTooLong.code(), 1002);
        assert_eq!(CoreError::InvalidThreshold.code(), 1003);
        assert_eq!(CoreError::InvalidReceipt.code(), 2000);
        assert_eq!(CoreError::ImageIdMismatch.code(), 2001);
        assert_eq!(CoreError::RootMismatch.code(), 2002);
        assert_eq!(CoreError::ProposalIdMismatch.code(), 2003);
        assert_eq!(CoreError::NullifierAlreadyUsed.code(), 3000);
        assert_eq!(CoreError::ThresholdNotMet.code(), 4000);
        assert_eq!(CoreError::AlreadyExecuted.code(), 4001);
    }

    #[test]
    fn from_code_round_trips() {
        let all = [
            CoreError::InstanceNotActive,
            CoreError::ProposalExpiredOrExecuted,
            CoreError::ActionBytesTooLong,
            CoreError::InvalidThreshold,
            CoreError::InvalidReceipt,
            CoreError::ImageIdMismatch,
            CoreError::RootMismatch,
            CoreError::ProposalIdMismatch,
            CoreError::NullifierAlreadyUsed,
            CoreError::ThresholdNotMet,
            CoreError::AlreadyExecuted,
        ];
        for e in all {
            assert_eq!(CoreError::from_code(e.code()), Some(e));
        }
    }

    #[test]
    fn from_code_rejects_unknown() {
        assert_eq!(CoreError::from_code(0), None);
        assert_eq!(CoreError::from_code(999), None);
        // 1003 is now InvalidThreshold (FINDING-V2-A); 1004 is the next unused.
        assert_eq!(CoreError::from_code(1004), None);
        assert_eq!(CoreError::from_code(2999), None);
        assert_eq!(CoreError::from_code(5000), None);
        assert_eq!(CoreError::from_code(u32::MAX), None);
    }

    #[test]
    fn display_strings_carry_the_code() {
        // The `Display` text is what shows up in logs and tx error fields.
        // Confirm each one mentions its code so a grep over chain logs
        // returns hits without needing to decode.
        assert!(
            CoreError::NullifierAlreadyUsed
                .to_string()
                .contains("E3000")
        );
        assert!(CoreError::ThresholdNotMet.to_string().contains("E4000"));
    }
}
