//! LP-0002 Private M-of-N Multisig — SPEL verifier program.
//!
//! Compiles to a Risc0 guest via `risc0-build` and runs on the LEZ chain.
//! Built with the SPEL framework (Anchor-style macros for LEZ programs).
//!
//! Instruction set per PLAN.md step 4:
//! - `create_multisig` — initialize a new instance, validate `(m, n)`
//! - `propose`         — open a proposal under an active instance
//! - `approve`         — submit a Risc0 receipt + nullifier; verify everything
//! - `execute`         — fire the chained call once `approvals_count >= m`
//! - `reject`          — placeholder, no-op for the MVP
//!
//! Error codes follow `private_multisig_core::CoreError` (E1xxx-E4xxx); they
//! are surfaced via `SpelError::custom(code, ...)`. The on-chain receipt
//! carries `6000 + code` per SPEL's convention so `1003` (InvalidThreshold)
//! shows up as `7003`, etc.
//!
//! Image-id binding for `approve` is
//! `private_multisig_program::APPROVE_CIRCUIT_IMAGE_ID`. The verifier program's
//! own image-id (this guest's) is `private_multisig_program::PRIVATE_MULTISIG_IMAGE_ID`.

use borsh::BorshSerialize;
use private_multisig_core::{MultisigState, Proposal};
use spel_framework::prelude::*;

#[lez_program]
mod private_multisig {
    #[allow(unused_imports)]
    use super::*;

    /// Initialize a new multisig instance.
    ///
    /// Validates `(m, n)` via `MultisigState::validate_threshold` and writes
    /// a fresh `MultisigState` to the state account. `proposal_count` starts
    /// at zero.
    #[instruction]
    pub fn create_multisig(
        #[account(init, pda = [literal("pmsig_state__"), arg("create_key")])]
        mut state: AccountWithMetadata,
        #[account(signer)]
        admin: AccountWithMetadata,
        create_key: [u8; 32],
        members_root: [u8; 32],
        m: u8,
        n: u32,
    ) -> SpelResult {
        // Threshold validation: rejects m=0, n=0, m>n. Returns
        // CoreError::InvalidThreshold (E1003) which we surface to SPEL as
        // `SpelError::custom(1003, _)` so on-chain consumers can match on
        // the original code through the `6000 + code` convention.
        MultisigState::validate_threshold(m, n)
            .map_err(|e| SpelError::custom(e.code(), e.to_string()))?;

        let body = MultisigState {
            create_key,
            members_root,
            m,
            n,
            proposal_count: 0,
        };
        let bytes = borsh::to_vec(&body).map_err(|e| {
            SpelError::custom(
                private_multisig_core::CoreError::InstanceNotActive.code(),
                format!("MultisigState serialization failed: {e}"),
            )
        })?;
        state.account.data = bytes.try_into().map_err(|_| {
            SpelError::custom(
                private_multisig_core::CoreError::InstanceNotActive.code(),
                "MultisigState body exceeds account data cap".to_string(),
            )
        })?;

        Ok(SpelOutput::execute(vec![state, admin], vec![]))
    }

    /// Open a proposal under an active instance.
    ///
    /// Validates `action_bytes` length, bumps `state.proposal_count`, writes
    /// a fresh `Proposal` to the proposal account.
    #[instruction]
    pub fn propose(
        #[account(mut)]
        mut state: AccountWithMetadata,
        #[account(init, pda = [literal("pmsig_prop___"), arg("create_key"), arg("index")])]
        mut proposal: AccountWithMetadata,
        #[account(signer)]
        proposer: AccountWithMetadata,
        create_key: [u8; 32],
        index: u64,
        action_bytes: Vec<u8>,
        target_program: [u8; 32],
    ) -> SpelResult {
        Proposal::validate_action_bytes(&action_bytes)
            .map_err(|e| SpelError::custom(e.code(), e.to_string()))?;

        // Decode the current state, assert index matches, bump the count.
        let mut state_body: MultisigState =
            borsh::from_slice(&state.account.data).map_err(|e| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    format!("MultisigState decode failed: {e}"),
                )
            })?;
        if index != state_body.proposal_count {
            return Err(SpelError::custom(
                private_multisig_core::CoreError::ProposalIdMismatch.code(),
                format!(
                    "expected proposal index {} (got {})",
                    state_body.proposal_count, index
                ),
            ));
        }
        state_body.proposal_count = state_body
            .proposal_count
            .checked_add(1)
            .ok_or_else(|| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    "proposal_count overflow".to_string(),
                )
            })?;
        state.account.data = borsh::to_vec(&state_body)
            .map_err(|e| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    format!("MultisigState re-encode failed: {e}"),
                )
            })?
            .try_into()
            .map_err(|_| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    "MultisigState body exceeds account data cap".to_string(),
                )
            })?;

        let _ = create_key;

        let proposal_body = Proposal {
            action_bytes,
            target_program,
            approvals_count: 0,
            executed: false,
        };
        proposal.account.data = borsh::to_vec(&proposal_body)
            .map_err(|e| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    format!("Proposal serialization failed: {e}"),
                )
            })?
            .try_into()
            .map_err(|_| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    "Proposal body exceeds account data cap".to_string(),
                )
            })?;

        Ok(SpelOutput::execute(vec![state, proposal, proposer], vec![]))
    }

    /// Submit an approval receipt.
    ///
    /// **Stub — receipt verification deferred.** PLAN.md step 4 calls for
    /// `risc0_zkvm::guest::env::verify(APPROVE_CIRCUIT_IMAGE_ID, &public_inputs)`
    /// here to add a composition assumption that someone proved the approve
    /// circuit for these public inputs. Implementing that and the
    /// `NullifierEntry` PDA init are the remaining work for this handler.
    #[instruction]
    pub fn approve(
        #[account(mut)]
        state: AccountWithMetadata,
        #[account(mut)]
        proposal: AccountWithMetadata,
        #[account(init, pda = [literal("pmsig_nulli__"), arg("proposal_pda"), arg("nullifier")])]
        nullifier_entry: AccountWithMetadata,
        #[account(signer)]
        submitter: AccountWithMetadata,
        create_key: [u8; 32],
        index: u64,
        proposal_pda: [u8; 32],
        nullifier: [u8; 32],
        receipt: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> SpelResult {
        // TODO(step-4 approve):
        //  1. Recompute proposal_id from chain_id + state_pda + index +
        //     H(action_bytes) + H(target_program) (private_multisig_core::derive_proposal_id).
        //  2. Assert public_inputs.proposal_id matches recompute.
        //  3. Assert public_inputs.members_root matches state.members_root.
        //  4. env::verify(APPROVE_CIRCUIT_IMAGE_ID, &public_inputs).
        //  5. Increment proposal.approvals_count.
        let _ = (create_key, index, proposal_pda, nullifier, receipt, public_inputs);
        Ok(SpelOutput::execute(
            vec![state, proposal, nullifier_entry, submitter],
            vec![],
        ))
    }

    /// Fire the chained call once `approvals_count >= m`.
    ///
    /// Checks `state.m`, `proposal.approvals_count`, `proposal.executed`;
    /// flips `executed = true`; emits a `ChainedCall` to `proposal.target_program`
    /// with `proposal.action_bytes`.
    #[instruction]
    pub fn execute(
        #[account(mut)]
        state: AccountWithMetadata,
        #[account(mut)]
        mut proposal: AccountWithMetadata,
        #[account(mut)]
        vault: AccountWithMetadata,
        #[account(signer)]
        executor: AccountWithMetadata,
        create_key: [u8; 32],
        index: u64,
    ) -> SpelResult {
        let state_body: MultisigState =
            borsh::from_slice(&state.account.data).map_err(|e| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    format!("MultisigState decode failed: {e}"),
                )
            })?;
        let mut proposal_body: Proposal =
            borsh::from_slice(&proposal.account.data).map_err(|e| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    format!("Proposal decode failed: {e}"),
                )
            })?;

        if proposal_body.executed {
            return Err(SpelError::custom(
                private_multisig_core::CoreError::AlreadyExecuted.code(),
                "proposal already executed".to_string(),
            ));
        }
        if proposal_body.approvals_count < u32::from(state_body.m) {
            return Err(SpelError::custom(
                private_multisig_core::CoreError::ThresholdNotMet.code(),
                format!(
                    "{} of {} approvals required (got {})",
                    state_body.m, state_body.n, proposal_body.approvals_count
                ),
            ));
        }

        proposal_body.executed = true;
        proposal.account.data = borsh::to_vec(&proposal_body)
            .map_err(|e| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    format!("Proposal re-encode failed: {e}"),
                )
            })?
            .try_into()
            .map_err(|_| {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    "Proposal body exceeds account data cap".to_string(),
                )
            })?;

        let _ = (create_key, index);

        // ChainedCall construction: emit a call to proposal.target_program
        // with proposal.action_bytes. The runtime delivers it after this
        // tx commits.
        // TODO(step-4): wire ChainedCall::new(...) with the right argument
        // layout for nssa_core 0.2.0-rc3. For now no chained call is emitted
        // so the executor + vault are observed but no funds move.
        Ok(SpelOutput::execute(
            vec![state, proposal, vault, executor],
            vec![],
        ))
    }

    /// Reject a proposal. Post-MVP placeholder per PLAN.md step 4.
    #[instruction]
    pub fn reject(
        #[account(signer)]
        rejector: AccountWithMetadata,
    ) -> SpelResult {
        // TODO(post-MVP): nullifier-domain-separated rejection vote.
        Ok(SpelOutput::execute(vec![rejector], vec![]))
    }
}
