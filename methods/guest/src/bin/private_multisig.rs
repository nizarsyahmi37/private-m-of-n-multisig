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
//! Error codes follow `private_multisig_core::CoreError` (E1xxx-E4xxx).
//! Image-id binding for `approve` is `private_multisig_program::APPROVE_CIRCUIT_IMAGE_ID`.

use spel_framework::prelude::*;

#[lez_program]
mod private_multisig {
    #[allow(unused_imports)]
    use super::*;

    /// Initialize a new multisig instance. Pre-MVP stub.
    #[instruction]
    pub fn create_multisig(
        #[account(init, pda = [literal("pmsig_state__"), arg("create_key")])]
        state: AccountWithMetadata,
        #[account(signer)]
        admin: AccountWithMetadata,
        create_key: [u8; 32],
        members_root: [u8; 32],
        m: u8,
        n: u32,
    ) -> SpelResult {
        let _ = (create_key, members_root, m, n);
        Ok(SpelOutput::execute(vec![state, admin], vec![]))
    }

    /// Open a proposal under an active instance. Pre-MVP stub.
    #[instruction]
    pub fn propose(
        #[account(mut)]
        state: AccountWithMetadata,
        #[account(init, pda = [literal("pmsig_prop___"), arg("create_key"), arg("index")])]
        proposal: AccountWithMetadata,
        #[account(signer)]
        proposer: AccountWithMetadata,
        create_key: [u8; 32],
        index: u64,
        action_bytes: Vec<u8>,
        target_program: [u8; 32],
    ) -> SpelResult {
        let _ = (create_key, index, action_bytes, target_program);
        Ok(SpelOutput::execute(vec![state, proposal, proposer], vec![]))
    }

    /// Submit an approval receipt. Pre-MVP stub.
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
        // Serde's stock impls only cover arrays up to length 32; the
        // canonical 96-byte `ApprovePublicInputs::to_bytes()` bundle is
        // carried as a `Vec<u8>` and length-validated inside the handler.
        public_inputs: Vec<u8>,
    ) -> SpelResult {
        let _ = (create_key, index, proposal_pda, nullifier, receipt, public_inputs);
        Ok(SpelOutput::execute(
            vec![state, proposal, nullifier_entry, submitter],
            vec![],
        ))
    }

    /// Fire the chained call once approvals_count >= m. Pre-MVP stub.
    #[instruction]
    pub fn execute(
        #[account(mut)]
        state: AccountWithMetadata,
        #[account(mut)]
        proposal: AccountWithMetadata,
        #[account(mut)]
        vault: AccountWithMetadata,
        #[account(signer)]
        executor: AccountWithMetadata,
        create_key: [u8; 32],
        index: u64,
    ) -> SpelResult {
        let _ = (create_key, index);
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
        Ok(SpelOutput::execute(vec![rejector], vec![]))
    }
}
