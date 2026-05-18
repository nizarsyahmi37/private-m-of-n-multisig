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
//! Image-id binding for `approve` is the pinned `APPROVE_CIRCUIT_IMAGE_ID`
//! included from `../approve_circuit_image_id.rs`. See that file for the
//! rationale on why this is a manual pin rather than a derived constant.

use crypto::{Hasher, Sha256Hasher};
use private_multisig_core::{
    derive_proposal_id, ChainId, MultisigState, Proposal, APPROVE_PUBLIC_INPUTS_LEN,
};
use spel_framework::prelude::*;

include!("../approve_circuit_image_id.rs");

/// Pinned LEZ chain id for this MVP deployment. Enters the `proposal_id`
/// preimage so an approval generated against this deployment cannot replay
/// on any other chain. `0xABCD_EF01` is the canonical devnet value the
/// repo's tests have been using since step 2; lifting it into a named
/// constant here just exposes it to the on-chain code.
///
/// Long-term: this should come from a runtime syscall or live in
/// `MultisigState` so each instance can target a different chain. For the
/// MVP we ship it as a compile-time pin.
const DEPLOYMENT_CHAIN_ID_U64: u64 = 0xABCD_EF01;

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
    /// Verifies the receipt by adding a composition assumption via
    /// `env::verify(APPROVE_CIRCUIT_IMAGE_ID, &public_inputs)` and
    /// cross-checks every public input against on-chain state:
    ///
    /// 1. `public_inputs` is exactly 96 bytes (canonical wire layout).
    /// 2. `public_inputs.members_root == state.members_root` (E2002).
    /// 3. `public_inputs.proposal_id == derive_proposal_id(chain_id,
    ///    state_pda, index, proposal.action_bytes, proposal.target_program)`
    ///    (E2003).
    /// 4. `public_inputs.nullifier == nullifier` (the PDA seed param), so
    ///    the just-init'd `NullifierEntry` PDA is keyed by the actual
    ///    nullifier the prover bound (E3000 surfaces via PDA-already-exists).
    /// 5. `env::verify` registers the composition assumption — without a
    ///    real `approve_circuit` receipt the host's prover cannot discharge
    ///    it and the outer SPEL receipt will not verify.
    ///
    /// `proposal.approvals_count` is bumped only after every check passes.
    #[instruction]
    pub fn approve(
        #[account(mut, pda = [literal("pmsig_state__"), arg("create_key")])]
        state: AccountWithMetadata,
        #[account(mut, pda = [literal("pmsig_prop___"), arg("create_key"), arg("index")])]
        mut proposal: AccountWithMetadata,
        #[account(init, pda = [literal("pmsig_nulli__"), account("proposal"), arg("nullifier")])]
        nullifier_entry: AccountWithMetadata,
        #[account(signer)]
        submitter: AccountWithMetadata,
        create_key: [u8; 32],
        index: u64,
        nullifier: [u8; 32],
        receipt: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> SpelResult {
        // (1) Wire-format sanity. The public-inputs bundle is fixed-size
        // (members_root || proposal_id || nullifier). Anything else is a
        // malformed receipt and rejected with E2000.
        if public_inputs.len() != APPROVE_PUBLIC_INPUTS_LEN {
            return Err(SpelError::custom(
                private_multisig_core::CoreError::InvalidReceipt.code(),
                format!(
                    "public_inputs length {} != canonical {}",
                    public_inputs.len(),
                    APPROVE_PUBLIC_INPUTS_LEN
                ),
            ));
        }
        let mut inputs_members_root = [0u8; 32];
        let mut inputs_proposal_id = [0u8; 32];
        let mut inputs_nullifier = [0u8; 32];
        inputs_members_root.copy_from_slice(&public_inputs[..32]);
        inputs_proposal_id.copy_from_slice(&public_inputs[32..64]);
        inputs_nullifier.copy_from_slice(&public_inputs[64..96]);

        // Decode state + proposal so we can recompute proposal_id and
        // cross-check members_root.
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

        // (2) `members_root` in the receipt must equal the on-chain root.
        // Pinning the root at create-time means a member set cannot rotate
        // mid-flight to redirect approvals. E2002.
        if inputs_members_root != state_body.members_root {
            return Err(SpelError::custom(
                private_multisig_core::CoreError::RootMismatch.code(),
                "public_inputs.members_root != state.members_root".to_string(),
            ));
        }

        // (3) Recompute proposal_id from public bytes the verifier already
        // trusts (state PDA, index, action_bytes, target_program, chain_id)
        // and reject if it doesn't match what the prover committed.
        let state_pda = *state.account_id.value();
        let chain_id = ChainId::from_u64(DEPLOYMENT_CHAIN_ID_U64);
        let recomputed_proposal_id = derive_proposal_id(
            &chain_id,
            &state_pda,
            index,
            &proposal_body.action_bytes,
            &proposal_body.target_program,
        );
        if inputs_proposal_id != recomputed_proposal_id {
            return Err(SpelError::custom(
                private_multisig_core::CoreError::ProposalIdMismatch.code(),
                "public_inputs.proposal_id != derive_proposal_id(state_pda, index, ...)".to_string(),
            ));
        }

        // (4) The nullifier the prover committed must match the seed used
        // to derive the `NullifierEntry` PDA the SPEL macro just init'd.
        // The PDA itself enforces double-vote rejection via init-fails-
        // if-exists; this check just keeps the two values consistent.
        if inputs_nullifier != nullifier {
            return Err(SpelError::custom(
                private_multisig_core::CoreError::InvalidReceipt.code(),
                "public_inputs.nullifier != nullifier seed".to_string(),
            ));
        }

        // (5) Composition assumption: the outer SPEL receipt verifies only
        // if the host can produce a real approve_circuit receipt with this
        // image-id and journal. `env::verify` returns `Result<_, Infallible>`
        // so unwrap is total.
        risc0_zkvm::guest::env::verify(APPROVE_CIRCUIT_IMAGE_ID, public_inputs.as_slice())
            .expect("env::verify returns Infallible");

        // (6) Bump approvals_count and write back. Overflow is impossible
        // in practice (u32 max approvals per proposal) but checked anyway.
        proposal_body.approvals_count = proposal_body.approvals_count.checked_add(1).ok_or_else(
            || {
                SpelError::custom(
                    private_multisig_core::CoreError::InstanceNotActive.code(),
                    "approvals_count overflow".to_string(),
                )
            },
        )?;
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

        // Unused-but-required SPEL plumbing arguments. `receipt` is the
        // raw bytes the host attaches as an assumption to the executor —
        // the guest itself never re-runs the verifier on them, so they're
        // not read here. `create_key` is the PDA seed already validated by
        // the SPEL macro. (The previous `proposal_pda` argument was dropped
        // because it was attacker-controlled and is now replaced by
        // `account("proposal")` in the nullifier_entry PDA seed list.)
        let _ = (create_key, receipt);

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
        #[account(mut, pda = [literal("pmsig_state__"), arg("create_key")])]
        state: AccountWithMetadata,
        #[account(mut, pda = [literal("pmsig_prop___"), arg("create_key"), arg("index")])]
        mut proposal: AccountWithMetadata,
        #[account(mut, pda = [literal("pmsig_vault__"), arg("create_key")])]
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

        // Snapshot the fields we need to construct the ChainedCall *before*
        // moving `proposal_body` into the re-serialize step below.
        let target_program_bytes = proposal_body.target_program;
        let action_bytes = proposal_body.action_bytes.clone();

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

        let _ = index;

        // Convert the 32-byte ProgramId to nssa_core's [u32; 8] layout.
        // Little-endian byte order matches risc0's u32 word convention
        // everywhere else in this codebase (see `image_id_hex` in
        // `private_multisig_program/src/lib.rs`, which round-trips via
        // `to_le_bytes`). Equivalent to `bytemuck::cast` on LE hosts.
        let mut target_program_id: ProgramId = [0u32; 8];
        for (i, word) in target_program_id.iter_mut().enumerate() {
            let off = i * 4;
            *word = u32::from_le_bytes([
                target_program_bytes[off],
                target_program_bytes[off + 1],
                target_program_bytes[off + 2],
                target_program_bytes[off + 3],
            ]);
        }

        // `action_bytes` is the byte payload the multisig members already
        // agreed on. The runtime feeds `instruction_data` to the callee via
        // `env::read::<Vec<u32>>()` and the callee deserializes it with
        // `risc0_zkvm::serde::Deserializer`. The matching encoder is
        // `risc0_zkvm::serde::to_vec`, which packs 4 bytes per u32 LE
        // word — anything else and the callee decodes garbage at the wrong
        // word boundaries. See ChainedCall semantics review CC-2.
        let instruction_data: InstructionData = risc0_zkvm::serde::to_vec(&action_bytes)
            .expect("risc0 serde::to_vec is infallible for Vec<u8>");

        // The vault PDA must be authorized in the callee's view so the
        // callee can decrease its balance. Two coordinated pieces:
        //  1. Flip `is_authorized = true` on the vault clone we pass in
        //     pre_states. nssa_core's `validate_execution` recomputes this
        //     from `pda_seeds` and rejects any mismatch.
        //  2. Provide the vault's `PdaSeed` so the runtime derives the
        //     authorized AccountId via `for_public_pda(self_program_id,
        //     vault_seed)` and matches it against the vault account_id.
        // The vault PDA scheme is `[literal("pmsig_vault__"), arg("create_key")]`
        // which spel_framework::pda::compute_pda combines via SHA-256 of
        // the two 32-byte sub-seeds. We replicate that here.
        let vault_literal_seed = spel_framework::pda::seed_from_str("pmsig_vault__");
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&vault_literal_seed);
        combined[32..].copy_from_slice(&create_key);
        let vault_pda_seed = PdaSeed::new(Sha256Hasher::hash(&combined));
        let mut vault_authorized = vault.clone();
        vault_authorized.is_authorized = true;

        let chained = ChainedCall {
            program_id: target_program_id,
            pre_states: vec![vault_authorized],
            instruction_data,
            pda_seeds: vec![vault_pda_seed],
        };

        Ok(SpelOutput::execute(
            vec![state, proposal, vault, executor],
            vec![chained],
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
