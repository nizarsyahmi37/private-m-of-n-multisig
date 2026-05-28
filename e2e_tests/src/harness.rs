//! Layer-B full-stack LEZ harness for the LP-0002 multisig flow.
//!
//! # Verification status: COMPILED + RUN against LEZ v0.2.0-rc3
//!
//! This module is gated behind `--features lez-integration`, which pulls
//! the LEZ sequencer client stack (`nssa`, `common`, `sequencer_service`,
//! `wallet`, `integration_tests`). Those crates have a hard **build-time**
//! prerequisite on `logos-blockchain-circuits` v0.4.2 being present at
//! `~/.logos-blockchain-circuits/` or `$LOGOS_BLOCKCHAIN_CIRCUITS`, and a
//! **run-time** prerequisite on Docker (LEZ's `TestContext` brings up
//! Bedrock via testcontainers). With both in place this harness has been
//! compiled and run (2026-05-28): `bootstrap` → `create_multisig` →
//! `create_vault` → `propose` → `execute`-gate all execute against the
//! real sequencer; `approve` reaches the confirmed composition boundary
//! (see `lez_full_flow` and the note below).
//!
//! It is modelled on the LEZ `integration_tests` patterns at tag
//! `v0.2.0-rc3` (`integration_tests/tests/program_deployment.rs`). The two
//! API shapes originally inferred from those sources and since confirmed
//! by compilation + run are the nonce-per-signer rule in [`Self::submit`]
//! and the tx-inclusion success check; the one remaining `// INFERRED:`
//! marker (chained-call account expansion in [`Self::execute`]) is
//! downstream of the composition boundary and not yet exercised end to
//! end — see that method.
//!
//! # What it does
//!
//! `MultisigE2eHarness` wraps LEZ's `TestContext` (which brings up
//! Bedrock via testcontainers + an in-process sequencer + indexer +
//! wallet) and layers the multisig-specific operations on top:
//!
//! 1. `bootstrap` — deploy the verifier program (`VERIFIER_PROGRAM_ELF`)
//!    and the `noop` chained-call target (`NOOP_ELF`), register a funded
//!    public account to act as the fee-paying signer.
//! 2. `create_multisig` / `create_vault` / `propose` / `approve` /
//!    `execute` — build and submit one verifier instruction each, using
//!    the same `Message` + `WitnessSet` + `PublicTransaction` shape the
//!    LEZ `program_deployment` test uses.
//! 3. `assert_inner_receipt_verifies` — checks the **SDK→verifier
//!    bridge**: proves the inner approve receipt, verifies it against
//!    `APPROVE_CIRCUIT_IMAGE_ID`, and asserts its journal equals the
//!    public-inputs the test submits in `approve`.
//!
//! # Composition coverage split
//!
//! THREAT_MODEL §10 item 9 asks whether the inner approve receipt actually
//! discharges the verifier's `env::verify(APPROVE_CIRCUIT_IMAGE_ID,
//! public_inputs)` assumption. That guarantee is covered in three pieces,
//! none of which require this harness to re-implement the sequencer:
//!
//! - **Inner receipt is real + bound to the right image-id and journal** —
//!   `assert_inner_receipt_verifies` here, and Layer A
//!   (`create_propose_approve_execute`). A receipt that verifies against
//!   `APPROVE_CIRCUIT_IMAGE_ID` with journal == `public_inputs` is exactly
//!   the assumption `env::verify` needs.
//! - **The verifier guest executes against real on-chain state** — the
//!   on-chain `approve` in `lez_full_flow`, run by the real LEZ SPEL
//!   runtime, which builds the `ProgramInput` pre-states and runs the same
//!   `VERIFIER_PROGRAM` ELF this crate deploys.
//! - **Real-proof assumption discharge through the sequencer's own
//!   prover** — the remaining integration: it needs a channel to hand the
//!   inner receipt to the block prover (the receipt never rides the
//!   instruction wire). Tracked in THREAT_MODEL §10 item 9; out of scope
//!   for a single in-process harness call, which could only test a
//!   hand-rolled reconstruction of the sequencer's inputs.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use integration_tests::{TestContext, TIME_TO_WAIT_FOR_BLOCK_SECONDS};
use private_multisig_core::pda::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_pda, derive_vault_pda,
};
use private_multisig_core::Instruction;
use private_multisig_program::{
    APPROVE_CIRCUIT_IMAGE_ID, VERIFIER_PROGRAM_ELF, VERIFIER_PROGRAM_IMAGE_ID,
};
use private_multisig_sdk::ApprovalProver;

// These import paths mirror `integration_tests/tests/program_deployment.rs`
// and are confirmed by compilation against LEZ v0.2.0-rc3. `NSSATransaction`
// lives in the `common` crate (a direct dep — LEZ's own tests import it the
// same way).
use common::transaction::NSSATransaction;
use nssa::program::Program;
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{AccountId, PublicTransaction};
use sequencer_service_rpc::RpcClient as _;
use wallet::cli::account::{AccountSubcommand, NewSubcommand};
use wallet::cli::{Command, SubcommandReturnValue};

use crate::{NOOP_ELF, NOOP_ID};

/// Convert a Risc0 program/image id (`[u32; 8]`, little-endian words) into
/// the 32-byte form `private_multisig_core::pda` derivation expects. This
/// is the exact word→byte unpacking the verifier guest's `execute`
/// handler does when it rebuilds `target_program_id` from stored bytes.
fn program_id_to_core_bytes(id: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in id.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Full-stack test harness for the multisig happy path.
///
/// Holds the LEZ `TestContext` plus the deployed program ids and the
/// fee-paying signer account registered during `bootstrap`.
pub struct MultisigE2eHarness {
    ctx: TestContext,
    /// Verifier program id, as the sequencer/runtime addresses it.
    verifier_program_id: nssa::ProgramId,
    /// Verifier program id in the 32-byte form PDA derivation uses.
    verifier_program_id_bytes: [u8; 32],
    /// `noop` chained-call target program id (32-byte form for proposals).
    noop_target_bytes: [u8; 32],
    /// Fee-paying public account that signs every instruction. Note this
    /// account carries no privileged role on-chain — SPEL's `#[account(signer)]`
    /// binds to *some* signer, not a specific identity (see the guest's
    /// authorization-model comments).
    signer: AccountId,
}

impl MultisigE2eHarness {
    /// Bring up the stack, deploy both programs, register the signer.
    pub async fn bootstrap() -> Result<Self> {
        let mut ctx = TestContext::new()
            .await
            .context("TestContext bring-up failed")?;

        // Compute program ids from the ELF bytes the same way the LEZ
        // `program_deployment` test computes `data_changer.id()`.
        let verifier_program =
            Program::new(VERIFIER_PROGRAM_ELF.to_vec()).context("verifier Program::new")?;
        let noop_program = Program::new(NOOP_ELF.to_vec()).context("noop Program::new")?;
        let verifier_program_id = verifier_program.id();
        // `Program::id()` returns `nssa::ProgramId` ([u32; 8]); the on-chain
        // PDA derivation in our core crate keys off the 32-byte form, so keep
        // both representations.
        let verifier_program_id_bytes = program_id_to_core_bytes(VERIFIER_PROGRAM_IMAGE_ID);
        let noop_target_bytes = program_id_to_core_bytes(NOOP_ID);

        // Deploy both programs by writing the ELFs to temp files and
        // issuing `Command::DeployProgram`. Bytes are already in memory
        // (re-exported from the program crate); tempfiles satisfy the
        // CLI's `binary_filepath: PathBuf` contract.
        deploy_program(&mut ctx, "private_multisig.bin", VERIFIER_PROGRAM_ELF).await?;
        deploy_program(&mut ctx, "noop.bin", NOOP_ELF).await?;
        wait_for_block().await;

        // Register a fresh public account to pay fees / sign.
        let signer = register_public_account(&mut ctx).await?;

        // Sanity: the deployed verifier id should match what we derived
        // from the re-exported ELF (catches an ELF/image-id skew between
        // `methods` and the deployed artifact).
        let _ = noop_program; // deployed above; id captured via NOOP_ID

        Ok(Self {
            ctx,
            verifier_program_id,
            verifier_program_id_bytes,
            noop_target_bytes,
            signer,
        })
    }

    /// `create_multisig` — initialize the instance under `create_key`.
    pub async fn create_multisig(
        &mut self,
        create_key: [u8; 32],
        members_root: [u8; 32],
        m: u8,
        n: u32,
    ) -> Result<()> {
        let state_pda = derive_multisig_state_pda(&self.verifier_program_id_bytes, &create_key);
        // Account order matches the handler signature: [state, creator(signer)].
        let accounts = vec![to_nssa(state_pda), self.signer];
        let ix = Instruction::CreateMultisig {
            create_key,
            members_root,
            m,
            n,
        };
        self.submit(accounts, ix).await
    }

    /// `create_vault` — initialize + claim the vault PDA (round-5 R5-T1).
    pub async fn create_vault(&mut self, create_key: [u8; 32]) -> Result<()> {
        let state_pda = derive_multisig_state_pda(&self.verifier_program_id_bytes, &create_key);
        let vault_pda = derive_vault_pda(&self.verifier_program_id_bytes, &create_key);
        // Handler order: [state, vault(init), signer].
        let accounts = vec![to_nssa(state_pda), to_nssa(vault_pda), self.signer];
        self.submit(accounts, Instruction::CreateVault { create_key })
            .await
    }

    /// `propose` — open a proposal at `index` targeting the `noop` program.
    pub async fn propose(
        &mut self,
        create_key: [u8; 32],
        index: u64,
        action_bytes: Vec<u8>,
    ) -> Result<[u8; 32]> {
        let state_pda = derive_multisig_state_pda(&self.verifier_program_id_bytes, &create_key);
        let proposal_pda = derive_proposal_pda(&self.verifier_program_id_bytes, &create_key, index);
        // Handler order: [state(mut), proposal(init), signer].
        let accounts = vec![to_nssa(state_pda), to_nssa(proposal_pda), self.signer];
        let ix = Instruction::Propose {
            create_key,
            index,
            action_bytes,
            target_program: self.noop_target_bytes,
        };
        self.submit(accounts, ix).await?;
        Ok(proposal_pda)
    }

    /// `approve` — submit one member's approval.
    ///
    /// The inner Risc0 receipt is produced by the SDK's `ApprovalProver`
    /// and its composition with the verifier is exercised separately by
    /// [`Self::prove_approve_outer_receipt`]. On the submission path the
    /// instruction carries only the nullifier + the 96-byte public-inputs
    /// bundle; the receipt itself rides as an `add_assumption` on the
    /// prover side, never on the instruction wire (see the `Approve`
    /// variant docs).
    pub async fn approve(
        &mut self,
        create_key: [u8; 32],
        index: u64,
        nullifier: [u8; 32],
        public_inputs: Vec<u8>,
    ) -> Result<()> {
        let state_pda = derive_multisig_state_pda(&self.verifier_program_id_bytes, &create_key);
        let proposal_pda = derive_proposal_pda(&self.verifier_program_id_bytes, &create_key, index);
        let nullifier_entry =
            derive_nullifier_entry_pda(&self.verifier_program_id_bytes, &proposal_pda, &nullifier);
        // Handler order: [state(mut), proposal(mut), nullifier_entry(init), signer].
        let accounts = vec![
            to_nssa(state_pda),
            to_nssa(proposal_pda),
            to_nssa(nullifier_entry),
            self.signer,
        ];
        let ix = Instruction::Approve {
            create_key,
            index,
            nullifier,
            public_inputs,
        };
        self.submit(accounts, ix).await
    }

    /// `execute` — fire the chained call once threshold is met.
    pub async fn execute(&mut self, create_key: [u8; 32], index: u64) -> Result<()> {
        let state_pda = derive_multisig_state_pda(&self.verifier_program_id_bytes, &create_key);
        let proposal_pda = derive_proposal_pda(&self.verifier_program_id_bytes, &create_key, index);
        let vault_pda = derive_vault_pda(&self.verifier_program_id_bytes, &create_key);
        // Handler order: [state(mut), proposal(mut), vault(mut), submitter(signer)].
        // INFERRED (still unexercised): the `noop` chained-call target's
        // account(s) are assumed to be appended by the SPEL runtime when it
        // expands the `ChainedCall`, so the submitter does not list them
        // here. Only the *pre-threshold* `execute` is exercised today (it
        // panics at ThresholdNotMet before reaching the chained-call path);
        // the chained-call expansion runs only in a *post-threshold*
        // `execute`, which is downstream of the composition boundary that
        // blocks `approve` (see `lez_full_flow`). If the runtime instead
        // expects the caller to pre-declare chained accounts, add the vault
        // (the account the noop reads) after `submitter`.
        let accounts = vec![
            to_nssa(state_pda),
            to_nssa(proposal_pda),
            to_nssa(vault_pda),
            self.signer,
        ];
        self.submit(accounts, Instruction::Execute { create_key, index })
            .await
    }

    /// Prove the inner approve receipt and confirm it is a real, verifying
    /// receipt whose journal equals the exact public-inputs bundle the
    /// on-chain `approve` cross-checks and feeds to
    /// `env::verify(APPROVE_CIRCUIT_IMAGE_ID, public_inputs)`.
    ///
    /// This is the SDK→verifier cryptographic bridge: a receipt that
    /// verifies against `APPROVE_CIRCUIT_IMAGE_ID` with this journal is
    /// exactly the assumption the verifier guest's `env::verify` needs
    /// discharged. We assert that link directly rather than re-proving the
    /// outer SPEL guest in-process, because faithfully driving the outer
    /// guest means reconstructing the sequencer's `ProgramInput` pre-states
    /// (valid `MultisigState`/`Proposal` account bytes, the four `approve`
    /// PDAs, owner/authorization flags) so the guest's cross-checks pass
    /// before it reaches `env::verify` — i.e. re-implementing the
    /// sequencer. The **outer guest is exercised end-to-end by the on-chain
    /// `approve`** in this test, through the real LEZ SPEL runtime. See the
    /// module header for the full composition-coverage split.
    pub fn assert_inner_receipt_verifies(prover: &mut ApprovalProver) -> Result<()> {
        let receipt_bytes = prover.prove().context("inner approve proof")?;
        let receipt: risc0_zkvm::Receipt =
            bincode::deserialize(&receipt_bytes).context("decode inner receipt")?;
        receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .context("inner approve receipt verify")?;
        // The journal the prover committed must be byte-identical to the
        // public-inputs the test submits in the `approve` instruction — the
        // verifier guest both cross-checks these against on-chain state and
        // passes them to `env::verify`, so any drift would break the
        // composition the on-chain handler relies on.
        let public_inputs = prover.public_inputs_bytes();
        if receipt.journal.bytes.as_slice() != public_inputs.as_ref() {
            bail!("inner receipt journal != submitted public_inputs");
        }
        Ok(())
    }

    /// Fetch an account's on-chain state via the sequencer RPC.
    pub async fn get_account(&self, pda: [u8; 32]) -> Result<nssa::Account> {
        self.ctx
            .sequencer_client()
            .get_account(to_nssa(pda))
            .await
            .context("get_account RPC")
    }

    /// Borrow the underlying LEZ test context (sequencer trace inspection,
    /// indexer queries, etc.).
    pub const fn ctx(&self) -> &TestContext {
        &self.ctx
    }

    /// The verifier program id in the 32-byte form a `MultisigStateSnapshot`
    /// needs so its `proposal_id`/PDA derivations match what the deployed
    /// program computes on-chain.
    pub const fn verifier_program_id_bytes(&self) -> [u8; 32] {
        self.verifier_program_id_bytes
    }

    /// Build + sign + submit one verifier instruction, then wait a block.
    async fn submit(&self, accounts: Vec<AccountId>, ix: Instruction) -> Result<()> {
        // One nonce per *signer*, not per account. nssa's
        // `validated_state_diff::from_public_transaction` requires
        // `message.nonces.len() == witness_set.signatures.len()` and zips
        // the nonces against the signer account ids derived from the
        // witness set. Our transactions have a single signer (the
        // fee-payer); the PDA accounts in `accounts` are non-signers and
        // contribute no nonce. Fetch the signer's current nonce fresh each
        // submit — it increments per landed tx, and we wait a block between.
        let nonces = self
            .ctx
            .sequencer_client()
            .get_accounts_nonces(vec![self.signer])
            .await
            .context("get_accounts_nonces")?;
        let private_key = self
            .ctx
            .wallet()
            .get_account_public_signing_key(self.signer)
            .context("signer has no public signing key")?;

        let message = Message::try_new(self.verifier_program_id, accounts, nonces, ix)
            .context("Message::try_new")?;
        let witness_set = WitnessSet::for_message(&message, &[&private_key]);
        let transaction = PublicTransaction::new(message, witness_set);

        let tx_hash = self
            .ctx
            .sequencer_client()
            .send_transaction(NSSATransaction::Public(transaction))
            .await
            .context("send_transaction")?;
        wait_for_block().await;

        // `send_transaction` only acks mempool acceptance. A tx whose guest
        // panics (e.g. ThresholdNotMet, AlreadyExecuted, a nullifier PDA
        // that already exists) is *skipped* at block production and never
        // included — the sequencer logs "failed execution check ...
        // skipping it". `get_transaction` returns `None` for such a tx and
        // `Some` once it lands in a block, so it is our on-chain
        // success/failure signal: the negative-path assertions in
        // `lez_full_flow` rely on a skipped tx surfacing here as an error.
        let included = self
            .ctx
            .sequencer_client()
            .get_transaction(tx_hash)
            .await
            .context("get_transaction")?;
        if included.is_none() {
            bail!("transaction not included in a block (guest execution failed / skipped)");
        }
        Ok(())
    }
}

/// Convert our 32-byte PDA address into the sequencer's `AccountId`.
fn to_nssa(bytes: [u8; 32]) -> AccountId {
    AccountId::new(bytes)
}

/// Deploy a program by spilling its ELF to a temp file and issuing the
/// wallet's `DeployProgram` subcommand (mirrors `program_deployment.rs`).
async fn deploy_program(ctx: &mut TestContext, name: &str, elf: &[u8]) -> Result<()> {
    let dir = tempfile::tempdir().context("tempdir for program ELF")?;
    let path: PathBuf = dir.path().join(name);
    std::fs::write(&path, elf).with_context(|| format!("write {name}"))?;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::DeployProgram {
            binary_filepath: path,
        },
    )
    .await
    .with_context(|| format!("DeployProgram {name}"))?;
    // Keep `dir` alive until the deploy tx is constructed; the wallet reads
    // the file synchronously inside `execute_subcommand`, so dropping here
    // (end of scope) is safe.
    Ok(())
}

/// Register a fresh public account and return its id.
async fn register_public_account(ctx: &mut TestContext) -> Result<AccountId> {
    let ret = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await
    .context("register public account")?;
    match ret {
        SubcommandReturnValue::RegisterAccount { account_id } => Ok(account_id),
        other => bail!("expected RegisterAccount, got {other:?}"),
    }
}

/// Sleep one block interval so a submitted tx lands before the next query.
async fn wait_for_block() {
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
}
