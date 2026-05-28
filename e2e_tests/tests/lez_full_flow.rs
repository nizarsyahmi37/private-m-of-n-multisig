//! Layer-B full-stack flow against a local LEZ sequencer, asserting the
//! reachable boundary on LEZ `v0.2.0-rc3`.
//!
//! # What this validates
//!
//! Compiles only under `--features lez-integration` (needs
//! `logos-blockchain-circuits` v0.4.2 on disk + Docker — see
//! `e2e_tests/README.md`). It drives the multisig through the real
//! sequencer and asserts everything that *can* execute on this LEZ
//! version, stopping at a confirmed architecture boundary:
//!
//! - **create_multisig / create_vault / propose execute on-chain.** The
//!   2-of-3 instance's state has the correct `members_root`, `m = 2`,
//!   `n = 3` (PLAN.md §4.1).
//! - **The threshold gate works.** `execute` before any approval is
//!   rejected by the sequencer (`ThresholdNotMet`, error 4000) — PLAN.md
//!   §4.2a.
//! - **The SDK→verifier bridge holds.** The inner approve receipt proves,
//!   verifies against `APPROVE_CIRCUIT_IMAGE_ID`, and its journal equals
//!   the `public_inputs` we submit.
//! - **`approve` cannot land on LEZ v0.2.0-rc3 — and we assert that.** The
//!   verifier guest calls `env::verify(APPROVE_CIRCUIT_IMAGE_ID, ...)`,
//!   which raises a `sys_verify_integrity` composition assumption. LEZ's
//!   public-transaction execution path (`Program::execute` →
//!   `default_executor().execute()`) provides **no channel** to supply the
//!   inner receipt that would discharge it, so the sequencer rejects the
//!   tx ("no receipt found to resolve assumption ... skipping it"). The
//!   only `add_assumption` in LEZ is on the privacy-preserving tx path, not
//!   for public programs. This is THREAT_MODEL §10 item 9, empirically
//!   reproduced against the real stack — see `src/harness.rs` and the
//!   `lez-public-tx-no-assumption-channel` project note.
//!
//! The downstream happy-path steps (second approval, post-threshold
//! `execute`, double-execute rejection, nullifier replay, chained-call
//! observability) are unreachable until that boundary is resolved (LEZ
//! gains a public-tx assumption channel, or `approve` is routed through a
//! composition-capable tx path). They are documented at the end of this
//! file as the target flow.
//!
//! Run it with `make test-e2e-full` (or directly:
//! `cargo test -p private_multisig_e2e_tests --features lez-integration
//! --test lez_full_flow -- --ignored --nocapture`). It's `#[ignore]` by
//! default because it stands up Docker containers and proves a real
//! receipt — far too heavy for the inline `cargo test` path.

#![cfg(feature = "lez-integration")]

use anyhow::Result;
use private_multisig_e2e_tests::harness::MultisigE2eHarness;
use private_multisig_program::APPROVE_CIRCUIT_ELF;
use private_multisig_sdk::{ApprovalProver, Member, MultisigBuilder, MultisigStateSnapshot};

/// Deterministic create_key for the instance under test.
const CREATE_KEY: [u8; 32] = [0xB2; 32];

#[tokio::test(flavor = "multi_thread")]
#[ignore = "stands up Docker + proves a real receipt; run via `make test-e2e-full`"]
async fn layer_b_flow_to_composition_boundary() -> Result<()> {
    // ---- Members + 2-of-3 multisig (SDK side) ----
    let alice = Member::new()?;
    let bob = Member::new()?;
    let carol = Member::new()?;

    let mut builder = MultisigBuilder::new(2);
    builder.add_member(alice.commitment())?;
    builder.add_member(bob.commitment())?;
    builder.add_member(carol.commitment())?;
    let finalized = builder.finalize()?;

    // ---- Stand up the stack + deploy programs ----
    let mut h = MultisigE2eHarness::bootstrap().await?;
    let program_id = h.verifier_program_id_bytes();

    // ---- create_multisig + create_vault ----
    h.create_multisig(CREATE_KEY, finalized.members_root, finalized.m, finalized.n)
        .await?;
    h.create_vault(CREATE_KEY).await?;

    // §4.1 — on-chain state reflects the member set + threshold.
    let state_pda = private_multisig_core::pda::derive_multisig_state_pda(&program_id, &CREATE_KEY);
    let state_account = h.get_account(state_pda).await?;
    let state: private_multisig_core::MultisigState =
        borsh::from_slice(state_account.data.as_ref())?;
    assert_eq!(state.members_root, finalized.members_root, "members_root");
    assert_eq!(state.m, 2, "threshold m");
    assert_eq!(state.n, 3, "member count n");

    // ---- propose a no-op chained call to the `noop` target ----
    let action_bytes = b"layer-b-noop-action".to_vec();
    let index: u64 = 0;
    h.propose(CREATE_KEY, index, action_bytes.clone()).await?;

    // Snapshot mirrors the just-proposed state so the SDK derives the same
    // proposal_id the chain stored. proposal_count = 1 after one propose.
    let snapshot = MultisigStateSnapshot::new(
        program_id,
        CREATE_KEY,
        finalized.members_root,
        finalized.m,
        finalized.n,
        1,
    )?;
    // The `noop` target id. Matches `target_program` the harness stores in
    // `propose` (both unpack `NOOP_ID`).
    let noop_target = target_account_id();
    let target_program = snapshot
        .derive_proposal_id(index, &action_bytes, &noop_target)
        .to_owned();
    let _ = target_program; // proposal_id derivation cross-check; value unused

    // §4.2a — `execute` must fail before threshold is met. This is a
    // genuine on-chain rejection (the guest panics with ThresholdNotMet and
    // the sequencer skips the tx), surfaced by the harness as an error.
    let early = h.execute(CREATE_KEY, index).await;
    assert!(
        early.is_err(),
        "execute before 2 approvals must fail (ThresholdNotMet)"
    );

    // ---- Prove one member's approval (SDK→verifier bridge) ----
    // Proving the inner receipt and verifying it against
    // `APPROVE_CIRCUIT_IMAGE_ID` (journal == submitted public_inputs) is the
    // assumption the on-chain verifier's `env::verify` would need to
    // discharge. `assert_inner_receipt_verifies` checks exactly that.
    let proof = finalized.merkle_proof(&alice.commitment())?;
    let mut prover = ApprovalProver::new(
        &alice,
        &snapshot,
        index,
        &action_bytes,
        &noop_target,
        &proof,
        APPROVE_CIRCUIT_ELF,
    )?;
    MultisigE2eHarness::assert_inner_receipt_verifies(&mut prover)?;
    let nullifier = prover.nullifier();
    let public_inputs = prover.public_inputs_bytes().to_vec();

    // ---- Composition boundary: `approve` cannot land on LEZ v0.2.0-rc3 ----
    // The verifier guest calls `env::verify(APPROVE_CIRCUIT_IMAGE_ID, ...)`,
    // which raises a `sys_verify_integrity` assumption. LEZ's public-tx
    // execution path has no channel to supply the inner receipt, so the
    // sequencer logs "no receipt found to resolve assumption" and skips the
    // tx — which the harness surfaces as an error. We assert that boundary
    // explicitly so this test stays honest (and flips loudly if a future
    // LEZ version starts resolving the assumption). THREAT_MODEL §10 item 9.
    let approve = h.approve(CREATE_KEY, index, nullifier, public_inputs).await;
    assert!(
        approve.is_err(),
        "approve is expected to be rejected on LEZ v0.2.0-rc3: the public-tx \
         execution path cannot resolve the env::verify composition assumption \
         (THREAT_MODEL §10 item 9). If this now succeeds, LEZ gained a public-tx \
         assumption channel — extend this test through the full happy path."
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Target flow (blocked on the composition boundary above)
//
// Once `approve` can land — LEZ exposes a public-tx assumption channel, or
// `approve` is routed through a composition-capable tx path — this test
// should be extended to the full PLAN.md §4 happy path:
//
//   * a second distinct approval, then `execute` succeeds (§4.2b),
//   * a second `execute` fails with AlreadyExecuted (§4.2c),
//   * a third approval reusing a nullifier is rejected because the
//     `NullifierEntry` PDA already exists (§4.3),
//   * the chained call to `noop` is observable: the proposal is marked
//     `executed` (§4.4).
//
// The model-level coverage of these (HashSet nullifier model, threshold
// arithmetic, etc.) already lives in Layer A
// (`tests/create_propose_approve_execute.rs`) and the program crate's
// blue/red-team tests.
// ---------------------------------------------------------------------------

/// The `noop` target program id in the 32-byte form `proposal_id`
/// derivation expects, unpacked from the re-exported `NOOP_ID` image
/// words. Matches the `target_program` bytes the harness stores in
/// `propose` (`program_id_to_core_bytes(NOOP_ID)`).
fn target_account_id() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in private_multisig_e2e_tests::NOOP_ID.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}
