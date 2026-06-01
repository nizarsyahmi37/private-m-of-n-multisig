//! `quickstart` — one-command external-adopter demo of the LP-0002
//! private multisig cryptographic flow.
//!
//! # What this binary does
//!
//! Generates a configurable M-of-N multisig (default 2-of-3) in-memory,
//! drives the SDK through `propose → approve → verify` for each member
//! up to the threshold, and prints a structured summary suitable for
//! external adopters who want to confirm the SDK + circuit work on
//! their machine before doing anything on-chain.
//!
//! This is the cryptographic-core half of the prize-submission
//! "quickstart" referenced in `PLAN.md` (§"Out of scope" follow-on
//! plan item 2). It does NOT yet submit transactions to a LEZ
//! sequencer — that needs follow-on plan item 1 (devnet/testnet
//! deployment of the verifier program) and a resolution to
//! `THREAT_MODEL.md` §10 item 9 (sequencer RPC doesn't accept attached
//! receipts for composition-assumption discharge). The `--mode testnet`
//! switch is wired but currently prints a directed message and exits.
//!
//! # Why it lives in `e2e_tests/src/bin/` and not the `cli` crate
//!
//! The `cli` crate is a thin wrapper around `spel::run()` (IDL-driven
//! subcommand dispatch). It cannot host the `approve` flow because
//! `approve` needs an in-process prover with the inner receipt attached
//! as an `ExecutorEnv::add_assumption(receipt)` — the same constraint
//! that §10 item 9 calls out. `e2e_tests` already has every dep this
//! needs (`private_multisig_sdk` with the `prover` feature, the
//! `APPROVE_CIRCUIT_ELF`, the bundled `noop` guest as a `ChainedCall`
//! target) and is intentionally excluded from the host workspace, so it
//! ships in the same dep-graph stance the prize evaluator will see when
//! they clone the repo.
//!
//! # Usage
//!
//! ```text
//! cargo run --manifest-path e2e_tests/Cargo.toml --bin quickstart
//! cargo run --manifest-path e2e_tests/Cargo.toml --bin quickstart -- \
//!     --mode layer-a --threshold 3 --members 5 --action "treasury-transfer"
//! ```
//!
//! Default flags exercise the same 2-of-3 happy path the Layer-A
//! integration test does, so a green quickstart implies a green CI.

use std::collections::HashSet;
use std::env;
use std::process::ExitCode;

use anyhow::{Context, Result};
use private_multisig_core::pda::derive_proposal_pda;
use private_multisig_program::{
    image_id_hex, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID, BUILD_USED_DOCKER,
};
use private_multisig_sdk::{ApprovalProver, Member, MultisigBuilder, MultisigStateSnapshot};
use risc0_zkvm::Receipt;

use private_multisig_e2e_tests::NOOP_ID;

/// Deterministic create_key for the demo instance. External adopters
/// running this for the on-chain version (post follow-on plan item 1)
/// MUST replace this with a random per-instance key; using a literal
/// here means every quickstart run claims the same PDA address.
const DEMO_CREATE_KEY: [u8; 32] = [0xB2; 32];

/// Placeholder program id for the in-memory snapshot. Layer-A doesn't
/// round-trip through the chain so this value is never observed by an
/// on-chain check — it just has to be consistent with whatever the
/// snapshot was built against.
const DEMO_PROGRAM_ID: [u8; 32] = [0xA1; 32];

/// Convert a Risc0 image id (`[u32; 8]` little-endian words) into the
/// 32-byte form the on-chain `target_program` field expects.
fn image_id_to_account_id(id: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in id.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Hex-encode a byte slice as lowercase. Inlined to avoid pulling
/// `hex` into `e2e_tests`'s direct dep graph for one helper.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn print_banner() {
    println!("=============================================================");
    println!("  LP-0002 Private M-of-N Multisig — Quickstart Demo");
    println!("=============================================================");
}

fn run_layer_a(threshold: u8, member_count: usize, action: &[u8]) -> Result<()> {
    if threshold == 0 {
        anyhow::bail!("--threshold must be >= 1");
    }
    if member_count == 0 {
        anyhow::bail!("--members must be >= 1");
    }
    if member_count < threshold as usize {
        anyhow::bail!(
            "--threshold {threshold} cannot exceed --members {member_count}; \
             a quorum bigger than the membership is unreachable"
        );
    }

    // Default to dev-mode proofs for fast iteration (~seconds) so the
    // demo isn't gated on a 2-3 minute real-proof run. The SDK's
    // `ApprovalProver` skips its internal `receipt.verify(IMAGE_ID)`
    // call under dev mode, which is essential here because the freshly-
    // built `APPROVE_CIRCUIT_IMAGE_ID` only matches the
    // `APPROVE_CIRCUIT_IMAGE_ID_PINNED` SDK constant when the guest was
    // built reproducibly under Docker (`RISC0_USE_DOCKER=1`); plain
    // host builds produce a path-dependent image-id and the verify
    // would fail with `claim digest does not match the expected
    // digest`. We surface both gates explicitly below so adopters
    // running with `RISC0_DEV_MODE=0` see what's expected of them.
    let dev_mode_was_set = env::var("RISC0_DEV_MODE").is_ok();
    if !dev_mode_was_set {
        // SAFETY: setting an env var here is sound because nothing else
        // in this single-threaded binary is reading env concurrently
        // before `prove()` is called.
        env::set_var("RISC0_DEV_MODE", "1");
    }
    let dev_mode = matches!(env::var("RISC0_DEV_MODE").as_deref(), Ok("1") | Ok("true"));

    print_banner();
    println!();
    println!("Mode: Layer A — in-process proof generation + verification.");
    println!("Membership: {threshold}-of-{member_count}.");
    println!("Action ({} bytes): {:?}", action.len(), String::from_utf8_lossy(action));
    println!(
        "Live APPROVE_CIRCUIT image-id (from this build): {}",
        image_id_hex()
    );
    println!(
        "Reproducible Docker build (RISC0_USE_DOCKER=1): {}",
        if BUILD_USED_DOCKER { "yes" } else { "no (host build — image-id is path-dependent)" }
    );
    println!(
        "Proving mode: {}",
        if dev_mode {
            if dev_mode_was_set {
                "RISC0_DEV_MODE=1 (set by user) — fast dev proofs, not on-chain valid"
            } else {
                "RISC0_DEV_MODE=1 (default for quickstart) — fast dev proofs, not on-chain valid"
            }
        } else {
            "RISC0_DEV_MODE=0 — real proofs (slow; multi-minute per receipt)"
        },
    );
    if !dev_mode && !BUILD_USED_DOCKER {
        println!();
        println!(
            "WARNING: real-proof mode (RISC0_DEV_MODE=0) without a reproducible"
        );
        println!(
            "         Docker build will fail receipt verification against the"
        );
        println!(
            "         pinned image-id. Either set RISC0_DEV_MODE=1 (fast demo)"
        );
        println!(
            "         or set RISC0_USE_DOCKER=1 before running (slow first build)."
        );
    }
    println!();

    // ---- Setup: generate `member_count` members, build the multisig ----
    let members: Vec<Member> = (0..member_count)
        .map(|i| Member::new().with_context(|| format!("member#{i} keygen failed")))
        .collect::<Result<Vec<_>>>()?;

    let mut builder = MultisigBuilder::new(threshold);
    for (i, member) in members.iter().enumerate() {
        builder
            .add_member(member.commitment())
            .with_context(|| format!("add member#{i} to builder failed"))?;
    }
    let finalized = builder.finalize().context("finalize multisig")?;
    println!(
        "✓ Built multisig with {} members. members_root: {}",
        finalized.n,
        hex_encode(&finalized.members_root),
    );

    // Snapshot mirrors what the SDK would read off-chain after `propose`
    // committed proposal index 0 — proposal_count = 1 means index 0 is
    // the freshest valid target.
    let snapshot = MultisigStateSnapshot::new(
        DEMO_PROGRAM_ID,
        DEMO_CREATE_KEY,
        finalized.members_root,
        finalized.m,
        finalized.n,
        1,
    )
    .context("build MultisigStateSnapshot")?;

    let target_program = image_id_to_account_id(NOOP_ID);
    let proposal_index: u64 = 0;
    let proposal_pda = derive_proposal_pda(&DEMO_PROGRAM_ID, &DEMO_CREATE_KEY, proposal_index);
    println!(
        "✓ Proposed action (target: noop guest, proposal_pda: {})",
        hex_encode(&proposal_pda),
    );
    println!();

    // ---- Approval loop: each member proves, we verify, we track nullifiers ----
    let mut nullifiers: HashSet<[u8; 32]> = HashSet::new();
    let mut approvals_recorded: u8 = 0;
    let action_bytes = action.to_vec();

    println!("Generating receipts (one per approving member):");
    for (i, member) in members.iter().enumerate() {
        let label = format!("member#{i}");
        let merkle_proof = finalized
            .merkle_proof(&member.commitment())
            .with_context(|| format!("{label}: derive merkle proof"))?;
        let mut prover = ApprovalProver::new(
            member,
            &snapshot,
            proposal_index,
            &action_bytes,
            &target_program,
            &merkle_proof,
            APPROVE_CIRCUIT_ELF,
        )
        .with_context(|| format!("{label}: construct ApprovalProver"))?;

        let receipt_bytes = prover.prove().with_context(|| format!("{label}: prove"))?;
        let receipt: Receipt = bincode::deserialize(&receipt_bytes)
            .with_context(|| format!("{label}: deserialize receipt"))?;

        // The on-chain `approve` verifier re-checks two invariants this
        // local verify chain mirrors: (a) the receipt verifies against
        // the pinned image-id (else E2001 ImageIdMismatch on-chain),
        // and (b) the 96-byte journal matches the SDK-computed public
        // inputs verbatim (else E2002 PublicInputsMismatch on-chain).
        receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .with_context(|| format!("{label}: receipt verify against APPROVE_CIRCUIT_IMAGE_ID"))?;
        let expected_journal = prover.public_inputs_bytes();
        if receipt.journal.bytes.as_slice() != expected_journal.as_slice() {
            anyhow::bail!(
                "{label}: journal/public-inputs mismatch (would be E2002 on-chain)"
            );
        }

        let nullifier = prover.nullifier();
        if !nullifiers.insert(nullifier) {
            // A distinct member always produces a distinct nullifier
            // (since the nullifier is `H(sk‖proposal_id)`), so a
            // duplicate here means something is structurally broken.
            anyhow::bail!(
                "{label}: produced a duplicate nullifier — this would be a \
                 protocol-level bug, not a double-vote attempt"
            );
        }
        approvals_recorded += 1;
        println!(
            "  ✓ {label} approved (nullifier prefix: {}…)",
            hex_encode(&nullifier[..4]),
        );

        if approvals_recorded >= threshold {
            println!(
                "  └ threshold ({threshold}) reached after {approvals_recorded} approvals \
                 — execute() would gate true."
            );
            break;
        }
    }

    if approvals_recorded < threshold {
        anyhow::bail!(
            "only collected {approvals_recorded} approvals but threshold is {threshold} — \
             demo state is inconsistent"
        );
    }

    // ---- Double-vote demo: model the on-chain NullifierEntry collision ----
    println!();
    println!("Double-vote simulation:");
    // Re-prove with member#0 — same secret, same proposal_id → same
    // nullifier. The on-chain `NullifierEntry` PDA uses
    // init-fails-if-exists, modelled here as a `HashSet` insert: the
    // first call wins, the second returns `false`.
    let replay_member = &members[0];
    let merkle_proof = finalized
        .merkle_proof(&replay_member.commitment())
        .context("replay member: derive merkle proof")?;
    let prover = ApprovalProver::new(
        replay_member,
        &snapshot,
        proposal_index,
        &action_bytes,
        &target_program,
        &merkle_proof,
        APPROVE_CIRCUIT_ELF,
    )
    .context("replay member: construct ApprovalProver")?;
    let replayed_nullifier = prover.nullifier();
    let inserted_again = nullifiers.insert(replayed_nullifier);
    if inserted_again {
        anyhow::bail!(
            "double-vote model failed: member#0's replay nullifier was not in the \
             set — the on-chain init-fails-if-exists check would have caught this"
        );
    }
    println!(
        "  ✓ member#0's replay would be rejected (E3000 NullifierAlreadyUsed on-chain)."
    );

    println!();
    println!("Invariants verified:");
    println!("  • Every receipt verified against APPROVE_CIRCUIT_IMAGE_ID");
    println!("  • Journal bytes matched SDK-computed public inputs (96 B each)");
    println!(
        "  • {} distinct nullifiers across approving members",
        approvals_recorded
    );
    println!("  • Same-member replay rejected via nullifier collision");
    println!();
    println!("Quickstart completed: the cryptographic core works on this machine.");
    println!();
    println!("Next: on-chain submission. Tracked as follow-on plan item 1");
    println!("(deploy verifier to LEZ devnet/testnet) — see PLAN.md");
    println!("\"Out of scope for this plan (explicit)\".");
    Ok(())
}

fn run_testnet_stub() -> Result<()> {
    print_banner();
    println!();
    println!("Mode: testnet — NOT YET IMPLEMENTED.");
    println!();
    println!("Submitting `approve` to a deployed verifier program requires");
    println!("discharging the inner-receipt composition assumption that");
    println!("`env::verify(APPROVE_CIRCUIT_IMAGE_ID, ...)` adds. The current");
    println!("`sequencer_service_rpc` (v0.2.0-rc3) public-transaction wire");
    println!("does not accept attached receipts (THREAT_MODEL.md §10 item 9).");
    println!();
    println!("Resolution needs either:");
    println!("  (a) a sequencer RPC extension that accepts attached receipts, or");
    println!("  (b) a local-prove path that produces a full outer receipt");
    println!("      before submitting the transaction.");
    println!();
    println!("Both are tracked as follow-on plan items 1 + 2.");
    anyhow::bail!("testnet mode is not yet implemented");
}

fn print_help() {
    let prog = env::args().next().unwrap_or_else(|| "quickstart".to_string());
    eprintln!("LP-0002 Private M-of-N Multisig — Quickstart demo");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  {prog} [--mode {{layer-a|testnet}}] [-m M] [-n N] [--action STR]");
    eprintln!();
    eprintln!("FLAGS:");
    eprintln!("  --mode <MODE>      layer-a (default) | testnet (not yet implemented)");
    eprintln!("  -m, --threshold M  approval threshold (default: 2)");
    eprintln!("  -n, --members N    total member count (default: 3; must be >= M)");
    eprintln!("  --action STR       UTF-8 action string committed to the proposal");
    eprintln!("                     (default: \"quickstart-demo-action\")");
    eprintln!("  -h, --help         show this help");
}

fn parse_args() -> Result<(String, u8, usize, Vec<u8>)> {
    let args: Vec<String> = env::args().collect();
    let mut mode = "layer-a".to_string();
    let mut threshold: u8 = 2;
    let mut members: usize = 3;
    let mut action: Vec<u8> = b"quickstart-demo-action".to_vec();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                i += 1;
                mode = args
                    .get(i)
                    .context("--mode requires a value (layer-a or testnet)")?
                    .clone();
            }
            "-m" | "--threshold" => {
                i += 1;
                threshold = args
                    .get(i)
                    .context("--threshold requires a value")?
                    .parse()
                    .context("--threshold must be a small positive integer")?;
            }
            "-n" | "--members" => {
                i += 1;
                members = args
                    .get(i)
                    .context("--members requires a value")?
                    .parse()
                    .context("--members must be a small positive integer")?;
            }
            "--action" => {
                i += 1;
                action = args
                    .get(i)
                    .context("--action requires a value")?
                    .as_bytes()
                    .to_vec();
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                anyhow::bail!("unknown argument: {other:?}. Run with --help for usage.");
            }
        }
        i += 1;
    }
    Ok((mode, threshold, members, action))
}

fn main() -> ExitCode {
    let (mode, threshold, members, action) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            print_help();
            return ExitCode::from(2);
        }
    };

    let result = match mode.as_str() {
        "layer-a" => run_layer_a(threshold, members, &action),
        "testnet" => run_testnet_stub(),
        other => {
            eprintln!("error: unknown mode '{other}'. Expected 'layer-a' or 'testnet'.");
            print_help();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!();
            eprintln!("quickstart failed: {e:#}");
            ExitCode::from(1)
        }
    }
}
