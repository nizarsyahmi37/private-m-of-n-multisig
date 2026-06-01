# LP-0002: Private M-of-N Multisig

A private M-of-N multisig primitive for the [Logos Execution Zone](https://github.com/logos-blockchain/logos-execution-zone) (LEZ): members hold shielded accounts, proposals and approvals leave no public trace of who voted, and on-chain state reveals only that a threshold was met — not which members approved.

The threshold proof is a Risc0 zkVM circuit. The on-chain verifier is a SPEL `#[lez_program]` that runs `env::verify(APPROVE_CIRCUIT_IMAGE_ID, public_inputs)` on each `approve` instruction and inits a `NullifierEntry` PDA to prevent double-voting.

## Quickstart

Single command, ~30 s on a warm cache, no on-chain dependencies:

```bash
cargo run --manifest-path e2e_tests/Cargo.toml --bin quickstart
```

This runs the SDK in-process: builds a 2-of-3 multisig, generates three demo members, proves two approvals against the bundled noop ChainedCall target, verifies each receipt against `APPROVE_CIRCUIT_IMAGE_ID`, and demonstrates the double-vote rejection invariant. Output is structured for adopter consumption — see [`e2e_tests/src/bin/quickstart.rs`](./e2e_tests/src/bin/quickstart.rs) for the source.

Flags:

```text
--mode {layer-a|testnet}   layer-a (default) | testnet (deferred — see THREAT_MODEL §10 item 9)
-m, --threshold M          approval threshold (default: 2)
-n, --members N            total member count (default: 3; must be ≥ M)
--action STR               UTF-8 action string committed to the proposal
                           (default: "quickstart-demo-action")
```

Real-proof mode (`RISC0_DEV_MODE=0`, ~3 minutes per receipt) additionally requires `RISC0_USE_DOCKER=1` so the freshly-built image-id matches the canonical pin:

```bash
RISC0_USE_DOCKER=1 RISC0_DEV_MODE=0 \
  cargo run --release --manifest-path e2e_tests/Cargo.toml --bin quickstart
```

The first Docker build pulls `risczero/risc0-guest-builder:r0.1.91.1` and runs the guest cross-compile in-container (~20 minutes cold; cached thereafter).

## Architecture

- **`crypto/`** — Hasher trait, depth-20 Merkle tree, identity commitments, nullifier derivation. No Risc0/LEZ deps.
- **`private_multisig_core/`** — Instruction enums, PDA seeds, state structs (`MultisigState`, `Proposal`, `NullifierEntry`, `Vault`), `ApprovePublicInputs` wire format, deterministic `proposal_id` derivation, error catalog `E1xxx`–`E4xxx`.
- **`methods/`** — Risc0 build wiring. Compiles the two guests (`approve_circuit`, `private_multisig`) and emits the canonical image-ids. Reproducible Docker builds gated by `RISC0_USE_DOCKER=1`; see [`methods/build.rs`](./methods/build.rs).
- **`private_multisig_program/`** — Host-side re-exports of `APPROVE_CIRCUIT_ELF`/`_IMAGE_ID` and `VERIFIER_PROGRAM_ELF`/`_IMAGE_ID`, plus drift sentinels.
- **`sdk/`** — Identity/member lifecycle (`Secret<T>` + Zeroize), `MultisigBuilder`, `ApprovalProver`, resumable `ApprovalSession` (sled-backed; persists across crashes; demotes `Submitted → Proved` on reorg deeper than `DEFAULT_FINALITY_BLOCKS = 32`).
- **`cli/`** — `pmsig` binary, generic IDL-driven (5 of 6 handlers work end-to-end; `approve` is in-process via the SDK pending THREAT_MODEL §10 item 9).
- **`idl-gen/`** — Emits `private_multisig.idl.json` from the SPEL annotations.
- **`e2e_tests/`** — Layer A (pure crypto composition, runs in CI) and Layer B (full LEZ sequencer harness, gated on `--features lez-integration` + local `logos-blockchain-circuits`).

The [Implementation Plan](./PLAN.md) covers each crate's design in detail; the [Threat Model](./THREAT_MODEL.md) lists every threat with its mitigation site and verification hook.

## Status

- **MVP foundation:** complete and CI-green on `main`. See [`PLAN.md` §Verification](./PLAN.md#verification) for the criteria.
- **Reproducibility:** guest builds are deterministic under `RISC0_USE_DOCKER=1`; image-id sentinels pass on both Apple Silicon (Rosetta) and Linux native amd64.
- **Benchmarks:** real-proof baseline is 161.1 s proving + 45.8 ms verify (Apple M1, real-proof mode). See [`BENCHMARKS.md`](./BENCHMARKS.md). The nightly CI workflow re-runs this on hosted runners and uploads a timing artifact.
- **Prize-submission follow-on:** four items remain, all explicitly out-of-scope for the foundation plan — devnet/testnet deployment, recruitment of 5 external instances, recorded demo video, optional Logos Basecamp GUI. See [`PLAN.md` §"Out of scope for this plan"](./PLAN.md#out-of-scope-for-this-plan-explicit).

## Build + test

```bash
# Workspace check (host build, fast)
cargo check --workspace --all-targets
cargo test --workspace --no-fail-fast

# Reproducible Docker build (canonical image-id)
RISC0_USE_DOCKER=1 cargo build -p methods

# SDK with the heavy native prover feature
cargo test -p private_multisig_sdk --features prover

# Layer A end-to-end (in-process, no sequencer)
cargo test --manifest-path e2e_tests/Cargo.toml --test create_propose_approve_execute

# Layer B end-to-end (Docker + LEZ sequencer; see e2e_tests/README.md)
cargo test --manifest-path e2e_tests/Cargo.toml --features lez-integration

# Real-proof benchmark (slow — multi-minute per receipt)
cargo test -p private_multisig_program --test perf_baseline --release -- --ignored --nocapture
```

CI invokes the same commands plus `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, the golden-IDL diff, and (on `main`) the Layer A e2e under `RISC0_DEV_MODE=1`. The nightly workflow re-runs Layer A with `RISC0_DEV_MODE=0` and uploads a `proof_timing.json` artifact.

## License

Dual-licensed under either [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT](http://opensource.org/licenses/MIT) at your option (matches the `license = "MIT OR Apache-2.0"` declaration on every crate's `Cargo.toml`). Top-level `LICENSE-APACHE` and `LICENSE-MIT` files are added as part of the prize-submission follow-on plan.
