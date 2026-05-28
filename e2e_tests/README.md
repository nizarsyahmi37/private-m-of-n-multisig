# `private_multisig_e2e_tests`

End-to-end tests for the LP-0002 Private M-of-N Multisig (PLAN.md step 7).
The crate ships **two layers** so the cheap, always-runnable crypto path
stays in CI while the heavy full-stack path is opt-in.

## Layer A — pure Risc0 composition (default, runs in CI)

`tests/create_propose_approve_execute.rs`. No LEZ dependencies. Builds a
2-of-3 multisig with the SDK, proves an approval for each member against
the pinned approve circuit, and asserts:

- each receipt verifies against `APPROVE_CIRCUIT_IMAGE_ID`,
- the journal is byte-identical to the SDK's 96-byte public-inputs bundle,
- members share `members_root` + `proposal_id` but emit distinct nullifiers,
- a same-member nullifier replay is rejected (models the `NullifierEntry` PDA).

```bash
# fast, dev-mode proofs
RISC0_DEV_MODE=1 cargo test -p private_multisig_e2e_tests --test create_propose_approve_execute
```

## Layer B — full LEZ sequencer harness (opt-in, dev machine only)

`src/harness.rs` + `tests/lez_full_flow.rs`, gated behind the
`lez-integration` feature. Wraps LEZ's `TestContext` (Bedrock via
testcontainers + in-process sequencer + indexer + wallet), deploys
`private_multisig.bin` + `noop.bin`, and drives the flow against the real
sequencer up to a confirmed architecture boundary:

- `create_multisig → create_vault → propose` execute on-chain; the 2-of-3
  state has the right `members_root` / `m` / `n`,
- the threshold gate holds (`execute` before approvals → `ThresholdNotMet`),
- the SDK→verifier bridge holds (inner receipt verifies against
  `APPROVE_CIRCUIT_IMAGE_ID`, journal == submitted public-inputs),
- **`approve` cannot land on LEZ v0.2.0-rc3** — its `env::verify`
  composition assumption has no resolution channel in the public-tx
  execution path; the test asserts this boundary. See the
  `lez-public-tx-no-assumption-channel` finding and THREAT_MODEL §10 item 9.

### Build-time prerequisite

The `lez-integration` feature transitively pulls `nssa`,
`sequencer_service`, `wallet`, and `integration_tests` from the
Logos Execution Zone. Those crates require **`logos-blockchain-circuits`
v0.4.2** to be present at build time, at either:

- `~/.logos-blockchain-circuits/`, or
- the path in `$LOGOS_BLOCKCHAIN_CIRCUITS`.

Without it the feature **does not compile**. CI therefore never builds
Layer B — only the nightly dev-machine job does.

### Run-time prerequisite

The Docker daemon must be running (LEZ's `TestContext` brings up Bedrock
via testcontainers). On macOS, start Docker Desktop.

> **Status (2026-05-28):** compiled and run against LEZ `v0.2.0-rc3` with
> the circuits prerequisite + Docker. The two originally-inferred API
> shapes (nonce-per-signer in `submit`, tx-inclusion success check) are
> confirmed; one `// INFERRED:` marker remains in `execute` for the
> chained-call account expansion, which is downstream of the `approve`
> composition boundary and not yet exercised end to end. The test passes
> by asserting the reachable boundary (see the Layer B summary above).

### Running it

```bash
# requires the circuits prerequisite above + Docker running
make test-e2e-full
# or directly:
cargo test -p private_multisig_e2e_tests --features lez-integration \
    --test lez_full_flow -- --ignored --nocapture
```

The full-flow test is `#[ignore]` by default because it stands up Docker
containers and proves a receipt.
