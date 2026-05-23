# LP-0002 Private M-of-N Multisig — MVP Foundation Plan

## Context

The repository currently contains only `TASK.md` (the LP-0002 prize spec) and a stub `README.md`. LP-0002 asks for a private multisig primitive for LEZ: members hold shielded accounts, approvals carry no on-chain identity, and the verifier confirms only that threshold M was reached. The public lez-multisig PoC is architecturally incompatible because LEZ shielded accounts are owned by the privacy protocol and increment a nonce on every use, while lez-multisig requires fresh zero-nonce keypairs claimed by the multisig program.

This plan establishes the **MVP foundation**: workspace layout, cryptographic core, LEZ verifier program, a Risc0 approval circuit, and a local end-to-end test. SDK polish, Basecamp GUI, testnet deployment with five external instances, and the recorded demo are deliberately deferred to follow-on planning passes — they depend on the foundation existing and on LEZ testnet specifics that aren't worth resolving until the core works locally.

**Threshold scheme (leaning Semaphore-style, decision deferred pending implementation spike):** a Merkle set of identity commitments + per-proposal nullifier, proven inside a Risc0 guest. No trusted setup, one proof per approval, composes naturally with LEZ's existing commitment/nullifier model for shielded accounts. The full trade-off table against FROST and MACI-hybrid lives in `THREAT_MODEL.md`; the final decision is made during step 1 of the implementation spike, after laptop proving-time and on-chain receipt-verification CU cost are measured.

## Architecture at a glance

```mermaid
flowchart TB
  subgraph client[Client SDK / CLI]
    KG[identity_commitment = H(sk, salt)]
    PROOF[Risc0 guest: approve_circuit\nproves Merkle path + nullifier]
  end

  subgraph chain[LEZ Verifier Program private_multisig_program]
    CM[create_multisig:\nstores members_root, M, N]
    PR[propose:\nstores action_bytes, approvals=0,\nnullifier_set=empty]
    AP[approve:\nverifies Risc0 receipt,\nchecks root match, inserts nullifier,\napprovals += 1]
    EX[execute:\nrequires approvals >= M,\nemits ChainedCall to target]
  end

  subgraph accts[On-chain accounts PDAs]
    MS[(MultisigState\nseed: pmsig_state__ XOR key)]
    PP[(Proposal\nseed: pmsig_prop___ XOR key XOR idx\nholds nullifier_set)]
    VT[(Vault\nseed: pmsig_vault__ XOR key)]
  end

  KG --> PROOF
  PROOF -- "receipt + public inputs\n(root, proposal_id, nullifier)" --> AP
  CM --> MS
  PR --> PP
  AP --> PP
  EX --> PP
  EX --> VT
```

Public inputs committed by the approve circuit: `members_root`, `proposal_id`, `nullifier`. Private witness: member secret `sk`, salt, Merkle path + indices. The on-chain `approve` handler verifies the Risc0 receipt against a pinned image ID, asserts the root matches the multisig's stored root and the proposal_id matches, then attempts to init a per-`(proposal, nullifier)` PDA (init-fails-if-exists is the double-vote check) and increments approvals.

## Threat model

Full red/blue team analysis lives in [`THREAT_MODEL.md`](./THREAT_MODEL.md). Headline threats this design defends against: (a) **de-anonymization** of approvers by chain observers, other members, or the relayer pool; (b) **replay** across proposals, instances, and chains; (c) **double-vote** by a single member; (d) **secret leakage** through SDK logs, swap, or `Debug` formatters. Mitigations are tracked T1.x–T7.x in the companion doc and mapped to concrete code locations in the blue-team control matrix.

## Workspace layout

Mirror lez-multisig's crate split so SPEL/IDL tooling and the LEZ CLI work out of the box. New top-level layout under `/home/user/repo`:

```
Cargo.toml                    # workspace
Makefile                      # build / idl / test targets, mirrors SPEL convention
README.md                     # replace stub with foundation docs
TASK.md                       # unchanged
crypto/                       # new: scheme-agnostic crypto core (no risc0, no LEZ)
  Cargo.toml
  src/
    lib.rs
    identity.rs               # IdentityCommitment, secret/salt types
    merkle.rs                 # fixed-depth Poseidon Merkle tree + path
    nullifier.rs              # nullifier = H(sk, proposal_id)
    hash.rs                   # Poseidon wrapper, deterministic
  tests/roundtrip.rs
private_multisig_core/        # shared types: instruction enums, account structs, PDA seeds
  Cargo.toml
  src/
    lib.rs
    instructions.rs           # CreateMultisig, Propose, Approve, Execute
    state.rs                  # MultisigState, Proposal, Vault
    pda.rs                    # seed constants + derivation helpers
    proof.rs                  # ApprovePublicInputs serialization
methods/                      # risc0 guest build wiring (mirrors lez-multisig)
  Cargo.toml
  build.rs
  guest/
    Cargo.toml
    src/bin/private_multisig.rs   # program guest (SPEL #[lez_program])
    src/bin/approve_circuit.rs    # approval ZK circuit guest
private_multisig_program/     # host-side program crate, re-exports image IDs
  Cargo.toml
  src/lib.rs
sdk/                          # client library: identity, witness, proving, tx building
  Cargo.toml
  src/
    lib.rs
    member.rs                 # Member keypair + commitment
    multisig.rs               # builders for create/propose/approve/execute
    prover.rs                 # wraps risc0 prove() for approve_circuit
    error.rs
cli/                          # thin IDL-driven CLI wrapping lez-cli (mirrors lez-multisig)
  Cargo.toml
  src/main.rs
idl-gen/                      # host binary that emits private_multisig.idl.json
  Cargo.toml
  src/main.rs
e2e_tests/                    # integration tests against a local sequencer
  Cargo.toml
  tests/create_propose_approve_execute.rs
  scripts/run_local_sequencer.sh
```

The naming `private_multisig_*` keeps it cleanly distinct from `multisig_*` in lez-multisig, allowing both to coexist in tooling.

## Implementation order

Each step is independently testable. Do them in order — later steps depend on earlier types.

1. **Workspace + crypto core (`crypto/`).** Cargo workspace, Poseidon hash (`risc0-zkvm`-compatible, prefer `risc0-zkvm` companion or `ark-bn254` Poseidon if available in lez-multisig's deps; otherwise use SHA-256 as a placeholder behind a `Hasher` trait and swap later). Define `IdentityCommitment = H(sk ‖ salt)`, fixed-depth (depth 20 → 1M members) `MerkleTree` with `insert`, `root`, `path(index)`, and `verify(root, leaf, path, index)`. Define `nullifier(sk, proposal_id) = H(sk ‖ proposal_id)`. Unit tests for round-trip insertion, path verification, nullifier determinism.

2. **Shared types (`private_multisig_core/`).** Mirror lez-multisig's split. PDA seeds: `b"pmsig_state__"`, `b"pmsig_prop___"`, `b"pmsig_vault__"`, plus `b"pmsig_nulli__"` for the `NullifierEntry` PDA (each is 13 bytes, padded to 32 by `pad_seed_32` to match SPEL's `seed_from_str`). Implementation took the SHA-256-of-concat path (`AccountId = SHA256(program_id ‖ combined_seeds)`), confirmed against `spel_framework::pda::compute_pda` by the parity tests in `private_multisig_program/tests/{all_pda_parity,vault_pda_seed_parity}.rs`. Instructions:
   - `CreateMultisig { create_key, members_root, m: u8, n: u32 }`
   - `Propose { create_key, index: u64, action_bytes: Vec<u8>, target_program: AccountId }`
   - `Approve { create_key, index: u64, receipt: Vec<u8>, public_inputs: ApprovePublicInputs }`
   - `Execute { create_key, index: u64 }`
   State structs:
   - `MultisigState { members_root: [u8;32], m: u8, n: u32, proposal_count: u64 }`
   - `Proposal { action_bytes, target_program, approvals_count: u32, executed: bool }` — nullifiers are NOT stored inline; each accepted approval inits a separate `NullifierEntry` PDA seeded by `(proposal_pda, nullifier)` so the proposal account stays fixed-size and double-vote prevention falls out of init-fails-if-exists semantics.
   - `NullifierEntry` — empty data; existence at PDA `(proposal_pda, nullifier)` is the bit.
   - `ApprovePublicInputs { members_root: [u8;32], proposal_id: [u8;32], nullifier: [u8;32] }`
     Serialization is fixed-layout `[members_root: 32 || proposal_id: 32 || nullifier: 32] = 96 bytes`, big-endian, no length prefix, no version byte. The guest commits these 96 bytes to the journal verbatim; the verifier re-reads them in the same layout.
   `proposal_id` is deterministic and computed identically by client, circuit, and verifier so it isn't trusted input:
   ```
   proposal_id = H(chain_id ‖ multisig_state_pda ‖ index ‖ H(action_bytes) ‖ H(target_program))
   ```
   `chain_id` blocks cross-chain replay; `H(action_bytes)` and `H(target_program)` bind the approval to the specific action being approved, so an approval cannot carry over if either is ever mutated post-`propose`.
   `action_bytes` is capped at 4 KiB inline. Larger payloads must be committed via `H(action_bytes)` only, with the bytes fetched from a content-addressed off-chain store at execute time. The `proposal_id` preimage uses `H(action_bytes)` so this cap does not change the security model.

3. **Approval circuit (`methods/guest/src/bin/approve_circuit.rs`).** Risc0 guest. Reads private witness `{ sk, salt, path: [Hash; 20], indices: [bool; 20] }` and public inputs `{ members_root, proposal_id, nullifier }`. Recomputes `leaf = H(sk ‖ salt)`, walks the Merkle path to a candidate root, asserts `candidate_root == members_root`, recomputes `n = H(sk ‖ proposal_id)`, asserts `n == nullifier`. Commits public inputs to the journal. Image ID pinned in `private_multisig_program/src/lib.rs` (built via `methods` crate's `build.rs`, same pattern lez-multisig uses).

4. **Verifier program (`methods/guest/src/bin/private_multisig.rs`).** SPEL `#[lez_program]` with six `#[instruction]` handlers (`create_multisig`, `create_vault`, `propose`, `approve`, `reject`, `execute`) — the `create_vault` handler was added in round 5 (R5-T1 fix) so the vault PDA can be claimed under the program before any `execute` chained call tries to authorize it; lez-multisig folded that into a single create step but private-multisig benefits from keeping vault creation idempotent and relayer-callable. The approval handler is swapped for a Risc0-receipt-verifying variant. The `approve` handler:
   1. Loads `MultisigState` and `Proposal` accounts.
   2. Recomputes `proposal_id = H(chain_id ‖ state_pda ‖ index ‖ H(proposal.action_bytes) ‖ H(proposal.target_program))`; asserts equals `public_inputs.proposal_id`. `chain_id` comes from the LEZ runtime (a syscall on LEZ or a pinned constant per deployment — `// VERIFY:` resolve during step 1).
   3. Asserts `public_inputs.members_root == state.members_root`.
   4. Verifies the receipt against the approve-circuit image ID (use `risc0_zkvm::Receipt::verify(IMAGE_ID)` inside the guest — same approach LEZ uses internally for nested proofs; confirm exact API against `programs/` in `logos-execution-zone` when implementing).
   5. Attempts to init `NullifierEntry` PDA at seeds `(proposal_pda, public_inputs.nullifier)`; init-fails-if-exists is the double-vote check.
   6. Increments `proposal.approvals_count`.
   `execute` requires `approvals_count >= m` and `!executed`; emits a `ChainedCall` to `target_program` with `action_bytes` (same primitive lez-multisig uses, per its PoC docs). `reject` is a no-op placeholder for the MVP — mark `// TODO(post-MVP)`.
   Error codes (deterministic, documented in the IDL): `E1000 InstanceNotActive`, `E1001 ProposalExpiredOrExecuted`, `E2000 InvalidReceipt`, `E2001 ImageIdMismatch`, `E2002 RootMismatch`, `E2003 ProposalIdMismatch`, `E3000 NullifierAlreadyUsed`, `E4000 ThresholdNotMet`, `E4001 AlreadyExecuted`.

5. **SDK (`sdk/`).** `Member::new()` → `(sk: Secret<[u8;32]>, salt, commitment)` where `sk` is wrapped in `secrecy::Secret` with `Zeroize` on drop and a redacting `Debug` impl. The CLI keystore encrypts `(sk, salt)` at rest with an Argon2id-derived KEK + ChaCha20-Poly1305; a BIP39 mnemonic export covers backup. `MultisigBuilder` gathers N commitments and emits `members_root`. `ApprovalProver::prove(sk, salt, path, indices, proposal_id, members_root) -> Receipt`. Thin wrappers build LEZ transactions for each instruction by consuming `private_multisig_core` types. Errors as `thiserror`.
   - **Resumable partial approvals (TASK.md Reliability requirement).** The SDK persists an `ApprovalSession { proposal_id, status: Drafted | Proving | Proved | Submitted | Confirmed, receipt?: Vec<u8> }` to a local sled/SQLite store at `~/.private-multisig/state` keyed by `(instance_pda, proposal_id, member_commitment)`. Crash recovery on next invocation resumes from the last persisted status: `Proving` re-enters the prover; `Proved` re-submits the cached receipt; `Submitted` polls for N-block confirmation before promoting to `Confirmed`. A reorg that drops a `Submitted` tx demotes back to `Proved` so the cached receipt is re-broadcast.

6. **CLI (`cli/`) + IDL gen (`idl-gen/`).** Copy lez-multisig's IDL-driven CLI shape verbatim — it derives flags from the IDL JSON, so once SPEL annotations are correct in step 4 the CLI is essentially free. `idl-gen` is a host binary that calls SPEL's IDL macro and writes `private_multisig.idl.json`.

7. **E2E test (`e2e_tests/`).** Single test: spin up a local sequencer (the `scripts/run_local_sequencer.sh` invocation should match lez-multisig's e2e test script — reuse it), create a 2-of-3 multisig with three SDK-generated members, propose a no-op `ChainedCall` to the `token` program, submit two approvals (with `RISC0_DEV_MODE=1` for speed in CI; gate a separate `--release` test on `RISC0_DEV_MODE=0`), execute, assert the chained call fired and the third member's later approval is rejected. Hook into a `Makefile` `test-e2e` target.

## Critical files to read before implementing

- `lez-multisig/multisig_core/src/pda.rs` — exact PDA seed/XOR convention to mirror.
- `lez-multisig/multisig_program/src/lib.rs` (guest entrypoint) — SPEL `#[lez_program]` shape and dispatch.
- `lez-multisig/methods/Cargo.toml` and `methods/build.rs` — Risc0 guest build wiring; image-ID export pattern.
- `lez-multisig/cli/src/main.rs` — IDL-driven CLI bootstrap; copy structurally.
- `lez-multisig/e2e_tests/` — sequencer launch script and harness pattern to copy.
- `logos-execution-zone/programs/token/` — a working SPEL program for cross-reference on account claim/state-update conventions and ChainedCall emission.
- `logos-execution-zone/programs/` — search for any program that verifies a nested Risc0 receipt; that's the exact API the `approve` handler needs.

If any of these aren't present or APIs have drifted, the implementer should resolve them by reading the referenced repos before writing code — don't guess.

## Open decisions deferred to implementation

- **Hash choice for Merkle + commitments**: inside Risc0, SHA-256 benefits from a built-in accelerator and is typically faster than Poseidon for STARK-only verification (proof size is fixed in Risc0 either way, so the trade-off is purely proving time). Poseidon is canonical only when the proof will be wrapped to Groth16 and the inner hash needs to be SNARK-friendly. Pick during step 1 after confirming whether LEZ verifies the receipt natively (SHA-256 wins) or expects a Groth16-wrapped proof (Poseidon wins). The `Hasher` trait keeps both paths reachable.
- **Merkle depth**: 20 (1M members) is generous and cheap inside a Risc0 guest. Adjust only if benchmarks show the proof too slow on a laptop.
- **Member set updates**: out of scope for MVP — `members_root` is fixed at `CreateMultisig`. Add/remove-member instructions are a follow-on; design them so the root is rotated and old nullifiers don't replay.
- **Reject instruction**: stubbed; needs its own nullifier domain (`H(sk ‖ proposal_id ‖ "reject")`) to remain unlinkable from approve. Defer to post-MVP.

## Verification

After implementation, the foundation is correct iff all of the following hold:

1. `cargo test -p crypto` — Merkle round-trip and nullifier determinism pass.
2. `cargo build --release` — workspace builds; Risc0 guests build and produce image IDs.
3. `make idl` — emits a non-empty `private_multisig.idl.json` with six instructions (`create_multisig`, `create_vault`, `propose`, `approve`, `execute`, `reject`) and four account types (state, vault, proposal, nullifier entry).
4. `make test-e2e` against a local sequencer (with `RISC0_DEV_MODE=1` for CI speed):
   - 2-of-3 multisig created; on-chain state has correct `members_root`, `m=2`, `n=3`.
   - Two distinct members approve a proposal; third approval with a *reused* nullifier is rejected with a documented error code.
   - `execute` succeeds after 2 approvals, fails before, fails twice in a row.
   - Chained call to the target program is observable in the sequencer trace.
5. One manual run of step 4 with `RISC0_DEV_MODE=0` to confirm real proofs verify (records baseline proving time on the dev machine — feeds the eventual prize-submission benchmarks).
6. CI: a single GitHub Actions workflow runs steps 1–4 on `main` and PRs. CI must be green on `main` before this plan is considered complete.
7. Nightly CI job (`workflow_dispatch` + `schedule: '0 6 * * *'`) runs the full E2E test with `RISC0_DEV_MODE=0` and uploads proof-generation timing as a benchmark artifact. This guards against real-prover regressions and feeds the eventual prize-submission benchmark table — `RISC0_DEV_MODE=1` CI alone leaves a long blind spot.

## Out of scope for this plan (explicit)

- Basecamp GUI app.
- Testnet deployment + the 5-external-instances criterion. **Hard prize blocker** — submission fails without this. The follow-on plan MUST address recruitment and ship a `quickstart` script that lets each external adopter create their instance in under 60 seconds.
- Recorded demo video.
- Performance/CU benchmarking write-up.
- Member set rotation, proposal rejection.
- Image-ID upgrade / migration story — v1 pins `APPROVE_CIRCUIT_IMAGE_ID` immutably; instances created under v1 stay on v1. Multi-image-version support is a follow-on plan.
- Audit/formal-verification work.

These become a follow-on plan once the foundation is green.