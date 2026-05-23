# LP-0002 Private M-of-N Multisig — Threat Model

Companion to [`PLAN.md`](./PLAN.md). Each threat entry follows: **Capability → Impact → Likelihood → Mitigation → Detection → Residual risk**. Threat IDs (T1.x–T7.x) are stable and referenced by integration tests and the §9 control matrix.

---

## 1. System Model & Trust Boundaries

### Actors

| Actor | Role | Trust |
|---|---|---|
| **Admin** | Creates the multisig instance, enrolls member commitments, finalizes the root. | Trusted for member-set integrity (v1). |
| **Members** | Each holds a private `(sk, salt)` whose commitment is a leaf in the Merkle tree. Submit approvals via ZK proofs. | Mutually untrusted; defended against M−1 collusion. |
| **Relayers** | Public LEZ accounts that submit `approve` and `execute` transactions, paying gas on behalf of members. | Semi-trusted: can censor, cannot forge, link, or replay. |
| **Chain observers** | Anyone reading public LEZ state. | Untrusted. |
| **Sequencer** | LEZ runtime, orders transactions, executes the verifier program. | Trusted for liveness and consensus per LEZ assumptions. |

### Trust boundaries

- **Trusted**: Risc0 zkVM soundness; Poseidon / SHA-256 collision resistance; LEZ sequencer; SPEL account-discriminator enforcement.
- **Semi-trusted**: relayer pool (mitigation: multi-relayer fallback, self-relay path).
- **Untrusted**: other members of the same instance; arbitrary chain observers; the public network path between client and relayer.

### Data sensitivity

| Datum | Sensitivity | Where it lives |
|---|---|---|
| `sk` (member secret) | Top secret — never leaves the device in plaintext. | SDK keystore, encrypted at rest; in-memory `Secret<[u8;32]>` with `Zeroize` on drop. |
| `salt` | Private. | Same as `sk`. |
| Merkle path + indices | Private (derivable from `sk`-knowledge of the tree). | Computed at proof time from the public leaf set. |
| `nullifier` | Public, but unlinkable across proposals by design. | On-chain as `NullifierEntry` PDA seed. |
| `members_root`, `proposal_id`, `action_bytes`, `target_program`, `chain_id` | Public. | On-chain in `MultisigState` / `Proposal` accounts. |

---

## 2. De-anonymization (Red Team) — headline threats

### T1.1 — Network metadata correlation on `approve` submission
- **Capability**: passive network observer or relayer logs IP / TLS fingerprint of the client submitting an approval.
- **Impact**: links a real-world identity to an approval, defeating the prize's primary anonymity guarantee.
- **Likelihood**: high if members submit directly from their ISP-attached address.
- **Mitigation**: SDK docs require submission via a public relayer pool; Tor / mixnet path documented for high-value instances; CLI exposes `--relayer <url>` and refuses to submit directly without `--allow-direct`.
- **Detection**: out-of-band — chain observers cannot detect; user reports of identity correlation.
- **Residual**: relayer operator can still observe client IP; mitigation is to use a relayer outside the adversary's trust set.

### T1.2 — Timing analysis across approvals
- **Capability**: observer correlates the chain-side order of `approve` transactions with off-chain member behavior (presence on Discord, working hours, etc.).
- **Impact**: probabilistic de-anonymization over many proposals.
- **Likelihood**: medium — exploitable against members who approve immediately.
- **Mitigation**: SDK applies a randomized submission delay (default 0–60 s, configurable); relayer pool batches approvals in fixed windows; documented "do not approve immediately" guidance.
- **Detection**: not detectable from chain state alone.
- **Residual**: long-horizon statistical analysis remains feasible — see T1.6.

### T1.3 — Proof-generation side channels
- **Capability**: attacker with co-tenancy on the member's hardware (shared cloud, malicious browser tab) observes cache / power / EM traces during proof generation.
- **Impact**: leaks `sk` or Merkle path, fully de-anonymizing.
- **Likelihood**: low if members prove locally on a personal laptop; high on shared hardware.
- **Mitigation**: docs forbid proof generation on shared cloud; guest uses constant-time hash implementations where feasible; SDK refuses to run inside a known container/VM environment without `--accept-shared-hardware`.
- **Detection**: not detectable.
- **Residual**: hardware-level side channels on personal devices are out of scope for v1.

### T1.4 — Cross-instance leaf intersection
- **Capability**: observer cross-references the leaf sets of many instances and notices that the same commitment appears repeatedly.
- **Impact**: links a member's identity across multiple multisigs.
- **Likelihood**: medium — requires off-chain knowledge of who participates where.
- **Mitigation**: SDK generates a fresh `(sk, salt)` per instance by default; CLI `identity new --instance <id>`; no public registry of `leaf ↔ identity` shipped.
- **Detection**: chain observers cannot detect intent; users self-detect by checking their own leaf reuse.
- **Residual**: members who deliberately reuse identities accept the risk.

### T1.5 — M−1 collusion identifying the Mth approver
- **Capability**: M−1 members collude, share their leaves and approvals, and observe who else approved.
- **Impact**: identifies the Mth approver by elimination.
- **Likelihood**: scenario-dependent; for tight-knit multisigs, plausible.
- **Mitigation**: none possible in v1 — fundamental property of any M-of-N anonymity set of size N where M−1 is known.
- **Detection**: members can detect by tracking who they know voted vs. the approval count.
- **Residual**: **documented and accepted**. Anonymity set is N − (known approvers). For meaningful anonymity, deploy with N ≫ M.

### T1.6 — Statistical voting-pattern analysis over many proposals
- **Capability**: long-running observer correlates patterns of approval / non-approval across many proposals with off-chain stances and behaviors.
- **Impact**: probabilistic identification over time.
- **Likelihood**: high for active, long-running multisigs.
- **Mitigation**: randomized delays (T1.2); some mitigation from members occasionally voting against their typical pattern.
- **Detection**: not detectable from chain state alone.
- **Residual**: persistent — documented. Inherent to any anonymous voting system.

---

## 3. Replay & Double-Vote

### T2.1 — Nullifier forgery
- **Capability**: attacker submits a receipt whose committed `nullifier` does not match the canonical `H(sk ‖ proposal_id)`.
- **Impact**: would let an attacker spend multiple "approval slots" with one secret.
- **Mitigation**: the approve circuit asserts `nullifier == H(sk ‖ proposal_id)`; an invalid receipt fails Risc0 verification.
- **Detection**: rejected at the verifier with `E2000 InvalidReceipt`.
- **Residual**: depends on Risc0 zkVM soundness — see T3.3.

### T2.2 — Cross-proposal replay
- **Capability**: attacker takes an approval from proposal A and submits it on proposal B in the same instance.
- **Impact**: would let one approval count toward multiple proposals.
- **Mitigation**: `nullifier` binds to `proposal_id`; the per-(proposal, nullifier) `NullifierEntry` PDA seed makes cross-proposal reuse a no-op (the PDA at proposal B would never collide because the nullifier itself differs). The verifier additionally recomputes and asserts `proposal_id` from on-chain state.
- **Detection**: rejected with `E2003 ProposalIdMismatch`.
- **Residual**: none.

### T2.3 — Cross-instance replay
- **Capability**: attacker takes an approval from instance X and submits it on instance Y.
- **Impact**: would let one approval count toward proposals in unrelated multisigs.
- **Mitigation**: `state_pda` is part of the `proposal_id` preimage, so the proposal_id committed in the receipt is bound to the originating instance; verifier asserts `public_inputs.proposal_id == recompute(state_pda, ...)`.
- **Detection**: rejected with `E2003 ProposalIdMismatch`.
- **Residual**: none.

### T2.4 — Cross-chain replay
- **Capability**: attacker takes an approval from devnet/testnet and submits it on mainnet (or any fork).
- **Impact**: bypasses the threshold on a chain where the member never intended to approve.
- **Mitigation**: `chain_id` enters the `proposal_id` preimage; verifier reads `chain_id` from the LEZ runtime and recomputes.
- **Detection**: rejected with `E2003 ProposalIdMismatch`.
- **Residual**: depends on `chain_id` being unforgeable in the verifier's runtime environment — verify during step 1.

### T2.5 — Action-bytes mutation post-propose
- **Capability**: attacker (or buggy admin path) tries to mutate `action_bytes` or `target_program` on an existing `Proposal` between propose and execute, expecting prior approvals to carry over.
- **Impact**: would let members be tricked into approving action A but executing action B.
- **Mitigation**: `H(action_bytes)` and `H(target_program)` are in the `proposal_id` preimage; the verifier recomputes from current on-chain state, so any mutation invalidates all existing approvals. The MVP additionally treats `Proposal` fields as write-once after `propose`.
- **Detection**: rejected with `E2003 ProposalIdMismatch` if mutation occurs; integration test asserts write-once semantics.
- **Residual**: none.

---

## 4. Threshold Integrity

### T3.1 — Fake-member injection by admin
- **Capability**: admin enrolls an adversary-controlled leaf at `create_multisig` time.
- **Impact**: a malicious admin can manufacture a majority.
- **Mitigation**: documented trust assumption — v1 is admin-gated by design. Future versions add multi-admin enrollment with mutual co-signs.
- **Detection**: members verify the public leaf set out-of-band against their own commitments before participating.
- **Residual**: admin-key compromise remains a fundamental v1 risk. Document this in the submission's "Security Assumptions" section.

### T3.2 — Root manipulation post-finalize
- **Capability**: admin attempts to swap `members_root` after the multisig is active.
- **Impact**: would let admin retroactively change the member set.
- **Mitigation**: `members_root` is written once at `create_multisig` and the program exposes no instruction to update it; SPEL account discriminators enforce read-only after creation.
- **Detection**: integration test exercises a "swap-root" attempt and asserts it fails.
- **Residual**: none in v1 (no update path exists).

### T3.3 — Risc0 prover soundness bug
- **Capability**: a bug in the Risc0 zkVM lets a malicious prover produce a receipt that verifies but does not prove the claimed statement.
- **Impact**: complete bypass of the approval circuit.
- **Mitigation**: pin to an audited Risc0 release in `Cargo.toml`; subscribe to Risc0 security advisories; ship an emergency-rotation path via SDK version bumps.
- **Detection**: out-of-band — Risc0 disclosure.
- **Residual**: same trust assumption as any Risc0-based protocol.

---

## 5. Liveness & DoS

### T4.1 — Spam invalid receipts to burn CU
- **Capability**: attacker submits a flood of malformed `approve` transactions.
- **Impact**: drives up gas costs and proposal-submission noise.
- **Mitigation**: verifier fails fast on invalid receipts (cheapest check first: image-ID, then root, then nullifier init, then receipt cryptographic verification); LEZ tx fees disincentivize spam.
- **Detection**: anomalous tx volume on the verifier program.
- **Residual**: paying for the failed verification still costs the attacker — economic mitigation.

### T4.2 — `execute` frontrunning races
- **Capability**: two parties race to call `execute` on a proposal that has just reached threshold.
- **Impact**: one tx wins; the other reverts. No state corruption.
- **Mitigation**: `executed: bool` on `Proposal` is checked-and-set atomically; `E4001 AlreadyExecuted` returned on losers.
- **Detection**: chain observers see one success + one revert.
- **Residual**: none — first-wins is the documented semantics.

### T4.3 — Relayer censorship
- **Capability**: a relayer refuses to forward an approval.
- **Impact**: delays an approval; does not prevent it.
- **Mitigation**: SDK supports multiple relayer endpoints with round-robin / fallback; documented self-relay path via the member's own funded transport account; SDK exposes a `submit` retry policy.
- **Detection**: client observes failed submission; falls over to next relayer.
- **Residual**: a single censored relayer is recoverable; coordinated censorship across all relayers requires self-relay.

### T4.4 — Proposal expiry griefing
- **Capability**: adversary delays approvals past an expiry deadline.
- **Impact**: proposal cannot execute.
- **Mitigation**: v1 has no expiry — flag for v2. Until then, the documented behavior is that proposals remain open indefinitely.
- **Detection**: N/A in v1.
- **Residual**: v2 adds `expiry` and a corresponding `E1001` error; the resumable SDK state machine surfaces the deadline to the user.

---

## 6. Cryptographic Risks

### T5.1 — Groth16 trusted setup compromise
- **Capability**: if the implementation takes the Groth16-wrap path, the toxic waste from the setup ceremony is compromised.
- **Impact**: undetectable forgery of any proof.
- **Mitigation**: use Risc0's published Groth16 setup with documented ceremony lineage; prefer the native Risc0 verifier path if LEZ supports it (resolved during step 1).
- **Detection**: not detectable — must be prevented at ceremony time.
- **Residual**: standard zk-SNARK trust assumption.

### T5.2 — Hash preimage on nullifier
- **Capability**: attacker finds `(sk', proposal_id')` such that `H(sk' ‖ proposal_id') == nullifier` for an existing nullifier.
- **Impact**: would let an attacker create a colliding nullifier and impersonate an approval slot.
- **Mitigation**: Poseidon / SHA-256 collision resistance ≥ 128 bits over 254-bit (Poseidon BN254) or 256-bit (SHA-256) fields.
- **Detection**: not detectable in the wild before exploitation.
- **Residual**: same as any system relying on these primitives.

### T5.3 — Field/curve mismatch between guest and on-chain verifier
- **Capability**: the guest commits hashes in one field while the on-chain verifier interprets them in another.
- **Impact**: false positives or false negatives; valid proofs rejected or invalid proofs accepted.
- **Mitigation**: single source-of-truth parameter file (`crypto/src/params.rs`) imported by both guest and verifier; CI parity test computes the same input through both paths and asserts byte equality.
- **Detection**: CI parity test catches drift on every commit.
- **Residual**: none if parity test is maintained.

---

## 7. Implementation & Supply Chain

### T6.1 — SDK leaks secrets in logs / `Debug`
- **Capability**: developer or user accidentally logs a `Member` value or a `Secret<[u8;32]>` via `{:?}`.
- **Impact**: full disclosure of `sk`.
- **Mitigation**: `Secret<T>` newtype with a redacting `Debug` impl (renders `"[REDACTED]"`); CI `cargo clippy` lint banning `Debug` derives on types containing `Secret`; integration test asserts `format!("{:?}", member)` does not contain the byte sequence of the wrapped secret.
- **Detection**: CI lint + parity test.
- **Residual**: human error in third-party integrations.

### T6.2 — Memory disclosure post-use
- **Capability**: attacker with read access to RAM or swap reads `sk` after the SDK is done with it.
- **Impact**: full disclosure of `sk`.
- **Mitigation**: `Secret<T>` uses `Zeroize` on drop; SDK docs guide users to disable swap for high-value instances; OS-level `mlock` where supported.
- **Detection**: not detectable.
- **Residual**: depends on OS hardening; documented.

### T6.3 — Dependency compromise (supply chain)
- **Capability**: a malicious crate is published or an existing crate is compromised.
- **Impact**: arbitrary code in the SDK / verifier / guest.
- **Mitigation**: `cargo audit` + `cargo deny` in CI on every PR; `Cargo.lock` checked in and pinned; minimize dependency surface, especially in the guest binary; review every new direct dependency.
- **Detection**: `cargo audit` flags known CVEs; `cargo deny` flags policy violations.
- **Residual**: zero-day in a trusted crate.

### T6.4 — Verifier program bugs
- **Capability**: classic on-chain program bugs — CU bypass, integer overflow, account confusion, missing discriminator checks.
- **Impact**: scenario-dependent; worst case is full bypass of approval verification.
- **Mitigation**: SPEL's type system enforces account discriminators by default; `cargo fuzz` targets the `approve` instruction with malformed inputs; manual review checkpoint before testnet deployment; documented error catalog (`E1000`–`E4001`) makes test assertions specific.
- **Detection**: fuzz suite + integration tests + manual review.
- **Residual**: latent bugs until the manual-review checkpoint is performed.

### T6.5 — Reorg / forced rollback of an approval
- **Capability**: the LEZ chain reorgs and drops a previously included `approve`.
- **Impact**: a member's approval is silently undone.
- **Mitigation**: SDK tracks `Submitted → Confirmed` with N-block confirmation (`N = 32` default, configurable); the resumable `ApprovalSession` state machine demotes `Submitted → Proved` on reorg and re-broadcasts the cached receipt.
- **Detection**: SDK observes the receipt no longer in the canonical chain; user is surfaced a warning.
- **Residual**: catastrophic reorgs deeper than `N` blocks are out of scope; document the `N` choice.

---

## 8. Operational

### T7.1 — Phishing CLI / Basecamp app
- **Capability**: attacker distributes a malicious build of the CLI or Basecamp app that exfiltrates `sk` on first run.
- **Impact**: full member compromise.
- **Mitigation**: signed releases with a documented signing key; reproducible builds with checksums in the README; out-of-band verification instructions in the docs.
- **Detection**: checksum mismatch on download.
- **Residual**: users who skip verification remain at risk.

### T7.2 — Compromised member device
- **Capability**: malware on the member's machine reads the encrypted keystore and keylogs the passphrase.
- **Impact**: full member compromise.
- **Mitigation**: hardware-wallet integration path (v2); strong-passphrase guidance + Argon2id KDF parameters; documented "consider this device's threat model" in the docs.
- **Detection**: not detectable from inside the SDK.
- **Residual**: v1 cannot defend against post-compromise; document explicitly.

### T7.3 — Admin social engineering
- **Capability**: attacker convinces the admin to enroll an attacker-controlled leaf during `add_member`.
- **Impact**: malicious member injection — equivalent to T3.1.
- **Mitigation**: docs require the admin to verify each prospective member's leaf out-of-band (e.g., over a Signal call) before submitting `add_member`; CLI prints a warning when a single `add_member` batch includes unfamiliar leaves.
- **Detection**: members spot a wrong leaf in the public set; admin retracts before `finalize`.
- **Residual**: depends on admin opsec.

---

## 9. Blue-Team Control Matrix

| Threat ID | Mitigation lives in | Verification |
|---|---|---|
| T1.1 | Docs only in v1; relayer/submission module deferred to a follow-on under `sdk/src/` | Manual review |
| T1.2 | Deferred to a follow-on `submit`-pathway under `sdk/src/`; v1 has no submission delay | Unit test on delay distribution (post-implementation) |
| T1.3 | `methods/guest/src/bin/approve_circuit.rs` (constant-time hash), docs | Manual review |
| T1.4 | `sdk/src/member.rs` (per-instance identity default); CLI integration deferred | Unit test |
| T1.5 | Documented residual; `THREAT_MODEL.md` §10 | None |
| T1.6 | Documented residual; partial mitigation deferred with T1.2 | None |
| T2.1 | `methods/guest/src/bin/approve_circuit.rs` (nullifier assertion) | Integration test: tampered nullifier |
| T2.2 | `methods/guest/src/bin/private_multisig.rs` `approve` handler + `NullifierEntry` PDA | **Integration test: cross-proposal replay** |
| T2.3 | `methods/guest/src/bin/private_multisig.rs` `approve` handler (`proposal_id` recompute) | **Integration test: cross-instance replay** |
| T2.4 | `methods/guest/src/bin/private_multisig.rs` `approve` handler (`chain_id` in preimage) | **Integration test: cross-chain replay** |
| T2.5 | `methods/guest/src/bin/private_multisig.rs` `propose` handler (write-once via init-fails-if-exists) | **Integration test: mutation rejected** |
| T3.1 | Documented trust assumption | Manual review |
| T3.2 | `methods/guest/src/bin/private_multisig.rs` (no `update_root` instruction; init-only state) | **Integration test: root swap rejected** |
| T3.3 | `methods/{,guest/}Cargo.toml`, `sdk/Cargo.toml` (`risc0-{build,zkvm} = "=3.0.5"` pinned strict) | Manual review + advisory monitoring |
| T4.1 | `methods/guest/src/bin/private_multisig.rs` `approve` handler (fail-fast ordering) | Bench test on rejection cost |
| T4.2 | `methods/guest/src/bin/private_multisig.rs` `execute` handler (atomic check-and-set) | Integration test: double-execute |
| T4.3 | Deferred to follow-on relayer module under `sdk/src/` | Unit test: fallback path (post-implementation) |
| T4.4 | v2 — documented | None in v1 |
| T5.1 | `Cargo.toml` (Risc0 setup pinned), docs | Manual review |
| T5.2 | `crypto/src/hash.rs` (algo choice + params) | Manual review |
| T5.3 | `private_multisig_core/src/proof.rs` (single-source `derive_proposal_id`) + `private_multisig_core/tests/cross_crate_parity.rs` | **CI parity test: guest vs verifier byte equality** |
| T6.1 | `sdk/src/member.rs` (`Secret<T>` + redacting `Debug`); no CI lint yet | **Unit test: `Debug` output redaction** |
| T6.2 | `sdk/src/member.rs` (`Zeroize`), docs | Manual review |
| T6.3 | `.github/workflows/ci.yml` `audit` job (`cargo audit` + `cargo deny`) | CI on every PR |
| T6.4 | `private_multisig_program/tests/{receipt_negative_paths,red_team_program_v4}.rs`; `cargo fuzz` corpus deferred | **Negative-path tests + manual review** |
| T6.5 | `sdk/src/session.rs` (`try_confirm` + `DEFAULT_FINALITY_BLOCKS`) | Integration test: simulated reorg |
| T7.1 | Release tooling, docs | Manual review |
| T7.2 | Docs + v2 hardware path | Manual review |
| T7.3 | Docs; CLI admin warning deferred to the CLI follow-on | Manual review |

Threats in **bold** have explicit integration tests planned in the MVP foundation.

---

## 10. Residual Risks & Documented Trust Assumptions

These risks are not fully mitigated in v1 and must appear in the submission's "Security Assumptions" section:

1. **M−1 collusion** identifies the Mth approver. Fundamental to any M-of-N anonymity set.
2. **Admin key compromise** allows arbitrary member-set manipulation pre-finalize and bypass of v1 trust. v2 introduces multi-admin co-sign.
3. **Long-horizon statistical voting-pattern analysis** can probabilistically de-anonymize active members. Inherent to all anonymous voting systems.
4. **Hardware side channels** on the member's own device. v1 does not defend; v2 hardware-wallet path narrows the attack surface.
5. **Risc0 zkVM soundness** — relied on as a trust root. Subject to the same assumptions as any Risc0 application.
6. **Catastrophic chain reorgs deeper than `N` blocks** silently undo approvals; SDK surfaces a warning but cannot recover.
7. **Single-relayer censorship** is recoverable; coordinated censorship across all known relayers requires the self-relay path.
8. **Post-compromise of a member device** cannot be recovered v1; v2 ships hardware-wallet support.

---

## 11. Verification Hooks

### Threats verified by integration tests (must be in the foundation E2E suite)

- T2.2 cross-proposal replay
- T2.3 cross-instance replay
- T2.4 cross-chain replay
- T2.5 action-bytes mutation rejected
- T3.2 root manipulation rejected
- T5.3 guest-vs-verifier parameter parity
- T6.1 `Debug` redaction
- T6.4 `cargo fuzz` corpus (continuous fuzz)

### Threats verified by manual review at the testnet-deployment checkpoint

- T1.1 / T1.3 (operational guidance is correct and visible in docs)
- T3.1 (admin trust documented in README)
- T3.3 / T5.1 (Risc0 versions pinned; advisory monitoring in place)
- T5.2 (hash parameters reviewed against latest analyses)
- T7.x (release tooling, signing, docs)

### Threats accepted as residual

- T1.5, T1.6, T4.4 (v1), and items in §10.

The blue-team control matrix in §9 doubles as the security-review checklist; every row must be signed off before testnet deployment.
