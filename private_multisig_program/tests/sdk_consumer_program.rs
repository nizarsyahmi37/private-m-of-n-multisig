//! SDK-consumer perspective audit of `private_multisig_program`.
//!
//! ## Recommended SDK use pattern (copy this verbatim)
//!
//! These tests are the on-ramp. An SDK author building the LP-0002 client
//! side can copy the body of `sdkp_sdk_prove_path_signature_is_stable` and
//! get a working prove-and-verify flow that hits ONLY the public surface of
//! this crate plus `private_multisig_core` plus `crypto`. The recommended
//! end-to-end flow is:
//!
//! 1. Generate per-member [`Identity`] from a CSPRNG (32-byte `sk` and
//!    32-byte `salt`). The SDK should wrap `sk` in `secrecy::Secret` with
//!    `Zeroize` on drop — this crate keeps `sk` as raw bytes by design.
//! 2. Enroll commitments into a `MerkleTree<Sha256Hasher>` and freeze the
//!    root as `members_root`. Wrap `tree.insert(*c.as_bytes())` as
//!    `tree.insert_commitment(&c)` to hide the dereference (see core-side
//!    audit, FRICTION #1).
//! 3. Construct an [`Instruction::CreateMultisig`] and Borsh-serialize via
//!    `borsh::to_vec` — that wire-byte payload is what LEZ accepts.
//! 4. For each approval:
//!    1. Pack the 788-byte witness with [`pack_witness`] below (this is the
//!       canonical reference packer the SDK should ship).
//!    2. Feed the bytes to `ExecutorEnv::builder().write_slice(&buf).build()`.
//!    3. Call `default_prover().prove(env, APPROVE_CIRCUIT_ELF)`.
//!    4. Take `prove_info.receipt` and call
//!       `receipt.verify(APPROVE_CIRCUIT_IMAGE_ID)` BEFORE trusting any byte
//!       from `receipt.journal.bytes` — the journal IS publicly readable
//!       without verifying (see `sdkp_journal_can_be_extracted_without_calling_verify`)
//!       but treating an unverified journal as authoritative is the security
//!       footgun.
//!    5. Borsh-serialize the full receipt (`borsh::to_vec(&receipt)`) and
//!       persist to disk. The verifier program will accept the same bytes
//!       back later.
//! 5. Build the [`Instruction::Approve`] payload from the persisted receipt
//!    plus `ApprovePublicInputs::from_bytes(&journal_arr)`.
//!
//! The SDK should NOT need any `pub(crate)` item from this program crate —
//! the entire flow is reachable through `APPROVE_CIRCUIT_ELF`,
//! `APPROVE_CIRCUIT_IMAGE_ID`, and `image_id_hex()`. See
//! `sdkp_no_private_item_required_for_full_flow` for the explicit pin.
//!
//! ## Partial-approval resumability
//!
//! `sdkp_partial_approval_state_machine_compiles` walks through the
//! Drafted → Proving → Proved → Submitted → Confirmed state machine the SDK
//! is required to implement, with each state Borsh-serialized so the SDK
//! can save sessions to disk and resume after a crash. The receipt bytes
//! are the heavy payload in `Proved`; everything else is small.

#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::similar_names)]
#![allow(dead_code)]

use std::env;

use borsh::{from_slice, to_vec, BorshDeserialize, BorshSerialize};
use crypto::{
    merkle::MerkleProof, Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH, SALT_LEN,
    SK_LEN,
};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id, ApprovePublicInputs, ChainId,
    APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{
    image_id_hex, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Wire-format constants — duplicated from `witness_wire_format.rs` so this
/// file stays independent of any other test module.
const WIRE_PUBLIC_PREFIX_LEN: usize = 64;
const WIRE_SIBLINGS_FLAT_LEN: usize = MERKLE_DEPTH * HASH_LEN;
const WIRE_DIRECTION_LEN: usize = MERKLE_DEPTH;
const WIRE_TOTAL_WITNESS_LEN: usize =
    WIRE_PUBLIC_PREFIX_LEN + SK_LEN + SALT_LEN + WIRE_SIBLINGS_FLAT_LEN + WIRE_DIRECTION_LEN;

fn enable_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: the test process is single-threaded at this point — no
        // prover-spawned thread reads RISC0_DEV_MODE before we set it.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

fn build_member_set(n: u8) -> (Vec<Identity>, MerkleTree<Sha256Hasher>) {
    let members: Vec<Identity> = (0..n).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for m in &members {
        tree.insert(*m.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    (members, tree)
}

/// Synthetic proposal context — fixed program id, create key, target.
struct ProposalCtx {
    members_root: [u8; 32],
    proposal_id: [u8; 32],
}

fn synthetic_proposal_ctx(members_root: [u8; 32]) -> ProposalCtx {
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let proposal_id =
        derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program);
    ProposalCtx {
        members_root,
        proposal_id,
    }
}

/// Canonical reference packer for the 788-byte witness buffer that the
/// approve circuit's guest expects. This is the helper Scenario #8 calls
/// out as the "documented, minimal reference implementation": an SDK author
/// can copy this function verbatim into their crate.
///
/// Input is high-level: the approver's [`Identity`], its [`MerkleProof`]
/// against the live `members_root`, and the two 32-byte public inputs
/// (`members_root`, `proposal_id`).
///
/// Output is the exact byte sequence the prover wants — feed it to
/// `ExecutorEnv::builder().write_slice(...)` in a single call.
fn pack_witness(
    approver: &Identity,
    proof: &MerkleProof,
    members_root: &[u8; 32],
    proposal_id: &[u8; 32],
) -> [u8; WIRE_TOTAL_WITNESS_LEN] {
    let mut buf = [0u8; WIRE_TOTAL_WITNESS_LEN];

    // [0..32]   members_root
    // [32..64]  proposal_id
    buf[..HASH_LEN].copy_from_slice(members_root);
    buf[HASH_LEN..2 * HASH_LEN].copy_from_slice(proposal_id);

    let mut cursor = WIRE_PUBLIC_PREFIX_LEN;
    // [64..96]  sk
    buf[cursor..cursor + SK_LEN].copy_from_slice(&approver.sk);
    cursor += SK_LEN;
    // [96..128] salt
    buf[cursor..cursor + SALT_LEN].copy_from_slice(&approver.salt);
    cursor += SALT_LEN;

    // [128..768] flattened siblings: 20 × 32 bytes
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = cursor + level * HASH_LEN;
        buf[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    cursor += WIRE_SIBLINGS_FLAT_LEN;

    // [768..788] direction bytes (each strictly 0 or 1)
    for (level, bit) in proof.indices.iter().enumerate() {
        buf[cursor + level] = u8::from(*bit);
    }

    buf
}

/// Produce a receipt for the canonical "member at index 2 of 5 approves a
/// synthetic proposal" scenario. Shared by multiple sentinels.
fn produce_canonical_receipt() -> (Receipt, ApprovePublicInputs) {
    enable_dev_mode();

    let (members, tree) = build_member_set(5);
    let approver_index = 2usize;
    let approver = &members[approver_index];
    let proof = tree.proof(approver_index).unwrap();
    let members_root = tree.root();
    let ctx = synthetic_proposal_ctx(members_root);

    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&ctx.proposal_id);
    let expected = ApprovePublicInputs {
        members_root: ctx.members_root,
        proposal_id: ctx.proposal_id,
        nullifier: expected_nullifier,
    };

    let witness = pack_witness(approver, &proof, &ctx.members_root, &ctx.proposal_id);
    let env_builder = ExecutorEnv::builder()
        .write_slice(&witness)
        .build()
        .expect("ExecutorEnv build must succeed");
    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid witness");
    let receipt = prove_info.receipt;

    (receipt, expected)
}

// ---------------------------------------------------------------------------
// Scenario 1 — the full prove path the SDK will run
// ---------------------------------------------------------------------------

#[test]
fn sdkp_sdk_prove_path_signature_is_stable() {
    // Mirrors exactly what the SDK author's `produce_approval(...)` entry
    // point will do. Every call below is on the PUBLIC surface — no
    // pub(crate), no `use private_multisig_program::internal::*`.
    enable_dev_mode();

    let (members, tree) = build_member_set(5);
    let approver_index = 2usize;
    let approver = &members[approver_index];
    let proof = tree.proof(approver_index).unwrap();
    let members_root = tree.root();
    let ctx = synthetic_proposal_ctx(members_root);

    // Pack witness using the canonical helper. The signature
    // `pack_witness(&Identity, &MerkleProof, &[u8;32], &[u8;32])` is the
    // ergonomic surface the SDK will expose to its users.
    let witness = pack_witness(approver, &proof, &ctx.members_root, &ctx.proposal_id);

    // Build the ExecutorEnv via the documented `write_slice` path.
    let env_builder = ExecutorEnv::builder()
        .write_slice(&witness)
        .build()
        .expect("ExecutorEnv build must succeed");

    // `default_prover()` — no special trait imports needed at the call site.
    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid witness");

    // `ProveInfo { receipt, stats, .. }` — `.receipt` is the field name.
    let receipt = prove_info.receipt;

    // `receipt.verify(image_id)` — accepts `[u32; 8]` directly. No hex
    // round-trip, no `Into<...>` lift, no separate verifier-context object.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");
}

// ---------------------------------------------------------------------------
// Scenario 2 — APPROVE_CIRCUIT_IMAGE_ID is a `const`-suitable initializer
// ---------------------------------------------------------------------------

/// If `APPROVE_CIRCUIT_IMAGE_ID` were ever changed to a `static` or a
/// `LazyLock`, this `static` declaration would fail to compile — the test
/// is a compile-time pin.
static MY_IMAGE_ID: [u32; 8] = APPROVE_CIRCUIT_IMAGE_ID;

#[test]
fn sdkp_image_id_consumable_as_constant() {
    // The static above is the meaningful assertion; this test body just
    // pins runtime equality so anyone reading the test sees what's pinned.
    assert_eq!(MY_IMAGE_ID, APPROVE_CIRCUIT_IMAGE_ID);
    assert_eq!(MY_IMAGE_ID.len(), 8);
}

// ---------------------------------------------------------------------------
// Scenario 3 — image-id Borsh-serializable for persisted instance config
// ---------------------------------------------------------------------------

#[test]
fn sdkp_image_id_can_be_serialized_via_borsh_for_persistence() {
    // The SDK persists per-instance configuration to disk — `members_root`,
    // `threshold`, and the pinned `image_id`. Confirm `[u32; 8]` Borsh
    // round-trips cleanly without any newtype wrapper.
    let bytes = to_vec(&APPROVE_CIRCUIT_IMAGE_ID).expect("[u32;8] must Borsh-encode");
    assert_eq!(bytes.len(), 32, "8 × u32 = 32 bytes, no length prefix");

    let decoded: [u32; 8] =
        from_slice(&bytes).expect("[u32;8] must Borsh-decode");
    assert_eq!(decoded, APPROVE_CIRCUIT_IMAGE_ID);
}

// ---------------------------------------------------------------------------
// Scenario 4 — hex helper round-trips to the [u32;8] word array
// ---------------------------------------------------------------------------

#[test]
fn sdkp_image_id_hex_can_be_parsed_back_to_word_array() {
    // SDK-consumer sentinel for the release-notes / config-pin flow: take
    // `image_id_hex()`, hex-decode, repack as `[u32; 8]`, confirm equality.
    let s = image_id_hex();
    assert_eq!(s.len(), 64, "hex string must be exactly 64 chars");
    for c in s.chars() {
        assert!(
            c.is_ascii_digit() || ('a'..='f').contains(&c),
            "image_id_hex() must be lowercase hex; saw {c}",
        );
    }

    let bytes = hex::decode(&s).expect("image_id_hex() must be valid hex");
    assert_eq!(bytes.len(), 32, "hex must decode to 32 bytes");

    let mut reconstructed = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4]
            .try_into()
            .expect("4-byte chunk");
        reconstructed[i] = u32::from_le_bytes(chunk);
    }
    assert_eq!(reconstructed, APPROVE_CIRCUIT_IMAGE_ID);
}

// ---------------------------------------------------------------------------
// Scenario 5 — receipt Borsh-serializable for disk persistence and replay
// ---------------------------------------------------------------------------

#[test]
fn sdkp_receipt_serializable_for_storage_and_resubmit() {
    let (receipt, _expected) = produce_canonical_receipt();

    // Borsh-encode the entire Receipt — what the SDK persists to disk in
    // the "Proved" state of its session machine.
    let bytes = to_vec(&receipt).expect("Receipt must Borsh-serialize");
    assert!(!bytes.is_empty(), "Receipt bytes must not be empty");

    // Decode back and verify against the pinned image-id. This is exactly
    // what the SDK's "resume after restart" path does.
    let decoded: Receipt = from_slice(&bytes).expect("Receipt must Borsh-decode");
    decoded
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("round-tripped Receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");

    // Journal bytes survive the round-trip byte-for-byte.
    assert_eq!(
        decoded.journal.bytes, receipt.journal.bytes,
        "journal bytes must survive Borsh round trip",
    );
}

// ---------------------------------------------------------------------------
// Scenario 6 — journal readable WITHOUT calling verify (display-only path)
// ---------------------------------------------------------------------------

#[test]
fn sdkp_journal_can_be_extracted_without_calling_verify() {
    // The SDK may show "this approval is for proposal 0xABC..." in a UI
    // before it has finished verification. Confirm that pattern compiles
    // and produces sensible bytes without `verify` being called first.
    //
    // SECURITY NOTE — the journal bytes are NOT cryptographically trusted
    // until `receipt.verify(IMAGE_ID)` returns `Ok`. The SDK MUST verify
    // before treating any byte from the journal as authoritative (e.g.
    // before constructing the `Approve` instruction's `public_inputs`).
    // Peek-before-verify is fine for purely cosmetic display.
    let (receipt, expected) = produce_canonical_receipt();

    // Touch journal bytes WITHOUT verifying.
    let journal_bytes = receipt.journal.bytes.as_slice();
    assert_eq!(
        journal_bytes.len(),
        APPROVE_PUBLIC_INPUTS_LEN,
        "approve circuit journal must be exactly {APPROVE_PUBLIC_INPUTS_LEN} bytes",
    );

    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(journal_bytes);
    let peeked = ApprovePublicInputs::from_bytes(&arr);

    // In dev mode the bytes match what the host expected — but the SDK is
    // NOT allowed to rely on that until verify has succeeded. Pin the
    // requirement: now verify, THEN trust.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify before journal is trusted");
    assert_eq!(peeked, expected);
}

// ---------------------------------------------------------------------------
// Scenario 7 — ApprovePublicInputs round-trip from journal bytes
// ---------------------------------------------------------------------------

#[test]
fn sdkp_apprrove_public_inputs_from_journal_round_trip() {
    let (receipt, expected) = produce_canonical_receipt();
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify");

    let journal = receipt.journal.bytes.as_slice();
    assert_eq!(journal.len(), APPROVE_PUBLIC_INPUTS_LEN);
    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(journal);

    // `from_bytes` returns the full bundle; the SDK projects each field
    // as a public 32-byte array — no additional accessor required.
    let decoded = ApprovePublicInputs::from_bytes(&arr);
    assert_eq!(decoded, expected);
    assert_eq!(decoded.members_root, expected.members_root);
    assert_eq!(decoded.proposal_id, expected.proposal_id);
    assert_eq!(decoded.nullifier, expected.nullifier);

    // And the inverse — repacking yields the exact journal bytes.
    let repacked = decoded.to_bytes();
    assert_eq!(repacked.as_slice(), journal);
}

// ---------------------------------------------------------------------------
// Scenario 8 — pack_witness helper documented as canonical SDK reference
// ---------------------------------------------------------------------------

#[test]
fn sdkp_witness_packing_is_simple_enough_to_be_documented() {
    enable_dev_mode();

    // `pack_witness` is defined at file scope above and is intentionally
    // small: ~25 lines, no external dependencies, only `copy_from_slice`
    // and `u8::from(bool)`. The SDK can vendor this function verbatim.
    //
    // Confirm the prover accepts what `pack_witness` produces — i.e. the
    // reference implementation is functionally correct, not just visually
    // tidy.
    let (members, tree) = build_member_set(5);
    let approver_index = 2usize;
    let approver = &members[approver_index];
    let proof = tree.proof(approver_index).unwrap();
    let members_root = tree.root();
    let ctx = synthetic_proposal_ctx(members_root);

    let witness = pack_witness(approver, &proof, &ctx.members_root, &ctx.proposal_id);
    assert_eq!(
        witness.len(),
        WIRE_TOTAL_WITNESS_LEN,
        "pack_witness must produce exactly {WIRE_TOTAL_WITNESS_LEN} bytes",
    );
    assert_eq!(witness.len(), 788, "the SDK-facing constant is 788 bytes");

    let env_builder = ExecutorEnv::builder()
        .write_slice(&witness)
        .build()
        .expect("ExecutorEnv build must succeed");
    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must accept the canonical packing");
    prove_info
        .receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt from canonical packing must verify");
}

// ---------------------------------------------------------------------------
// Scenario 9 — partial-approval state machine compiles on the public API
// ---------------------------------------------------------------------------

/// State machine the SDK is required to implement. Every variant is Borsh-
/// serializable so the SDK can save sessions to disk and resume after a
/// crash. The heavy payload lives in `Proved.receipt_bytes`; everything
/// else is small.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
enum ApprovalSession {
    /// User has identified the proposal but has not yet generated a proof.
    Drafted,
    /// Prover is running; no receipt yet.
    Proving,
    /// Receipt produced locally; not yet submitted to LEZ. This is the
    /// resumable state — Borsh-encode and persist before submitting.
    Proved {
        receipt_bytes: Vec<u8>,
        public_inputs: ApprovePublicInputs,
    },
    /// Transaction submitted; awaiting on-chain confirmation.
    Submitted,
    /// Transaction included in a block and the verifier accepted the
    /// receipt. Terminal state.
    Confirmed,
}

#[test]
fn sdkp_partial_approval_state_machine_compiles() {
    // Drive every transition. Each one must Borsh-round-trip without help
    // from any internal item of the program crate.
    let session = ApprovalSession::Drafted;
    let bytes = to_vec(&session).expect("Drafted must Borsh-encode");
    assert_eq!(
        from_slice::<ApprovalSession>(&bytes).unwrap(),
        ApprovalSession::Drafted,
    );

    // Drafted → Proving (no payload change, just a state advance).
    let mut session = ApprovalSession::Proving;
    let bytes = to_vec(&session).expect("Proving must Borsh-encode");
    assert_eq!(
        from_slice::<ApprovalSession>(&bytes).unwrap(),
        ApprovalSession::Proving,
    );

    // Proving → Proved {receipt_bytes, public_inputs}. Receipt bytes come
    // from a real prover run; public inputs come from the journal.
    let (receipt, expected) = produce_canonical_receipt();
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify before being stored");
    let receipt_bytes = to_vec(&receipt).expect("Receipt must Borsh-encode");
    session = ApprovalSession::Proved {
        receipt_bytes: receipt_bytes.clone(),
        public_inputs: expected,
    };

    // Persist + resume: encode, decode, confirm equality, and confirm the
    // re-decoded receipt STILL verifies. This is the "user crashed mid-
    // approval, reopened the app, replayed the session" check.
    let persisted = to_vec(&session).expect("Proved state must Borsh-encode");
    let resumed: ApprovalSession =
        from_slice(&persisted).expect("Proved state must Borsh-decode");
    assert_eq!(resumed, session);

    if let ApprovalSession::Proved {
        receipt_bytes,
        public_inputs,
    } = resumed
    {
        let resumed_receipt: Receipt =
            from_slice(&receipt_bytes).expect("inner Receipt must Borsh-decode");
        resumed_receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .expect("resumed receipt must verify against the pinned image-id");
        assert_eq!(public_inputs, expected);
    } else {
        panic!("resumed state lost its Proved variant");
    }

    // Proved → Submitted → Confirmed: terminal transitions, no payload.
    session = ApprovalSession::Submitted;
    assert_eq!(
        from_slice::<ApprovalSession>(&to_vec(&session).unwrap()).unwrap(),
        ApprovalSession::Submitted,
    );
    session = ApprovalSession::Confirmed;
    assert_eq!(
        from_slice::<ApprovalSession>(&to_vec(&session).unwrap()).unwrap(),
        ApprovalSession::Confirmed,
    );
}

// ---------------------------------------------------------------------------
// Scenario 10 — full flow reachable without any pub(crate) item
// ---------------------------------------------------------------------------

#[test]
fn sdkp_no_private_item_required_for_full_flow() {
    // This test re-runs the full prove-and-verify flow using ONLY items
    // imported at the top of this file. Every one of those imports comes
    // from a `pub` re-export of the four upstream crates:
    //
    //   - `borsh` (workspace dep)
    //   - `crypto` (pub re-exports)
    //   - `private_multisig_core` (pub re-exports)
    //   - `private_multisig_program` (the three `pub` items under test)
    //   - `risc0_zkvm` (upstream public API)
    //
    // If any of the four upstream crates regresses a `pub` item, this
    // test stops compiling. Nothing in the body uses `pub(crate)`.
    enable_dev_mode();

    let (members, tree) = build_member_set(5);
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let ctx = synthetic_proposal_ctx(members_root);

    let witness = pack_witness(approver, &proof, &ctx.members_root, &ctx.proposal_id);
    let env_builder = ExecutorEnv::builder()
        .write_slice(&witness)
        .build()
        .expect("ExecutorEnv build must succeed via public API alone");
    let prove_info = default_prover()
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prove via public API alone");
    let receipt = prove_info.receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("verify via public API alone");

    // And the journal decode round-trip, again via public API alone.
    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(receipt.journal.bytes.as_slice());
    let _decoded = ApprovePublicInputs::from_bytes(&arr);

    // Touch image_id_hex() once so it is part of the "full flow" surface
    // this test pins.
    let _hex = image_id_hex();
}

// ---------------------------------------------------------------------------
// Scenario 11 — doc audit on `private_multisig_program/src/lib.rs`
// ---------------------------------------------------------------------------

/// `include_str!` snapshots the lib.rs source AT TEST-BUILD TIME. If anyone
/// adds a new `pub` item without a docstring, this test fails — but if
/// they later add docs without a fresh rebuild, the test correctly picks
/// up the new file because `include_str!` rebuilds on file changes.
const LIB_RS_SRC: &str = include_str!("../src/lib.rs");

#[test]
fn sdkp_doc_audit_on_program_crate() {
    // Audit rule: for each `pub const`, `pub fn`, or `pub static` line at
    // the file scope, the immediately preceding non-empty line must be a
    // `///` doc comment. Inner `//!` doc comments at the top of the file
    // don't count for individual items.
    let lines: Vec<&str> = LIB_RS_SRC.lines().collect();

    let pub_item_starts = ["pub const ", "pub fn ", "pub static "];

    let mut audited = 0usize;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // Skip `pub use` re-exports — they are not first-class items the
        // SDK consumer reads docs for.
        if !pub_item_starts.iter().any(|p| trimmed.starts_with(p)) {
            continue;
        }
        // Find the most recent non-empty preceding line.
        let mut j = i;
        let preceding_doc = loop {
            if j == 0 {
                break false;
            }
            j -= 1;
            let prev = lines[j].trim_start();
            if prev.is_empty() {
                continue;
            }
            // Attribute lines (`#[...]`) sit between docs and the item.
            if prev.starts_with("#[") || prev.starts_with("#![") {
                continue;
            }
            break prev.starts_with("///");
        };
        assert!(
            preceding_doc,
            "pub item missing rustdoc:\n  line {}: {}\n",
            i + 1,
            line,
        );
        audited += 1;
    }
    // We expect at least three audited items: `APPROVE_CIRCUIT_ELF`,
    // `APPROVE_CIRCUIT_IMAGE_ID`, and `image_id_hex`.
    assert!(
        audited >= 3,
        "expected at least 3 pub items in lib.rs, audited {audited}",
    );

    // Spot-check that each named symbol's docstring mentions it.
    assert!(
        LIB_RS_SRC.contains("/// Compiled RISC-V ELF bytes"),
        "APPROVE_CIRCUIT_ELF doc preamble missing",
    );
    assert!(
        LIB_RS_SRC.contains("/// Image ID of the approve circuit"),
        "APPROVE_CIRCUIT_IMAGE_ID doc preamble missing",
    );
    assert!(
        LIB_RS_SRC.contains("/// Hex-encoded helper"),
        "image_id_hex() doc preamble missing",
    );
}

// ---------------------------------------------------------------------------
// Scenario 12 — recommended SDK use pattern documented at top of file
// ---------------------------------------------------------------------------

#[test]
fn sdkp_recommended_sdk_use_pattern_documented_in_test() {
    // The block comment at the top of this file IS the documentation of
    // the recommended SDK pattern. This test simply asserts the doc block
    // is present (snapshotted via `include_str!`) and contains each of
    // the key on-ramp keywords. If anyone later strips the doc block, the
    // SDK author will notice immediately because this sentinel will fail.
    const SELF_SRC: &str = include_str!("./sdk_consumer_program.rs");

    for needle in [
        "Recommended SDK use pattern",
        "APPROVE_CIRCUIT_ELF",
        "APPROVE_CIRCUIT_IMAGE_ID",
        "pack_witness",
        "ExecutorEnv",
        "receipt.verify",
        "Borsh-serialize",
        "Drafted",
        "Proved",
        "Confirmed",
    ] {
        assert!(
            SELF_SRC.contains(needle),
            "recommended-pattern doc block missing keyword: {needle}",
        );
    }
}
