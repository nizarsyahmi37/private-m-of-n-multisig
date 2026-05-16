//! Blue-team validator (round 3 — final structural pass) for the LP-0002
//! Risc0 approve circuit.
//!
//! Rounds 1 and 2 confirmed the foundational defensive properties:
//!
//! - canonical 96-byte journal `[root || pid || nullifier]`
//! - Borsh / explicit-layout parity, both at the bundle layer and the
//!   `Receipt` layer (full `borsh::to_vec(&receipt)` round trip verifies)
//! - nullifier determinism and cross-member / cross-proposal distinctness,
//!   including a 2×2 product and a 10-pair scan
//! - image-id stability across runs and hex/word-array round trip
//! - 1-, 7-, 5000-member tree edge cases
//! - parallel proving across 4 OS threads with no race
//! - byte-position spec pin: `[0..32) root, [32..64) pid, [64..96) nullifier`
//! - 10x determinism, receipt clone independence, length=96 strictness
//!
//! Round 3 is the **structural** validation pass before step 4 starts
//! consuming this API. The aim is not to re-prove the cryptographic
//! invariants — those are locked — but to pin the wire-level and
//! ownership-level properties an SDK / on-chain integrator will rely on:
//!
//! - 8-thread parallel widening (sentinel for any latent prover-stack race
//!   that wider-than-4 concurrency would surface)
//! - 50-receipt serial scale-up (10x widening past round 2's batch sanity)
//! - receipt **byte size stability** under same-witness re-proofs (storage
//!   budgeting pin — round 2 pinned journal byte-identity, this pins the
//!   full borsh-serialized Receipt size)
//! - `image_id_hex()` idempotence pin
//! - `image_id_hex()` ↔ `[u32; 8]` round trip via `hex::decode` (third
//!   independent pin of the canonical hex sentinel from
//!   `image_id_stability.rs`)
//! - explicit little-endian pin for `APPROVE_CIRCUIT_IMAGE_ID[0]` derived
//!   from the hex sentinel `b03a41ce…`
//! - per-field byte slice assertion (each `[0..32)`, `[32..64)`, `[64..96)`
//!   isolably checked so a failure tells you which field drifted)
//! - explicit no-leak sentinel: a witness with a recognizable `0xDEADBEEF…`
//!   signature in `sk` must not surface anywhere in the journal
//! - two proposals / same member / same root: clean separation between
//!   "what tree" and "what proposal"
//! - independence of unrelated receipts (absence of cross-verification API)
//! - `Receipt::clone` ownership independence (verify clone after drop)
//! - image-id word-array constant pin, duplicated from
//!   `image_id_stability.rs` so any rename catches across files
//! - ELF size band as a perf regression guard (perf baseline measured
//!   ~263,940 bytes; pin `[100_000, 1_000_000]` as the guardrail)
//! - full from_bytes / to_bytes round trip at the journal layer
//!
//! Every test sets `RISC0_DEV_MODE=1` so the file runs in seconds. The
//! defensive assertions are identical under `RISC0_DEV_MODE=0`.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_name_repetitions)]

use std::env;
use std::thread;

use crypto::{Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id, ApprovePublicInputs, ChainId,
    APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{
    image_id_hex, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// ---------------------------------------------------------------------------
// Shared helpers — self-contained so this integration test file compiles
// independently of `blue_team_program{,_v2}.rs`.
// ---------------------------------------------------------------------------

fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: each `#[test]` runs in its own process at file granularity
        // for an integration test crate's tests; setting once at the top of
        // each test is single-threaded with respect to env until the prover
        // (or our own `thread::spawn`) is invoked further down.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

#[derive(Clone)]
struct Witness {
    members_root: [u8; 32],
    proposal_id: [u8; 32],
    approver: Identity,
    siblings_flat: [u8; MERKLE_DEPTH * HASH_LEN],
    direction_bytes: [u8; MERKLE_DEPTH],
}

fn build_witness(
    members: &[Identity],
    approver_index: usize,
    chain_id: &ChainId,
    state_pda: &[u8; 32],
    index: u64,
    action_bytes: &[u8],
    target_program: &[u8; 32],
) -> Witness {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .expect("tree.insert must succeed within capacity");
    }
    let members_root = tree.root();

    let proof = tree.proof(approver_index).expect("proof must exist");

    let proposal_id = derive_proposal_id(
        chain_id,
        state_pda,
        index,
        action_bytes,
        target_program,
    );

    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    Witness {
        members_root,
        proposal_id,
        approver: members[approver_index].clone(),
        siblings_flat,
        direction_bytes,
    }
}

fn prove_once(w: &Witness) -> Receipt {
    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&w.members_root);
    public_prefix[32..].copy_from_slice(&w.proposal_id);

    let env_builder = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&w.approver.sk)
        .write_slice(&w.approver.salt)
        .write_slice(&w.siblings_flat)
        .write_slice(&w.direction_bytes)
        .build()
        .expect("ExecutorEnv build must succeed");

    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid witness");
    let receipt = prove_info.receipt;

    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");

    receipt
}

fn decode_journal(receipt: &Receipt) -> ApprovePublicInputs {
    let bytes = receipt.journal.bytes.as_slice();
    assert_eq!(
        bytes.len(),
        APPROVE_PUBLIC_INPUTS_LEN,
        "journal length drift: expected {APPROVE_PUBLIC_INPUTS_LEN}, got {}",
        bytes.len()
    );
    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(bytes);
    ApprovePublicInputs::from_bytes(&arr)
}

struct ProposalContext {
    chain_id: ChainId,
    state_pda: [u8; 32],
    target_program: [u8; 32],
}

fn default_proposal_context() -> ProposalContext {
    let program_id: [u8; 32] = [0x77; 32];
    let create_key: [u8; 32] = [0x42; 32];
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0x33; 32];
    let chain_id = ChainId::from_u64(0x1234_5678);
    ProposalContext {
        chain_id,
        state_pda,
        target_program,
    }
}

// ---------------------------------------------------------------------------
// 1. 8 OS threads, 8 distinct witnesses, all verify, pairwise-distinct
//    nullifiers. Wider-concurrency sentinel beyond round 2's 4-thread test.
// ---------------------------------------------------------------------------

#[test]
fn v3_8_parallel_threads_8_different_witnesses_all_verify() {
    ensure_dev_mode();

    // Spread 8 distinct (member, proposal) pairs so each thread has a fully
    // independent witness — distinct member, distinct proposal index,
    // distinct action bytes. Any latent shared-mutable state on the prover
    // host stack that only surfaces at >4-way concurrency lands here.
    let members: Vec<Identity> = (0..8u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let witnesses: Vec<Witness> = (0..8u64)
        .map(|i| {
            build_witness(
                &members,
                i as usize,
                &ctx.chain_id,
                &ctx.state_pda,
                i,
                format!("v3_parallel_8_thread_{i}").as_bytes(),
                &ctx.target_program,
            )
        })
        .collect();

    let handles: Vec<_> = witnesses
        .into_iter()
        .map(|w| {
            thread::spawn(move || {
                let receipt = prove_once(&w);
                receipt
                    .verify(APPROVE_CIRCUIT_IMAGE_ID)
                    .expect("each of 8 threads' receipts must verify");
                let decoded = decode_journal(&receipt);
                // Each thread carries its own witness, not a stolen one.
                assert_eq!(decoded.members_root, w.members_root);
                assert_eq!(decoded.proposal_id, w.proposal_id);
                let host_nul = w.approver.nullifier::<Sha256Hasher>(&w.proposal_id);
                assert_eq!(decoded.nullifier, host_nul);
                decoded.nullifier
            })
        })
        .collect();

    let nullifiers: Vec<[u8; 32]> = handles
        .into_iter()
        .enumerate()
        .map(|(i, h)| h.join().unwrap_or_else(|_| panic!("thread {i} panicked")))
        .collect();

    // Pairwise distinct: C(8,2) = 28 comparisons.
    for i in 0..nullifiers.len() {
        for j in (i + 1)..nullifiers.len() {
            assert_ne!(
                nullifiers[i], nullifiers[j],
                "threads {i} and {j} produced the same nullifier"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2. 50 distinct witnesses produced serially, all verify, 50 distinct
//    nullifiers, every journal decodes cleanly. Scale-up sentinel beyond
//    round 2's 10-pair scan.
// ---------------------------------------------------------------------------

#[test]
fn v3_50_distinct_witnesses_serial_all_verify() {
    ensure_dev_mode();

    // 10 members × 5 proposal indices = 50 distinct (member, proposal)
    // pairs. Every receipt must verify; every journal must decode; the 50
    // nullifiers must be pairwise distinct.
    let members: Vec<Identity> = (0..10u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let mut nullifiers: Vec<[u8; 32]> = Vec::with_capacity(50);
    for member_idx in 0..10usize {
        for proposal_idx in 0..5u64 {
            let action =
                format!("v3_scale_m{member_idx}_p{proposal_idx}");
            let w = build_witness(
                &members,
                member_idx,
                &ctx.chain_id,
                &ctx.state_pda,
                proposal_idx,
                action.as_bytes(),
                &ctx.target_program,
            );
            let receipt = prove_once(&w);
            receipt
                .verify(APPROVE_CIRCUIT_IMAGE_ID)
                .expect("receipt must verify against pinned image-id");
            let decoded = decode_journal(&receipt);
            assert_eq!(decoded.members_root, w.members_root);
            assert_eq!(decoded.proposal_id, w.proposal_id);
            let host_nul =
                members[member_idx].nullifier::<Sha256Hasher>(&w.proposal_id);
            assert_eq!(decoded.nullifier, host_nul);
            nullifiers.push(decoded.nullifier);
        }
    }

    assert_eq!(nullifiers.len(), 50);

    // Pairwise distinct: C(50,2) = 1225 comparisons. O(n^2) is fine at n=50.
    for i in 0..nullifiers.len() {
        for j in (i + 1)..nullifiers.len() {
            assert_ne!(
                nullifiers[i], nullifiers[j],
                "pairs {i} and {j} produced the same nullifier"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Receipt byte size is stable for the same witness across two proving
//    runs. Pins storage-budget assumptions for the SDK.
// ---------------------------------------------------------------------------

#[test]
fn v3_receipt_byte_size_is_stable_for_same_witness() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        99,
        b"v3_receipt_size_stability",
        &ctx.target_program,
    );

    let r1 = prove_once(&w);
    let r2 = prove_once(&w);

    let s1 = borsh::to_vec(&r1).expect("receipt must borsh-serialize");
    let s2 = borsh::to_vec(&r2).expect("receipt must borsh-serialize");

    // Size stability is what storage budgeting needs. Content stability is
    // even stronger and is the actual round-1 invariant; we re-pin it here
    // as a stronger guarantee in case future Risc0 ever introduces
    // non-determinism in the serialized form while keeping length stable.
    assert_eq!(
        s1.len(),
        s2.len(),
        "receipt byte size drift across same-witness re-proofs: {} vs {}",
        s1.len(),
        s2.len(),
    );
    assert_eq!(
        s1, s2,
        "receipt bytes drift across same-witness re-proofs (size was stable)"
    );

    // Dev-mode receipts are small (perf baseline measured ~354 bytes). Pin
    // a generous band so a future Risc0 release that grows the dev-mode
    // receipt shape (added metadata, version prefix, etc.) is flagged
    // before SDK / on-chain budgeting silently breaks.
    assert!(
        !s1.is_empty(),
        "receipt borsh size is zero (clearly broken)"
    );
    assert!(
        s1.len() < 64 * 1024,
        "dev-mode receipt grew past 64 KiB ({} bytes) — shape regressed",
        s1.len(),
    );
}

// ---------------------------------------------------------------------------
// 4. `image_id_hex()` is idempotent (two calls return the same string).
// ---------------------------------------------------------------------------

#[test]
fn v3_image_id_hex_is_stable_across_calls() {
    // No prover invocation needed — purely a host-side constant.
    let a = image_id_hex();
    let b = image_id_hex();
    assert_eq!(a, b, "image_id_hex() must be idempotent");
    assert_eq!(a.len(), 64, "image_id_hex() must always return 64 chars");
}

// ---------------------------------------------------------------------------
// 5. `image_id_hex()` round-trips through `hex::decode` → 32 bytes →
//    8 LE u32s → equals `APPROVE_CIRCUIT_IMAGE_ID`.
// ---------------------------------------------------------------------------

#[test]
fn v3_image_id_hex_decodes_to_image_id_words() {
    let s = image_id_hex();
    let bytes = hex::decode(&s).expect("image_id_hex must be valid hex");
    assert_eq!(bytes.len(), 32, "hex must decode to 32 bytes");

    let mut words = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4]
            .try_into()
            .expect("4-byte chunk slice");
        words[i] = u32::from_le_bytes(chunk);
    }

    assert_eq!(
        words, APPROVE_CIRCUIT_IMAGE_ID,
        "hex → bytes → LE u32 array did not round-trip to the pinned image-id"
    );
}

// ---------------------------------------------------------------------------
// 6. Endianness pin: first 4 bytes of the canonical hex `b0 3a 41 ce`
//    interpret as LE u32 == 0xce413ab0 == 3_460_381_360.
//
//    The image-id shifted when the SPEL verifier guest was added to the
//    methods crate (adding `nssa_core` + `spel-framework` + `serde` to the
//    guest crate's dep graph changes the unified guest build's compile
//    environment, which propagates into every binary's image-id). The new
//    pinned hex lives in image_id_stability.rs as `PINNED_IMAGE_ID_HEX`.
// ---------------------------------------------------------------------------

#[test]
fn v3_image_id_word_array_endianness_is_little_endian() {
    // The canonical hex sentinel in image_id_stability.rs starts with
    // "b03a41ce…". As LITTLE-endian u32 that is:
    //   byte[0]=0xb0, byte[1]=0x3a, byte[2]=0x41, byte[3]=0xce
    //   → u32 = 0xce413ab0 = 3,460,381,360
    // If the hex helper ever serialized as big-endian instead, the first
    // word would be 0xb03a41ce = 2,956,673,486, and this test would fail.
    assert_eq!(
        APPROVE_CIRCUIT_IMAGE_ID[0], 3_460_381_360u32,
        "endianness pin failed: APPROVE_CIRCUIT_IMAGE_ID[0] = {}, expected 3_460_381_360 \
         (which is 0x{:08x}, the LE interpretation of the hex prefix b0 3a 41 ce)",
        APPROVE_CIRCUIT_IMAGE_ID[0],
        0xce41_3ab0u32,
    );

    // Cross-check the LE interpretation explicitly: pull the first 4 bytes
    // of the hex helper output and run them back through `from_le_bytes`.
    let s = image_id_hex();
    let prefix = &s[..8]; // 4 bytes worth of hex chars
    let prefix_bytes =
        hex::decode(prefix).expect("hex prefix decode must succeed");
    assert_eq!(prefix_bytes.len(), 4);
    let prefix_arr: [u8; 4] = prefix_bytes
        .as_slice()
        .try_into()
        .expect("4-byte prefix array");
    let le = u32::from_le_bytes(prefix_arr);
    assert_eq!(le, 3_460_381_360u32, "LE re-decode of hex prefix disagreed");
    assert_eq!(
        le, APPROVE_CIRCUIT_IMAGE_ID[0],
        "hex prefix LE decode disagreed with APPROVE_CIRCUIT_IMAGE_ID[0]"
    );
}

// ---------------------------------------------------------------------------
// 7. Journal bytes match `ApprovePublicInputs` layout — each 32-byte slice
//    asserted as a SEPARATE sub-assertion so a failure is isolable.
// ---------------------------------------------------------------------------

#[test]
fn v3_journal_bytes_match_apprrove_public_inputs_layout_per_field() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        1,
        &ctx.chain_id,
        &ctx.state_pda,
        17,
        b"v3_per_field_layout_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal = receipt.journal.bytes.clone();
    assert_eq!(journal.len(), 96, "journal must be exactly 96 bytes");

    // Each field as its OWN assertion so a failure points at the right one.
    let root_slice = &journal[0..32];
    assert_eq!(
        root_slice, &w.members_root,
        "journal[0..32) (members_root field) diverged from host members_root"
    );

    let pid_slice = &journal[32..64];
    assert_eq!(
        pid_slice, &w.proposal_id,
        "journal[32..64) (proposal_id field) diverged from host proposal_id"
    );

    let expected_nullifier = w.approver.nullifier::<Sha256Hasher>(&w.proposal_id);
    let nul_slice = &journal[64..96];
    assert_eq!(
        nul_slice, &expected_nullifier,
        "journal[64..96) (nullifier field) diverged from host-computed nullifier"
    );
}

// ---------------------------------------------------------------------------
// 8. No-leak sentinel: a recognizable `0xDEADBEEF…` `sk` signature must
//    NOT appear anywhere in the 96-byte journal.
// ---------------------------------------------------------------------------

#[test]
fn v3_no_witness_data_leaks_to_journal() {
    ensure_dev_mode();

    // Sentinel `sk` whose first 4 bytes are `0xDE 0xAD 0xBE 0xEF` and which
    // is otherwise arbitrary. A substring match for this 4-byte pattern in
    // the 96-byte journal would indicate a witness-bytes leak. We
    // additionally search for the full 32-byte `sk` — any future leak that
    // accidentally committed the secret in full would surface here too.
    let mut sk = [0u8; 32];
    sk[0] = 0xDE;
    sk[1] = 0xAD;
    sk[2] = 0xBE;
    sk[3] = 0xEF;
    for i in 4..32 {
        sk[i] = 0xA0u8.wrapping_add(i as u8);
    }
    let salt = [0x5Au8; 32];
    let leak_member = Identity::new(sk, salt);

    // Embed `leak_member` at index 0 in a 4-member tree so the witness is
    // structurally valid and the proof actually executes.
    let mut members: Vec<Identity> = vec![leak_member.clone()];
    members.extend((1..4u8).map(deterministic_identity));

    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        0,
        &ctx.chain_id,
        &ctx.state_pda,
        88,
        b"v3_no_leak_sentinel_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal = receipt.journal.bytes.clone();
    assert_eq!(journal.len(), 96);

    // 4-byte signature substring scan.
    let signature: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    let found_4 = journal
        .as_slice()
        .windows(signature.len())
        .any(|w| w == signature);
    assert!(
        !found_4,
        "0xDEADBEEF signature appeared in journal — witness sk leaked"
    );

    // Full 32-byte sk substring scan — defense in depth.
    let found_full = journal
        .as_slice()
        .windows(sk.len())
        .any(|w| w == sk);
    assert!(
        !found_full,
        "Full 32-byte sk appeared in journal — witness fully leaked"
    );

    // And salt should not leak either.
    let found_salt = journal
        .as_slice()
        .windows(salt.len())
        .any(|w| w == salt);
    assert!(
        !found_salt,
        "32-byte salt appeared in journal — witness salt leaked"
    );

    // Sanity: journal still decodes cleanly and the nullifier matches the
    // host formula for the leak member.
    let decoded = decode_journal(&receipt);
    let expected = leak_member.nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(decoded.nullifier, expected);
}

// ---------------------------------------------------------------------------
// 9. Same member, two different proposals — two receipts. Journals agree on
//    `members_root`, differ on `proposal_id` and `nullifier`.
// ---------------------------------------------------------------------------

#[test]
fn v3_two_different_proposals_same_member_same_root() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let w_a = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        0,
        b"v3_proposal_alpha",
        &ctx.target_program,
    );
    let w_b = build_witness(
        &members,
        2,
        &ctx.chain_id,
        &ctx.state_pda,
        1,
        b"v3_proposal_beta",
        &ctx.target_program,
    );

    // Sanity: the two witnesses share a members_root (same tree) but
    // already differ on proposal_id at the host layer.
    assert_eq!(w_a.members_root, w_b.members_root);
    assert_ne!(w_a.proposal_id, w_b.proposal_id);

    let r_a = prove_once(&w_a);
    let r_b = prove_once(&w_b);

    r_a.verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt A must verify");
    r_b.verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt B must verify");

    let d_a = decode_journal(&r_a);
    let d_b = decode_journal(&r_b);

    // Same tree → same root in both journals.
    assert_eq!(
        d_a.members_root, d_b.members_root,
        "same member, same tree, different proposals: members_root must match"
    );

    // Different proposals → different proposal_id and different nullifier.
    assert_ne!(
        d_a.proposal_id, d_b.proposal_id,
        "different proposals must yield different proposal_id"
    );
    assert_ne!(
        d_a.nullifier, d_b.nullifier,
        "same member on different proposals must yield different nullifiers"
    );
}

// ---------------------------------------------------------------------------
// 10. Two unrelated receipts each verify against the pinned image-id, and
//     there is NO cross-verification API — receipts are independent.
// ---------------------------------------------------------------------------

#[test]
fn v3_unrelated_receipts_dont_cross_verify_against_each_other() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();

    let w_a = build_witness(
        &members,
        0,
        &ctx.chain_id,
        &ctx.state_pda,
        100,
        b"v3_independent_receipt_A",
        &ctx.target_program,
    );
    let w_b = build_witness(
        &members,
        3,
        &ctx.chain_id,
        &ctx.state_pda,
        200,
        b"v3_independent_receipt_B",
        &ctx.target_program,
    );

    let r_a = prove_once(&w_a);
    let r_b = prove_once(&w_b);

    // Each verifies against the pinned image-id, independently.
    r_a.verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt A must verify");
    r_b.verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt B must verify");

    // Their journals are independent: different witnesses must yield
    // different `(proposal_id, nullifier)` pairs. The members_root is the
    // same because the same tree was used — that is correct, and is the
    // SDK's anchor for grouping approvals.
    let d_a = decode_journal(&r_a);
    let d_b = decode_journal(&r_b);
    assert_ne!(d_a.proposal_id, d_b.proposal_id);
    assert_ne!(d_a.nullifier, d_b.nullifier);

    // Document the absence of a cross-verification API: there is no
    // `r_a.verify_against(&r_b)`, and there is no method on the Receipt
    // type that would let one receipt judge another. The verification API
    // is `Receipt::verify(image_id)`, and both receipts use the SAME
    // pinned image-id — that is what makes them "comparable" at all. Any
    // cross-receipt relationship is the verifier program's responsibility
    // (e.g. counting distinct nullifiers under a single proposal_id);
    // it is NOT something the receipt layer does on its own.
    //
    // This is asserted by the absence of any other working call here.
    // Adding a stronger cross-check (e.g. `r_a.verify(some_journal_of_b)`)
    // would not even type-check, which is the right level of API hygiene.
}

// ---------------------------------------------------------------------------
// 11. `Receipt::clone`, drop original, verify clone — ownership / lifetime
//     defensive pin.
// ---------------------------------------------------------------------------

#[test]
fn v3_receipt_clone_then_drop_original_then_verify_clone() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        4,
        &ctx.chain_id,
        &ctx.state_pda,
        555,
        b"v3_clone_lifetime_action",
        &ctx.target_program,
    );

    let original = prove_once(&w);
    let cloned = original.clone();
    let snapshot = original.journal.bytes.clone();

    // Drop the original BEFORE verifying the clone. Any implicit
    // `Rc`/`Arc` sharing whose contents could be moved out from under the
    // clone would surface here as either a verification failure or a
    // panic.
    drop(original);

    cloned
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("clone must verify against pinned image-id after original is dropped");

    // The clone's journal must be byte-identical to the snapshot we took
    // before the original was dropped.
    assert_eq!(
        cloned.journal.bytes, snapshot,
        "clone's journal diverged from the pre-drop snapshot"
    );

    // And the decoded fields still line up with the witness inputs.
    let decoded = decode_journal(&cloned);
    assert_eq!(decoded.members_root, w.members_root);
    assert_eq!(decoded.proposal_id, w.proposal_id);
    let expected_nullifier = w.approver.nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}

// ---------------------------------------------------------------------------
// 12. Pin the `[u32; 8]` image-id constant. Duplicates the pin from
//     `image_id_stability.rs` from a different file so any rename or
//     refactor that breaks one source catches across both.
// ---------------------------------------------------------------------------

#[test]
fn v3_image_id_word_array_is_pinned_constant() {
    // Same value as `PINNED_IMAGE_ID_WORDS` in image_id_stability.rs.
    // Duplicated here intentionally — the redundancy is the point.
    const EXPECTED: [u32; 8] = [
        3_460_381_360,
        3_239_953_090,
        1_343_517_355,
        3_511_254_084,
        1_815_790_745,
        1_201_536_365,
        692_780_191,
        2_077_888_072,
    ];

    assert_eq!(
        APPROVE_CIRCUIT_IMAGE_ID, EXPECTED,
        "APPROVE_CIRCUIT_IMAGE_ID drift! pinned: {:?}, actual: {:?}",
        EXPECTED, APPROVE_CIRCUIT_IMAGE_ID,
    );

    // Cross-check element 0 stays exactly the LE-decoded value of the
    // canonical hex sentinel prefix (defensive duplication of test 6).
    assert_eq!(EXPECTED[0], 3_460_381_360u32);
}

// ---------------------------------------------------------------------------
// 13. ELF size band as a perf regression guard. Perf baseline measured
//     ~263,940 bytes; pin `[100_000, 1_000_000]`.
// ---------------------------------------------------------------------------

#[test]
fn v3_elf_size_matches_perf_baseline_band() {
    let len = APPROVE_CIRCUIT_ELF.len();

    // Bands are intentionally wide: the perf baseline value (~263,940) is
    // not a hard pin because the Risc0 toolchain can move it by a few KB
    // across versions. The narrower image-id pin already catches any
    // actual ELF byte change. This is a coarser "did a giant dep get
    // pulled in / did the build produce a stub" guard.
    assert!(
        len >= 100_000,
        "approve_circuit ELF is suspiciously small: {} bytes (min 100_000)",
        len,
    );
    assert!(
        len <= 1_000_000,
        "approve_circuit ELF is suspiciously large: {} bytes (max 1_000_000)",
        len,
    );
}

// ---------------------------------------------------------------------------
// 14. Full round trip on the journal: receipt → from_bytes → to_bytes →
//     byte-identical to the original journal.
// ---------------------------------------------------------------------------

#[test]
fn v3_journal_decodes_with_apprrove_public_inputs_from_bytes_then_re_encodes_byte_identical() {
    ensure_dev_mode();

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let ctx = default_proposal_context();
    let w = build_witness(
        &members,
        3,
        &ctx.chain_id,
        &ctx.state_pda,
        2_024,
        b"v3_full_round_trip_action",
        &ctx.target_program,
    );

    let receipt = prove_once(&w);
    let journal_bytes = receipt.journal.bytes.clone();
    assert_eq!(journal_bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);

    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(&journal_bytes);
    let decoded = ApprovePublicInputs::from_bytes(&arr);

    // Field-level cross-check: decoded values match host-computed values.
    let expected_nullifier = w.approver.nullifier::<Sha256Hasher>(&w.proposal_id);
    assert_eq!(decoded.members_root, w.members_root);
    assert_eq!(decoded.proposal_id, w.proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);

    // Round-trip back to bytes and require byte-identity with the journal.
    let re_encoded = decoded.to_bytes();
    assert_eq!(
        re_encoded.as_slice(),
        journal_bytes.as_slice(),
        "to_bytes ∘ from_bytes did not round-trip the journal byte-for-byte"
    );

    // For belt-and-braces, also assert that calling `from_bytes` on the
    // re-encoded output yields a value equal to `decoded` itself — the
    // standard "f(g(x)) = x at every level" closure check.
    let redecoded = ApprovePublicInputs::from_bytes(&re_encoded);
    assert_eq!(redecoded, decoded);
}
