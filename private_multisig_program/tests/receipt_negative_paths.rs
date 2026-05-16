//! Negative-path / adversarial verification tests for the LP-0002 approve
//! circuit receipt.
//!
//! The happy-path coverage in `approve_circuit.rs` already shows that a
//! prover-produced receipt verifies against `APPROVE_CIRCUIT_IMAGE_ID`. The
//! purpose of THIS file is the strictly inverse claim: the receipt verifier
//! must reject every adjacent corruption — wrong image-id (zero, all-ones,
//! bitwise NOT, one-word-off, one-word-zeroed for every index), receipts
//! for a "different ELF", and self-constructed zero receipts. We also
//! sanity-check that two receipts produced from distinct witnesses both
//! still verify against the same pinned image-id (i.e., the receipt is
//! NOT tied to the witness) and that two receipts have distinct bytes
//! (sentinel for non-determinism in the prover — guarded behind dev-mode).
//!
//! All tests run with `RISC0_DEV_MODE=1` for tractable CI cost. Even in
//! dev mode the verifier still checks the claim's image-id against the
//! one passed to `Receipt::verify`, so the image-id rejection cases are
//! genuine end-to-end checks.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_lines)]

use std::env;

use crypto::{Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH};
use private_multisig_core::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// --------------------------------------------------------------------------
// Test fixtures and helpers
// --------------------------------------------------------------------------

/// Mirror the helper in `approve_circuit.rs` so the two test files stay
/// independent of each other (each `tests/*.rs` is a separate crate).
fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

/// Enable dev-mode for the prover. The verifier still checks the claim's
/// image-id against `Receipt::verify(image_id)` in dev-mode, so the
/// negative-path image-id tests in this file are genuine.
fn enable_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: cargo runs each `#[test]` in its own thread but each test
        // process is single-threaded with respect to env until threads spawn
        // inside the test body. We set the var before any prover thread.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

/// Bundle the host-side data we need to cross-check against the journal.
struct WitnessSession {
    receipt: Receipt,
    expected_bundle: ApprovePublicInputs,
}

/// Run the prover end-to-end with a freshly-built witness seeded by
/// `member_seeds[approver_index]`. Returns the receipt plus the host-side
/// expected public-input bundle.
fn produce_receipt(
    member_seeds: &[u8],
    approver_index: usize,
    proposal_nonce: u64,
    action_bytes: &[u8],
) -> WitnessSession {
    enable_dev_mode();

    // ----- Member set ----------------------------------------------------
    let members: Vec<Identity> = member_seeds
        .iter()
        .copied()
        .map(deterministic_identity)
        .collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let members_root = tree.root();

    let approver = &members[approver_index];
    let proof = tree.proof(approver_index).unwrap();

    // ----- Proposal-id derivation ---------------------------------------
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let proposal_id = derive_proposal_id(
        &chain_id,
        &state_pda,
        proposal_nonce,
        action_bytes,
        &target_program,
    );

    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&proposal_id);
    let expected_bundle = ApprovePublicInputs {
        members_root,
        proposal_id,
        nullifier: expected_nullifier,
    };

    // ----- Pack inputs and prove ----------------------------------------
    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&members_root);
    public_prefix[32..].copy_from_slice(&proposal_id);

    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    let env_builder = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&approver.sk)
        .write_slice(&approver.salt)
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build()
        .expect("ExecutorEnv build must succeed");

    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid witness");

    WitnessSession {
        receipt: prove_info.receipt,
        expected_bundle,
    }
}

/// Convenience: a "default" honest session for tests that only need one.
fn default_session() -> WitnessSession {
    produce_receipt(&[0, 1, 2, 3, 4], 2, 0, b"treasury_withdraw(100,recipient=0xABCD)")
}

// --------------------------------------------------------------------------
// 1. neg_wrong_image_id_rejects
// --------------------------------------------------------------------------

#[test]
fn neg_wrong_image_id_rejects() {
    let session = default_session();
    let receipt = &session.receipt;

    // Sanity: the right image-id still verifies.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("control: correct image-id must verify");

    // (a) all-zero image-id
    let zero = [0u32; 8];
    assert!(
        receipt.verify(zero).is_err(),
        "all-zero image-id must be rejected"
    );

    // (b) all-ones image-id
    let ones = [u32::MAX; 8];
    assert!(
        receipt.verify(ones).is_err(),
        "all-ones image-id must be rejected"
    );

    // (c) bitwise-NOT of the correct image-id
    let mut not_id = [0u32; 8];
    for i in 0..8 {
        not_id[i] = !APPROVE_CIRCUIT_IMAGE_ID[i];
    }
    // Defensive: the NOT cannot equal the original. (For any non-zero
    // input it can't, since NOT is an involution that has no fixed point
    // on 32-bit values.)
    assert_ne!(not_id, APPROVE_CIRCUIT_IMAGE_ID);
    assert!(
        receipt.verify(not_id).is_err(),
        "bitwise-NOT image-id must be rejected"
    );
}

// --------------------------------------------------------------------------
// 2. neg_one_word_off_image_id_rejects
// --------------------------------------------------------------------------

#[test]
fn neg_one_word_off_image_id_rejects() {
    let session = default_session();
    let receipt = &session.receipt;

    // Flip ONE word by +1 (with wrap), pick a deterministic index.
    let mut off = APPROVE_CIRCUIT_IMAGE_ID;
    off[3] = off[3].wrapping_add(1);
    assert_ne!(off, APPROVE_CIRCUIT_IMAGE_ID);

    assert!(
        receipt.verify(off).is_err(),
        "image-id with exactly one word off-by-one must be rejected"
    );
}

// --------------------------------------------------------------------------
// 3. neg_swapped_receipt_from_different_session_still_verifies_against_pinned_id
// --------------------------------------------------------------------------

#[test]
fn neg_swapped_receipt_from_different_session_still_verifies_against_pinned_id() {
    // Two distinct witnesses, two distinct receipts. Both must verify
    // against the SAME pinned image-id. The image-id is a property of the
    // ELF, NOT of the witness.
    let s1 = produce_receipt(&[0, 1, 2, 3, 4], 2, 0, b"action-A");
    let s2 = produce_receipt(&[10, 11, 12, 13, 14], 1, 7, b"action-B");

    s1.receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("first receipt must verify against the pinned image-id");
    s2.receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("second receipt must verify against the pinned image-id");

    // The two journals differ — the bundles carry different roots /
    // proposal-ids / nullifiers — so we are genuinely cross-checking two
    // independent runs.
    assert_ne!(
        s1.receipt.journal.bytes, s2.receipt.journal.bytes,
        "the two sessions must produce distinct journals"
    );
}

// --------------------------------------------------------------------------
// 4. neg_receipt_journal_decoded_matches_committed_inputs
// --------------------------------------------------------------------------

#[test]
fn neg_receipt_journal_decoded_matches_committed_inputs() {
    let session = default_session();
    let receipt = &session.receipt;

    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("control: correct image-id must verify");

    let journal_bytes = receipt.journal.bytes.as_slice();
    assert_eq!(
        journal_bytes.len(),
        APPROVE_PUBLIC_INPUTS_LEN,
        "journal must be the canonical 96-byte bundle — drift sentinel"
    );

    let mut journal_arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    journal_arr.copy_from_slice(journal_bytes);
    let decoded = ApprovePublicInputs::from_bytes(&journal_arr);

    assert_eq!(
        decoded, session.expected_bundle,
        "decoded journal must byte-match the host-side expected bundle"
    );
    // And the canonical packing of the host-side bundle must be byte-
    // identical to the wire journal — the strongest possible drift check.
    assert_eq!(
        &session.expected_bundle.to_bytes()[..],
        journal_bytes,
        "host-packed bundle must be byte-identical to the receipt journal"
    );
}

// --------------------------------------------------------------------------
// 5. neg_constructed_zero_receipt_fails_to_verify
// --------------------------------------------------------------------------

#[test]
fn neg_constructed_zero_receipt_fails_to_verify() {
    // `Receipt` does NOT implement `Default` (see risc0-zkvm 3.0 source
    // `src/receipt.rs`: there is no `impl Default for Receipt`, and
    // `InnerReceipt` is a `#[non_exhaustive]` enum with no `Default`).
    // `Receipt::new` requires an `InnerReceipt`, which in turn requires
    // a `Composite`, `Succinct`, `Groth16`, or `Fake` arm — none of which
    // are constructible from a default / zero seed without going through
    // the prover or, for `FakeReceipt`, hand-crafting a claim.
    //
    // We additionally confirm that `serde_json::from_str("{}")`-style
    // deserialization is impossible at the type level: `Receipt` requires
    // all three fields (`inner`, `journal`, `metadata`) to be present and
    // `inner` is `#[non_exhaustive]` with no default arm. So the closest
    // approximation to a "zero receipt" we can actually construct is a
    // `FakeReceipt` carrying a default `ReceiptClaim`. Build that and
    // confirm verification rejects it.
    enable_dev_mode();

    use risc0_zkvm::{FakeReceipt, InnerReceipt, MaybePruned, ReceiptClaim};

    // The default `ReceiptClaim` has a `Digest::ZERO` pre/post state — an
    // image-id of zero. The default journal is empty. The expected_claim
    // computed inside `Receipt::verify(APPROVE_CIRCUIT_IMAGE_ID)` will
    // bind to APPROVE_CIRCUIT_IMAGE_ID and to the digest of OUR empty
    // journal, so the digests cannot match the default-zero claim.
    let zero_claim: ReceiptClaim = ReceiptClaim {
        pre: MaybePruned::Pruned(Default::default()),
        post: MaybePruned::Pruned(Default::default()),
        exit_code: risc0_zkvm::ExitCode::Halted(0),
        input: MaybePruned::Pruned(Default::default()),
        output: MaybePruned::Pruned(Default::default()),
    };
    let fake = FakeReceipt::new(zero_claim);
    let inner = InnerReceipt::Fake(fake);
    let zero_receipt = Receipt::new(inner, Vec::new());

    // Verifying a hand-rolled "zero" receipt against the correct image-id
    // must reject: the claim's image-id is zero, not APPROVE_CIRCUIT_IMAGE_ID.
    assert!(
        zero_receipt.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
        "hand-rolled zero / default-claim receipt must NOT verify against APPROVE_CIRCUIT_IMAGE_ID"
    );

    // And for symmetry: verifying it against the zero image-id might
    // succeed only in dev-mode for a FakeReceipt — that path is NOT used
    // by the on-chain verifier (which always passes APPROVE_CIRCUIT_IMAGE_ID).
    // We don't assert on that case; what matters is the line above.
}

// --------------------------------------------------------------------------
// 6. neg_two_separate_receipts_have_distinct_inner_proofs
// --------------------------------------------------------------------------

#[test]
fn neg_two_separate_receipts_have_distinct_inner_proofs() {
    // Two distinct witnesses → two distinct journals (different
    // members_root, proposal_id, nullifier). The receipts' serialized
    // bytes must therefore differ. In `RISC0_DEV_MODE=1` the inner proof
    // is a `FakeReceipt` that carries the claim digest (which depends on
    // image-id + journal-digest), so even in dev-mode the receipt bytes
    // differ between two sessions with distinct journals.
    let s1 = produce_receipt(&[0, 1, 2, 3, 4], 2, 0, b"action-A");
    let s2 = produce_receipt(&[10, 11, 12, 13, 14], 1, 7, b"action-B");

    // Journals MUST differ (different roots / proposal_ids).
    assert_ne!(
        s1.receipt.journal.bytes, s2.receipt.journal.bytes,
        "two distinct witnesses must produce distinct journals"
    );

    // Serialize the whole receipts via borsh (Receipt implements
    // BorshSerialize) and compare bytes. Even in dev-mode the FakeReceipt
    // carries the claim's pruned digest, which encodes the journal digest,
    // so the receipts cannot be byte-identical.
    let s1_bytes = borsh::to_vec(&s1.receipt).expect("serialize receipt 1");
    let s2_bytes = borsh::to_vec(&s2.receipt).expect("serialize receipt 2");
    assert_ne!(
        s1_bytes, s2_bytes,
        "two receipts from distinct witnesses must NOT be byte-identical"
    );
}

// --------------------------------------------------------------------------
// 7. neg_verify_against_image_id_of_off_by_one_word_index_rejects
// --------------------------------------------------------------------------

#[test]
fn neg_verify_against_image_id_of_off_by_one_word_index_rejects() {
    let session = default_session();
    let receipt = &session.receipt;

    for i in 0..8 {
        let mut corrupted = APPROVE_CIRCUIT_IMAGE_ID;
        corrupted[i] = 0; // zero out one word, leave the rest as-is

        if corrupted == APPROVE_CIRCUIT_IMAGE_ID {
            // That word was already zero in the real id — replace with a
            // guaranteed-different value so the variant is truly distinct.
            corrupted[i] = 0xDEAD_BEEF;
        }
        assert_ne!(
            corrupted, APPROVE_CIRCUIT_IMAGE_ID,
            "variant {i} must differ from the real image-id"
        );

        assert!(
            receipt.verify(corrupted).is_err(),
            "image-id with word {i} replaced must be rejected"
        );
    }
}

// --------------------------------------------------------------------------
// 8. neg_journal_byte_at_each_position_can_be_tampered_with_only_via_re_proving
// --------------------------------------------------------------------------

#[test]
fn neg_journal_byte_at_each_position_can_be_tampered_with_only_via_re_proving() {
    // This is a type-system / surface audit, executed as a runtime check
    // wherever feasible. The surface to consider:
    //
    //   (a) `Receipt::journal: Journal` is a PUBLIC field on a struct whose
    //       Default impl is derived. So a caller CAN replace
    //       `receipt.journal` with arbitrary bytes via direct field
    //       assignment. The defense is that `Receipt::verify` recomputes
    //       the expected claim as `ReceiptClaim::ok(image_id,
    //       Pruned(journal.digest()))` and compares it against the
    //       receipt's inner claim digest — so any tamper of the journal
    //       breaks `expected_claim.digest() == inner.claim().digest()`.
    //       We assert that below.
    //
    //   (b) `Receipt::new(inner, journal)` rebuilds a receipt with a
    //       caller-chosen journal, but the inner claim is locked in by
    //       the prover — same defense as (a).
    //
    //   (c) `Receipt::inner` is also a public field. Setting it to a
    //       different `InnerReceipt` breaks the same digest equality.
    //
    // The only way to land a tampered-journal receipt that verifies is to
    // RE-PROVE with the new journal as a guest output — which is exactly
    // what we want.
    let session = default_session();
    let mut receipt = session.receipt.clone();

    // Sanity: untampered receipt verifies.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("control: untampered receipt must verify");

    // Tamper byte-0 of the journal.
    let original_byte = receipt.journal.bytes[0];
    receipt.journal.bytes[0] = original_byte.wrapping_add(1);
    assert!(
        receipt.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
        "tampered-journal (byte 0) receipt must NOT verify"
    );
    // Restore.
    receipt.journal.bytes[0] = original_byte;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("post-restore: receipt must verify again");

    // Tamper a middle byte (proposal_id region).
    let mid_idx = APPROVE_PUBLIC_INPUTS_LEN / 2;
    let original_mid = receipt.journal.bytes[mid_idx];
    receipt.journal.bytes[mid_idx] = original_mid ^ 0xFF;
    assert!(
        receipt.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
        "tampered-journal (middle byte) receipt must NOT verify"
    );
    receipt.journal.bytes[mid_idx] = original_mid;

    // Tamper the last byte (nullifier region).
    let last_idx = receipt.journal.bytes.len() - 1;
    let original_last = receipt.journal.bytes[last_idx];
    receipt.journal.bytes[last_idx] = original_last.wrapping_add(0x5A);
    assert!(
        receipt.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
        "tampered-journal (last byte) receipt must NOT verify"
    );
    receipt.journal.bytes[last_idx] = original_last;

    // After all restores, the receipt must verify again — no permanent
    // damage to the inner claim from our tampering.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("final control: fully-restored receipt must verify");
}

// --------------------------------------------------------------------------
// 9. neg_image_id_for_different_circuit_would_reject
// --------------------------------------------------------------------------

#[test]
fn neg_image_id_for_different_circuit_would_reject() {
    use crypto::{Hasher, Sha256Hasher};

    let session = default_session();
    let receipt = &session.receipt;

    // Fabricate an image-id by hashing an arbitrary 64-byte buffer. This
    // models "the image-id of some other ELF". It's astronomically
    // unlikely to collide with APPROVE_CIRCUIT_IMAGE_ID (SHA-256 of a
    // distinct preimage).
    let fake_elf_preimage = [0xA5u8; 64];
    let digest_bytes = Sha256Hasher::hash(&fake_elf_preimage);

    // Repack the 32 hash bytes as eight little-endian u32s — the wire
    // shape of an image-id.
    let mut fake_image_id = [0u32; 8];
    for i in 0..8 {
        let start = i * 4;
        fake_image_id[i] = u32::from_le_bytes(
            digest_bytes[start..start + 4]
                .try_into()
                .expect("4-byte chunk"),
        );
    }
    assert_ne!(fake_image_id, APPROVE_CIRCUIT_IMAGE_ID);
    assert_ne!(fake_image_id, [0u32; 8]);

    assert!(
        receipt.verify(fake_image_id).is_err(),
        "fabricated 'different ELF' image-id must be rejected"
    );
}

// --------------------------------------------------------------------------
// 10. neg_verify_with_pinned_correct_image_id_accepts
// --------------------------------------------------------------------------

#[test]
fn neg_verify_with_pinned_correct_image_id_accepts() {
    // Positive control. If THIS test ever fails while the negative tests
    // above pass, the test rig has degenerated into "everything rejects"
    // and the negative coverage is no longer meaningful.
    let session = default_session();
    let receipt = &session.receipt;

    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("positive control: correct image-id MUST verify");

    // And the journal must still be the canonical 96-byte bundle.
    assert_eq!(receipt.journal.bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
}
