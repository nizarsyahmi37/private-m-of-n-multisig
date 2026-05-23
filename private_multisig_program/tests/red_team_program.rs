//! Red-team validation (round 1) of the LP-0002 Risc0 approve circuit.
//!
//! This file is the FIRST adversarial pass on the guest itself. The four
//! input-layer crates (`crypto`, `private_multisig_core`) have already been
//! red-teamed four rounds each, so the attack surface here is squarely the
//! glue: the byte layout the host pushes into `ExecutorEnv`, the assertions
//! inside the guest, the journal it commits, and the receipt the host
//! verifies against `APPROVE_CIRCUIT_IMAGE_ID`.
//!
//! All tests run under `RISC0_DEV_MODE=1` (set before any prover invocation)
//! so each round-trip is sub-second rather than 5–10 minutes. Dev mode still
//! executes the guest, still runs every assertion in `approve_circuit.rs`,
//! and still produces a verifiable receipt — the only thing it skips is the
//! actual SNARK seal generation. Every "guest must fail" assertion below
//! therefore exercises the real guest panic path.
//!
//! Attack vectors covered (1:1 with the red-team spec):
//!   1.  `red_proves_for_non_member_fails`
//!   2.  `red_wrong_members_root_fails`
//!   3.  `red_tampered_sibling_bit_fails`
//!   4.  `red_tampered_direction_bit_fails`
//!   5.  `red_invalid_direction_byte_fails`
//!   6.  `red_proposal_id_substitution_changes_nullifier_in_journal`
//!   7.  `red_journal_does_not_leak_sk`
//!   8.  `red_zero_leaf_witness_fails_finding_1b_at_circuit_layer`
//!   9.  `red_truncated_witness_fails`
//!   10. `red_swapped_sk_salt_fails`
//!   11. `red_member_at_wrong_index_proof_fails`
//!   12. `red_image_id_mismatch_rejected`
//!   13. `red_creative_journal_bit_flip_breaks_verification` (creative)

#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::similar_names)]

use std::env;

use crypto::{merkle::MERKLE_DEPTH, Identity, MerkleTree, Sha256Hasher, HASH_LEN};
use private_multisig_core::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

// ---------------------------------------------------------------------------
// Shared scaffolding.
// ---------------------------------------------------------------------------

fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: this is a single-threaded cargo-test process; no other
        // thread is reading the env at this point. Same pattern the existing
        // happy-path test in `approve_circuit.rs` uses.
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

/// Build a 5-member tree (same pattern as the happy-path test) and return
/// the members and the tree.
fn build_member_set() -> (Vec<Identity>, MerkleTree<Sha256Hasher>) {
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    (members, tree)
}

/// Canonical synthetic `proposal_id` used across the failure tests.
fn canonical_proposal_id() -> [u8; 32] {
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program)
}

/// Witness packed for the guest's `read_slice` stream.
struct Witness {
    public_prefix: [u8; 64],
    sk: [u8; 32],
    salt: [u8; 32],
    siblings_flat: [u8; MERKLE_DEPTH * HASH_LEN],
    direction_bytes: [u8; MERKLE_DEPTH],
}

impl Witness {
    fn from_member(
        member: &Identity,
        proof: &crypto::MerkleProof,
        members_root: [u8; HASH_LEN],
        proposal_id: [u8; HASH_LEN],
    ) -> Self {
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
        Self {
            public_prefix,
            sk: member.sk,
            salt: member.salt,
            siblings_flat,
            direction_bytes,
        }
    }

    /// Build an `ExecutorEnv` from the witness and run the prover. Returns
    /// `Ok(receipt)` on success or `Err(())` on any failure (env build,
    /// prove, guest panic).
    fn try_prove(&self) -> Result<risc0_zkvm::Receipt, ()> {
        let env_builder = match ExecutorEnv::builder()
            .write_slice(&self.public_prefix)
            .write_slice(&self.sk)
            .write_slice(&self.salt)
            .write_slice(&self.siblings_flat)
            .write_slice(&self.direction_bytes)
            .build()
        {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        let prover = default_prover();
        match prover.prove(env_builder, APPROVE_CIRCUIT_ELF) {
            Ok(prove_info) => Ok(prove_info.receipt),
            Err(_) => Err(()),
        }
    }
}

/// Build a happy-path witness for member index `i`.
fn happy_witness(i: usize) -> (Identity, Witness, [u8; 32]) {
    let (members, tree) = build_member_set();
    let approver = members[i].clone();
    let proof = tree.proof(i).unwrap();
    let pid = canonical_proposal_id();
    let w = Witness::from_member(&approver, &proof, tree.root(), pid);
    (approver, w, pid)
}

// ---------------------------------------------------------------------------
// 1. Non-member tries to prove with a fabricated path.
// ---------------------------------------------------------------------------

#[test]
fn red_proves_for_non_member_fails() {
    ensure_dev_mode();
    let (_members, tree) = build_member_set();
    // Outsider — not enrolled in the tree.
    let outsider = deterministic_identity(0xEE);

    // All-zero siblings, all-zero directions — the classic FINDING-1 forgery
    // shape. The guest applies `hash_leaf` first, so this can't recover the
    // real root.
    let proof = crypto::MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    let w = Witness::from_member(&outsider, &proof, tree.root(), canonical_proposal_id());
    assert!(
        w.try_prove().is_err(),
        "non-member with fabricated all-zero proof must NOT produce a receipt"
    );

    // Also try with a randomly-shaped fake path — same outcome required.
    let mut fake_sibs = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for (lvl, sib) in fake_sibs.iter_mut().enumerate() {
        for b in 0..HASH_LEN {
            sib[b] = (lvl as u8).wrapping_mul(31).wrapping_add(b as u8);
        }
    }
    let proof2 = crypto::MerkleProof {
        siblings: fake_sibs,
        indices: [true; MERKLE_DEPTH],
    };
    let w2 = Witness::from_member(&outsider, &proof2, tree.root(), canonical_proposal_id());
    assert!(
        w2.try_prove().is_err(),
        "non-member with random-looking proof must NOT produce a receipt"
    );
}

// ---------------------------------------------------------------------------
// 2. Real member but a different `members_root` is passed in.
// ---------------------------------------------------------------------------

#[test]
fn red_wrong_members_root_fails() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let i = 1usize;
    let approver = &members[i];
    let proof = tree.proof(i).unwrap();

    // Wrong root: bit-flip the real root.
    let mut wrong_root = tree.root();
    wrong_root[0] ^= 0x01;

    let w = Witness::from_member(approver, &proof, wrong_root, canonical_proposal_id());
    assert!(
        w.try_prove().is_err(),
        "real member proof must NOT verify under a fabricated members_root"
    );

    // And: an entirely unrelated root (all 0xFF) — same outcome.
    let w2 = Witness::from_member(approver, &proof, [0xFFu8; 32], canonical_proposal_id());
    assert!(
        w2.try_prove().is_err(),
        "real member proof must NOT verify under an all-0xFF members_root"
    );
}

// ---------------------------------------------------------------------------
// 3. Flip a single bit of a sibling in an otherwise valid path.
// ---------------------------------------------------------------------------

#[test]
fn red_tampered_sibling_bit_fails() {
    ensure_dev_mode();
    let (_approver, mut w, _pid) = happy_witness(2);
    // Mutate sibling at level 0, byte 0, bit 0.
    w.siblings_flat[0] ^= 0x01;
    assert!(
        w.try_prove().is_err(),
        "tampered sibling (single bit flip) must NOT produce a receipt"
    );
}

// ---------------------------------------------------------------------------
// 4. Flip one direction byte (0↔1) in an otherwise valid path.
// ---------------------------------------------------------------------------

#[test]
fn red_tampered_direction_bit_fails() {
    ensure_dev_mode();
    let (_approver, mut w, _pid) = happy_witness(3);
    // The honest direction byte for level 0 is `index & 1`. Flip whichever
    // value it currently holds (0↔1 stays in the valid 0/1 range, so the
    // guest's strict check accepts it as well-formed; the Merkle verifier
    // then rejects because the recombination order is wrong).
    w.direction_bytes[0] ^= 1;
    assert!(
        w.try_prove().is_err(),
        "tampered direction byte (0↔1) must NOT produce a receipt"
    );
}

// ---------------------------------------------------------------------------
// 5. Direction byte outside {0, 1}. The guest has an explicit strict check.
// ---------------------------------------------------------------------------

#[test]
fn red_invalid_direction_byte_fails() {
    ensure_dev_mode();
    let (_approver, w, _pid) = happy_witness(0);
    // Try a few illegal values; the guest must reject every one.
    for bad in [2u8, 3, 0x7F, 0xFF] {
        let mut tampered = w.direction_bytes;
        tampered[5] = bad;
        let w2 = Witness {
            public_prefix: w.public_prefix,
            sk: w.sk,
            salt: w.salt,
            siblings_flat: w.siblings_flat,
            direction_bytes: tampered,
        };
        assert!(
            w2.try_prove().is_err(),
            "direction byte = {bad} must trip the strict-0-or-1 panic in the guest"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Same (sk, salt, members_root) but different proposal_id ⇒ different
//    nullifier in the journal.
// ---------------------------------------------------------------------------

#[test]
fn red_proposal_id_substitution_changes_nullifier_in_journal() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let i = 2usize;
    let approver = &members[i];
    let proof = tree.proof(i).unwrap();

    // Two distinct proposals.
    let pid_a = canonical_proposal_id();
    let pid_b: [u8; 32] = {
        let program_id: [u8; 32] = [0x99; 32];
        let create_key: [u8; 32] = [0xAB; 32];
        let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
        let target_program: [u8; 32] = [0xCD; 32];
        derive_proposal_id(
            &ChainId::from_u64(0xABCD_EF01),
            &state_pda,
            1, // index 1 — different proposal slot
            b"treasury_withdraw(200,recipient=0xABCD)",
            &target_program,
        )
    };
    assert_ne!(pid_a, pid_b, "test setup: pid_a and pid_b must differ");

    let wa = Witness::from_member(approver, &proof, tree.root(), pid_a);
    let wb = Witness::from_member(approver, &proof, tree.root(), pid_b);

    let ra = wa.try_prove().expect("happy path a must prove");
    let rb = wb.try_prove().expect("happy path b must prove");

    let ja = {
        let mut buf = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        buf.copy_from_slice(ra.journal.bytes.as_slice());
        ApprovePublicInputs::from_bytes(&buf)
    };
    let jb = {
        let mut buf = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        buf.copy_from_slice(rb.journal.bytes.as_slice());
        ApprovePublicInputs::from_bytes(&buf)
    };

    assert_eq!(ja.members_root, jb.members_root, "shared member set");
    assert_eq!(ja.members_root, tree.root());
    assert_ne!(
        ja.proposal_id, jb.proposal_id,
        "distinct proposal_id committed"
    );
    assert_eq!(ja.proposal_id, pid_a);
    assert_eq!(jb.proposal_id, pid_b);
    assert_ne!(
        ja.nullifier, jb.nullifier,
        "distinct proposal_id MUST yield distinct nullifier under SHA-256"
    );

    // Cross-check against host computation of the nullifier.
    let host_null_a = approver.nullifier::<Sha256Hasher>(&pid_a);
    let host_null_b = approver.nullifier::<Sha256Hasher>(&pid_b);
    assert_eq!(ja.nullifier, host_null_a);
    assert_eq!(jb.nullifier, host_null_b);
}

// ---------------------------------------------------------------------------
// 7. The 96-byte journal must NOT leak the secret material.
// ---------------------------------------------------------------------------

#[test]
fn red_journal_does_not_leak_sk() {
    ensure_dev_mode();
    let (approver, w, pid) = happy_witness(2);
    let receipt = w.try_prove().expect("happy path must prove");
    let journal = receipt.journal.bytes.clone();
    assert_eq!(
        journal.len(),
        APPROVE_PUBLIC_INPUTS_LEN,
        "journal must be the canonical 96 bytes"
    );

    // The secret material as full 32-byte sequences must not appear in the
    // 96-byte journal. (A length-32 needle in a length-96 haystack — only
    // ~65 possible starting positions, so this is a real check.)
    let sk = approver.sk;
    let salt = approver.salt;

    fn contains_slice(hay: &[u8], needle: &[u8]) -> bool {
        if needle.len() > hay.len() {
            return false;
        }
        hay.windows(needle.len()).any(|w| w == needle)
    }

    assert!(
        !contains_slice(&journal, &sk),
        "FINDING: sk bytes leak into the journal"
    );
    assert!(
        !contains_slice(&journal, &salt),
        "FINDING: salt bytes leak into the journal"
    );
    // Each Merkle sibling must also not appear verbatim — they're sampled
    // from the empty-marker chain in this test, so they have non-trivial
    // entropy.
    for level in 0..MERKLE_DEPTH {
        let sib = &w.siblings_flat[level * HASH_LEN..(level + 1) * HASH_LEN];
        assert!(
            !contains_slice(&journal, sib),
            "FINDING: Merkle sibling at level {level} leaks into the journal"
        );
    }

    // Sanity: the public parts that SHOULD be in the journal really are.
    let bundle = {
        let mut buf = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        buf.copy_from_slice(&journal);
        ApprovePublicInputs::from_bytes(&buf)
    };
    assert!(contains_slice(&journal, &bundle.members_root));
    assert!(contains_slice(&journal, &pid));
    assert!(contains_slice(&journal, &bundle.nullifier));
}

// ---------------------------------------------------------------------------
// 8. FINDING-1b at the circuit layer: try the zero-leaf forgery.
// ---------------------------------------------------------------------------

#[test]
fn red_zero_leaf_witness_fails_finding_1b_at_circuit_layer() {
    ensure_dev_mode();
    let (_members, tree) = build_member_set();

    // (a) sk = [0;32], salt = [0;32]: commitment is `H([0;64])`, which is
    // non-zero, so this does NOT actually reach the FINDING-1b verify_proof
    // guard. But the leaf is also not in the member tree — confirm the
    // guest fails for that independent reason.
    let zero_id = Identity::new([0u8; 32], [0u8; 32]);
    let proof = crypto::MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    let w = Witness::from_member(&zero_id, &proof, tree.root(), canonical_proposal_id());
    assert!(
        w.try_prove().is_err(),
        "all-zero identity must not pass membership check"
    );

    // (b) Cannot construct (sk, salt) such that H(sk‖salt) == [0;32] without
    // breaking SHA-256 preimage resistance. Confirm infeasibility under a
    // small random sample: a deterministic mini-search of 2000 (sk, salt)
    // pairs must not hit the all-zero commitment.
    let mut nonce: u64 = 0;
    for _ in 0..2000 {
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        sk[..8].copy_from_slice(&nonce.to_le_bytes());
        salt[..8].copy_from_slice(&nonce.wrapping_mul(2_654_435_761).to_le_bytes());
        nonce = nonce.wrapping_add(1);
        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();
        assert_ne!(
            *c.as_bytes(),
            [0u8; HASH_LEN],
            "extremely unlikely: random (sk,salt) hashed to all-zero commitment"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. Truncated witness: drop a byte. Find what actually happens.
// ---------------------------------------------------------------------------

#[test]
fn red_truncated_witness_fails() {
    ensure_dev_mode();
    let (_approver, w, _pid) = happy_witness(0);

    // Build env with one byte missing from the trailing direction buffer.
    // The honest witness writes 5 slices: public(64) + sk(32) + salt(32) +
    // sibs(640) + dirs(20). Trim the last slice to 19 bytes — the guest's
    // last `read_slice(&mut direction_buf[20])` will under-fill, which is
    // exactly what we want to pin.
    let env_builder = ExecutorEnv::builder()
        .write_slice(&w.public_prefix)
        .write_slice(&w.sk)
        .write_slice(&w.salt)
        .write_slice(&w.siblings_flat)
        .write_slice(&w.direction_bytes[..MERKLE_DEPTH - 1])
        .build();
    // The env-builder itself may or may not error here; both outcomes
    // are acceptable. What we care about is that NO valid receipt can be
    // produced from a truncated witness.
    let truncated_proved = match env_builder {
        Ok(env_ok) => default_prover()
            .prove(env_ok, APPROVE_CIRCUIT_ELF)
            .ok()
            .map(|info| info.receipt),
        Err(_) => None,
    };
    if let Some(receipt) = truncated_proved {
        // Extremely unlikely; if it ever happens, FAIL LOUDLY rather than
        // silently accept whatever junk the guest read.
        receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .expect_err("FINDING: truncated witness produced a verifiable receipt");
    }

    // Same again, but trimming a byte off the siblings buffer (mid-stream
    // truncation). The guest's later read_slice on direction_buf would
    // pull what's left, but the bytes are off-by-one.
    let env_builder2 = ExecutorEnv::builder()
        .write_slice(&w.public_prefix)
        .write_slice(&w.sk)
        .write_slice(&w.salt)
        .write_slice(&w.siblings_flat[..w.siblings_flat.len() - 1])
        .write_slice(&w.direction_bytes)
        .build();
    let truncated_proved2 = match env_builder2 {
        Ok(env_ok) => default_prover()
            .prove(env_ok, APPROVE_CIRCUIT_ELF)
            .ok()
            .map(|info| info.receipt),
        Err(_) => None,
    };
    if let Some(receipt) = truncated_proved2 {
        receipt
            .verify(APPROVE_CIRCUIT_IMAGE_ID)
            .expect_err("FINDING: mid-stream-truncated witness produced a verifiable receipt");
    }
}

// ---------------------------------------------------------------------------
// 10. Swap (sk, salt). Commitment becomes H(salt‖sk) ≠ H(sk‖salt).
// ---------------------------------------------------------------------------

#[test]
fn red_swapped_sk_salt_fails() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let i = 4usize;
    let real = &members[i];
    // Ensure sk != salt (otherwise the swap is a no-op).
    assert_ne!(real.sk, real.salt, "test pre: sk and salt must differ");
    let proof = tree.proof(i).unwrap();

    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&tree.root());
    public_prefix[32..].copy_from_slice(&canonical_proposal_id());

    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    // Swapped: write salt where sk goes, sk where salt goes.
    let env_builder = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&real.salt) // sk slot
        .write_slice(&real.sk) // salt slot
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build();
    let result = match env_builder {
        Ok(b) => default_prover().prove(b, APPROVE_CIRCUIT_ELF).ok(),
        Err(_) => None,
    };
    assert!(
        result.is_none(),
        "swapping sk and salt yields a different commitment and must fail membership"
    );
}

// ---------------------------------------------------------------------------
// 11. Member 2's (sk, salt) with member 3's Merkle proof.
// ---------------------------------------------------------------------------

#[test]
fn red_member_at_wrong_index_proof_fails() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let m2 = &members[2];
    let proof_m3 = tree.proof(3).unwrap();

    let w = Witness::from_member(m2, &proof_m3, tree.root(), canonical_proposal_id());
    assert!(
        w.try_prove().is_err(),
        "member-2 commitment with member-3 path targets the wrong leaf slot"
    );
}

// ---------------------------------------------------------------------------
// 12. Receipt verification with a deliberately wrong image-id.
// ---------------------------------------------------------------------------

#[test]
fn red_image_id_mismatch_rejected() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);
    let receipt = w.try_prove().expect("happy path must prove");

    // Sanity: verifies under the real image-id.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("happy path must verify under the real image-id");

    // All-zero image-id: must NOT verify.
    let zero_id: [u32; 8] = [0u32; 8];
    assert!(
        receipt.verify(zero_id).is_err(),
        "receipt must NOT verify against the all-zero image-id"
    );

    // Bitwise-NOT of the real image-id: must NOT verify.
    let mut not_id = APPROVE_CIRCUIT_IMAGE_ID;
    for w in not_id.iter_mut() {
        *w = !*w;
    }
    // (Astronomically unlikely the NOT-id collides with the real id, but
    // guard against it anyway so the assertion is meaningful.)
    if not_id != APPROVE_CIRCUIT_IMAGE_ID {
        assert!(
            receipt.verify(not_id).is_err(),
            "receipt must NOT verify against the bitwise-NOT image-id"
        );
    }

    // Single-bit flip of the real id: must NOT verify.
    let mut flipped = APPROVE_CIRCUIT_IMAGE_ID;
    flipped[0] ^= 1;
    assert!(
        receipt.verify(flipped).is_err(),
        "receipt must NOT verify against a one-bit-off image-id"
    );
}

// ---------------------------------------------------------------------------
// 13. Creative: bit-flip the journal AFTER proving, verification must fail.
//
//     Premise: the verifier's contract ties the receipt to the journal hash
//     baked into the seal. If an attacker grabs a valid receipt and mutates
//     even one journal byte (e.g., changes the committed `nullifier` so it
//     hashes to a different on-chain `NullifierEntry` slot and bypasses
//     double-spend detection), `verify(image_id)` MUST reject. Pin that.
// ---------------------------------------------------------------------------

#[test]
fn red_creative_journal_bit_flip_breaks_verification() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(1);
    let mut receipt = w.try_prove().expect("happy path must prove");

    // Cache the original journal so we can restore it for comparison.
    let original = receipt.journal.bytes.clone();
    assert_eq!(original.len(), APPROVE_PUBLIC_INPUTS_LEN);

    // Mutate the nullifier region (bytes 64..96) — flip a single bit.
    receipt.journal.bytes[80] ^= 0x01;
    assert!(
        receipt.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
        "FINDING: receipt verifies against image-id after journal nullifier was tampered"
    );

    // Restore and confirm the receipt is otherwise valid.
    receipt.journal.bytes = original;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("restored journal must re-verify cleanly");

    // Also try mutating the members_root region (bytes 0..32).
    receipt.journal.bytes[0] ^= 0x80;
    assert!(
        receipt.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
        "FINDING: receipt verifies against image-id after journal members_root was tampered"
    );
}
