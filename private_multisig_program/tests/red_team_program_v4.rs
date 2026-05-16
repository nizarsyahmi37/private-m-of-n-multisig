//! Red-team validation (round 4) of the LP-0002 Risc0 approve circuit
//! and program crate.
//!
//! Rounds 1, 2, and 3 produced zero new findings across 37 adversarial
//! tests, and the crypto + core layers have had four rounds each — fully
//! exhausted. The one piece of legitimate residual surface is the new
//! `pack_approve_witness` helper plus its `APPROVE_WITNESS_LEN` constant
//! that landed in round 3. The round-3 unit tests in `src/lib.rs` cover
//! only a tiny subset of the helper's adversarial surface; everything
//! below is dedicated to attacking that helper from every angle a
//! downstream SDK or on-chain integrator might trip on.
//!
//! Index of tests in this file:
//!
//!   1.  `red4_pack_witness_byte_exact_against_handcomputed_fixture`
//!   2.  `red4_pack_witness_parity_with_5_writeslice_path`
//!   3.  `red4_pack_witness_zero_sk_zero_salt_prove_must_fail`
//!   4.  `red4_pack_witness_swapped_siblings_both_fail`
//!   5.  `red4_approve_witness_len_constant_audit`
//!   6.  `red4_pack_witness_slot_boundary_sweep`
//!   7.  `red4_pack_witness_all_directions_true_pinned_layout`
//!   8.  `red4_pack_witness_no_silent_truncation_or_padding`
//!   9.  `red4_pack_witness_cross_call_determinism_100x`
//!   10. `red4_pack_witness_tight_loop_no_panic_no_drift`     (allocation-free observation)
//!   11. `red4_pack_witness_helper_purity_does_not_mutate_inputs`
//!   12. `red4_pack_witness_does_not_leak_sk_outside_offset_64_96`
//!   13. `red4_pack_witness_does_not_leak_salt_outside_offset_96_128`
//!   14. `red4_pack_witness_root_and_pid_appear_only_in_their_slots`
//!   15. `red4_creative_pack_witness_field_collision_search`   (own attack)
//!
//! All prover tests set `RISC0_DEV_MODE=1` for speed.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::similar_names)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::cognitive_complexity)]

use std::env;

use crypto::{
    merkle::MerkleProof, Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH, SALT_LEN,
    SK_LEN,
};
use private_multisig_core::{derive_proposal_id, ChainId};
use private_multisig_program::{
    pack_approve_witness, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID, APPROVE_WITNESS_LEN,
};
use risc0_zkvm::{default_prover, ExecutorEnv};

// ---------------------------------------------------------------------------
// Shared scaffolding — each tests/*.rs is its own crate, so each file owns
// its helpers independently.
// ---------------------------------------------------------------------------

fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: same pattern as red_team_program{,_v2,_v3}.rs. cargo runs
        // each #[test] in its own thread but env mutation happens before
        // the prover spawns its own worker threads.
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

fn build_member_set() -> (Vec<Identity>, MerkleTree<Sha256Hasher>) {
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    (members, tree)
}

fn canonical_proposal_id() -> [u8; 32] {
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program)
}

/// Locate every starting offset where `needle` appears in `haystack`. Used
/// by the leak-surface tests to ensure secret bytes appear in exactly one
/// place in the packed buffer.
fn find_all_offsets(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
        }
    }
    out
}

// ===========================================================================
// 1. Hand-compute the expected 788 bytes for a fully-distinguishable known
//    witness and assert byte-equal. The round-3 unit test
//    `pack_approve_witness_layout_pins_each_slot` only spot-checks five
//    offsets; this sweeps EVERY byte position with a fixture where each
//    field carries a unique constant pattern.
// ===========================================================================

#[test]
fn red4_pack_witness_byte_exact_against_handcomputed_fixture() {
    // Distinguishable patterns: each field's bytes are constant and disjoint
    // from every other field's, so a slot-offset bug would be visible byte-
    // for-byte.
    let members_root: [u8; 32] = [0x11; 32];
    let proposal_id: [u8; 32] = [0x22; 32];
    let identity = Identity::new([0x33; 32], [0x44; 32]);

    // Siblings: level `L` -> byte = `0x50 + L`. All 32 bytes in level L hold
    // the same value `0x50 + L`. Levels 0..=19 ⇒ 0x50..=0x63 — all distinct
    // and never colliding with 0x11/0x22/0x33/0x44 or the {0,1} directions.
    let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
    for (level, sib) in siblings.iter_mut().enumerate() {
        let v = 0x50u8.wrapping_add(level as u8);
        for b in sib.iter_mut() {
            *b = v;
        }
    }
    // Alternating directions so the 20-byte tail is non-uniform and any
    // off-by-one in the indices write would show as a visible swap.
    let mut indices = [false; MERKLE_DEPTH];
    for (i, bit) in indices.iter_mut().enumerate() {
        *bit = i % 2 == 0;
    }
    let proof = MerkleProof { siblings, indices };

    // Hand-pack. We write each field via a different loop so no piece of
    // logic is shared with `pack_approve_witness` other than the spec itself.
    let mut expected = [0u8; APPROVE_WITNESS_LEN];
    for i in 0..32 {
        expected[i] = members_root[i];
    }
    for i in 0..32 {
        expected[32 + i] = proposal_id[i];
    }
    for i in 0..32 {
        expected[64 + i] = identity.sk[i];
    }
    for i in 0..32 {
        expected[96 + i] = identity.salt[i];
    }
    for level in 0..MERKLE_DEPTH {
        for byte in 0..32 {
            expected[128 + level * 32 + byte] = siblings[level][byte];
        }
    }
    for level in 0..MERKLE_DEPTH {
        expected[768 + level] = u8::from(indices[level]);
    }

    let actual = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

    // Byte-by-byte sweep with informative messages so any single divergence
    // points to the exact offset.
    assert_eq!(actual.len(), 788);
    assert_eq!(actual.len(), APPROVE_WITNESS_LEN);
    for i in 0..APPROVE_WITNESS_LEN {
        assert_eq!(
            actual[i], expected[i],
            "byte mismatch at offset {i}: helper={:#04x}, hand-computed={:#04x}",
            actual[i], expected[i]
        );
    }
    // And the trivial whole-buffer equality for completeness.
    assert_eq!(actual.as_slice(), expected.as_slice());
}

// ===========================================================================
// 2. Byte-order parity with the existing 5 × write_slice path. Pack via the
//    helper, then prove BOTH paths against the same logical inputs and
//    compare receipts. Journals must be byte-identical. This is the
//    canonical "future refactor of write_slice → helper must not silently
//    change wire bytes" canary at the prover layer.
// ===========================================================================

#[test]
fn red4_pack_witness_parity_with_5_writeslice_path() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let pid = canonical_proposal_id();

    // Path A — single 788-byte write_slice via the new helper.
    let packed = pack_approve_witness(approver, &proof, &members_root, &pid);
    let env_a = ExecutorEnv::builder()
        .write_slice(&packed)
        .build()
        .expect("env A build");
    let receipt_a = default_prover()
        .prove(env_a, APPROVE_CIRCUIT_ELF)
        .expect("path A prove")
        .receipt;
    receipt_a
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("path A verify");

    // Path B — five write_slice calls, matching what the SDK does today.
    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&members_root);
    public_prefix[32..].copy_from_slice(&pid);
    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }
    let env_b = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&approver.sk)
        .write_slice(&approver.salt)
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build()
        .expect("env B build");
    let receipt_b = default_prover()
        .prove(env_b, APPROVE_CIRCUIT_ELF)
        .expect("path B prove")
        .receipt;
    receipt_b
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("path B verify");

    // Cross-check: the journals must be byte-identical. Receipt envelopes
    // may differ (since they're separate prover invocations) but the
    // *journal* — bound to the guest's commitments — is identical iff the
    // wire bytes the guest read were identical.
    assert_eq!(
        receipt_a.journal.bytes, receipt_b.journal.bytes,
        "FINDING: helper-packed and 5-call-packed paths produced divergent journals"
    );

    // And: the hand-flattened wire bytes equal the helper output. This is
    // already pinned in `witness_wire_format::wire_round_trip_repack_via_independent_packer`
    // at the SDK-internal packer; here we pin it for the public helper.
    let mut hand_flat = [0u8; APPROVE_WITNESS_LEN];
    hand_flat[..64].copy_from_slice(&public_prefix);
    hand_flat[64..96].copy_from_slice(&approver.sk);
    hand_flat[96..128].copy_from_slice(&approver.salt);
    hand_flat[128..768].copy_from_slice(&siblings_flat);
    hand_flat[768..788].copy_from_slice(&direction_bytes);
    assert_eq!(hand_flat, packed, "helper output diverges from hand-flatten");
}

// ===========================================================================
// 3. sk and salt both all-zero. The helper does not validate inputs — it's
//    a pure packer. So the buffer will be well-formed but the guest's
//    membership check should reject because the resulting commitment
//    H(0^32 || 0^32) is NOT in any honest tree this test builds.
// ===========================================================================

#[test]
fn red4_pack_witness_zero_sk_zero_salt_prove_must_fail() {
    ensure_dev_mode();

    // Honest tree + a real proof for member 2, used as the sibling chain
    // the attacker would PRETEND to use. With sk=salt=0 the leaf commitment
    // is H(0||0) which equals a deterministic SHA-256 digest — not the
    // honest leaf, so the path won't climb to the real root.
    let (_members, tree) = build_member_set();
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let pid = canonical_proposal_id();
    let zero_identity = Identity::new([0u8; 32], [0u8; 32]);

    let packed = pack_approve_witness(&zero_identity, &proof, &members_root, &pid);

    // Sanity: the helper still produced 788 bytes with the zero sk/salt
    // at their canonical offsets.
    assert_eq!(packed.len(), APPROVE_WITNESS_LEN);
    assert_eq!(&packed[64..96], &[0u8; 32]);
    assert_eq!(&packed[96..128], &[0u8; 32]);

    let env_built = ExecutorEnv::builder()
        .write_slice(&packed)
        .build()
        .expect("env build");
    let result = default_prover().prove(env_built, APPROVE_CIRCUIT_ELF);
    assert!(
        result.is_err(),
        "FINDING: prove succeeded with sk=salt=0 against an honest members_root"
    );

    // And as a positive cross-check: the commitment H(0||0) really IS
    // non-zero (preimage-hard) — so the helper is not "silently producing
    // an empty leaf".
    let zero_commit = zero_identity.commitment::<Sha256Hasher>();
    assert_ne!(
        *zero_commit.as_bytes(),
        [0u8; 32],
        "sanity: H(0||0) must not be all-zero (or SHA-256 is broken)"
    );
}

// ===========================================================================
// 4. Pack two different witnesses for the same (members_root, proposal_id)
//    but with swapped siblings; confirm both fail. This is the "siblings[0]
//    and siblings[1] traded" adversarial check at the helper layer.
// ===========================================================================

#[test]
fn red4_pack_witness_swapped_siblings_both_fail() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let approver = &members[2];
    let real_proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let pid = canonical_proposal_id();

    // Variant A — swap siblings[0] and siblings[1].
    let mut proof_a = real_proof.clone();
    proof_a.siblings.swap(0, 1);
    let packed_a = pack_approve_witness(approver, &proof_a, &members_root, &pid);
    let env_a = ExecutorEnv::builder()
        .write_slice(&packed_a)
        .build()
        .expect("env A build");
    assert!(
        default_prover().prove(env_a, APPROVE_CIRCUIT_ELF).is_err(),
        "FINDING: witness with siblings[0] ⇆ siblings[1] proved against honest root"
    );

    // Variant B — swap siblings[5] and siblings[10] (middle levels).
    let mut proof_b = real_proof.clone();
    proof_b.siblings.swap(5, 10);
    let packed_b = pack_approve_witness(approver, &proof_b, &members_root, &pid);
    let env_b = ExecutorEnv::builder()
        .write_slice(&packed_b)
        .build()
        .expect("env B build");
    assert!(
        default_prover().prove(env_b, APPROVE_CIRCUIT_ELF).is_err(),
        "FINDING: witness with siblings[5] ⇆ siblings[10] proved against honest root"
    );

    // Cross-check: the two packed buffers differ from each other AND from
    // the honest packing, so the swaps aren't no-ops. Skip the equality
    // sentinel only if (astronomically unlikely) two sibling levels happen
    // to be byte-equal.
    let honest = pack_approve_witness(approver, &real_proof, &members_root, &pid);
    if real_proof.siblings[0] != real_proof.siblings[1] {
        assert_ne!(packed_a, honest, "swap A produced identical bytes");
    }
    if real_proof.siblings[5] != real_proof.siblings[10] {
        assert_ne!(packed_b, honest, "swap B produced identical bytes");
    }
}

// ===========================================================================
// 5. APPROVE_WITNESS_LEN constant audit — pin exactly 788; verify against
//    the constituent arithmetic. The round-3 unit test does this but only
//    for one expression; here we expand the audit so a future PR that
//    silently shifts ANY constant (HASH_LEN, MERKLE_DEPTH, SK_LEN, SALT_LEN)
//    while leaving APPROVE_WITNESS_LEN at 788 also fires.
// ===========================================================================

#[test]
fn red4_approve_witness_len_constant_audit() {
    // Direct pin.
    assert_eq!(APPROVE_WITNESS_LEN, 788);

    // Constituent arithmetic — each summand pinned independently.
    let public_prefix = 64usize;
    assert_eq!(public_prefix, 32 + 32, "public prefix = root || pid");
    assert_eq!(SK_LEN, 32);
    assert_eq!(SALT_LEN, 32);
    assert_eq!(MERKLE_DEPTH, 20);
    assert_eq!(HASH_LEN, 32);

    let computed = public_prefix + SK_LEN + SALT_LEN + MERKLE_DEPTH * HASH_LEN + MERKLE_DEPTH;
    assert_eq!(
        computed, APPROVE_WITNESS_LEN,
        "APPROVE_WITNESS_LEN ({}) diverges from constituent arithmetic ({})",
        APPROVE_WITNESS_LEN, computed
    );

    // Alternate form: 64 + 32 + 32 + 20*32 + 20.
    assert_eq!(APPROVE_WITNESS_LEN, 64 + 32 + 32 + 20 * 32 + 20);

    // Helper buffer length must agree.
    let id = Identity::new([0u8; 32], [0u8; 32]);
    let proof = MerkleProof {
        siblings: [[0u8; 32]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    let buf = pack_approve_witness(&id, &proof, &[0u8; 32], &[0u8; 32]);
    assert_eq!(buf.len(), 788);
    assert_eq!(buf.len(), APPROVE_WITNESS_LEN);

    // Type-level sentinel: take the function's return type into a const
    // slot via the buffer length so a return-type change would fail to
    // compile here.
    const _ASSERT_LEN_IS_788: [(); 788] = [(); APPROVE_WITNESS_LEN];
}

// ===========================================================================
// 6. Slot-boundary tests — set each field to a distinguishable constant and
//    confirm the boundary positions (31/32, 63/64, 95/96, 127/128, 767/768)
//    sit exactly where the spec promises.
// ===========================================================================

#[test]
fn red4_pack_witness_slot_boundary_sweep() {
    // Distinguishable fillers — each field's bytes are a unique constant
    // chosen so the boundaries are unambiguous.
    let members_root: [u8; 32] = [0xA1; 32];
    let proposal_id: [u8; 32] = [0xA2; 32];
    let identity = Identity::new([0xA3; 32], [0xA4; 32]);
    // Sibling level L holds 0xB0 + L (so [0..20) = 0xB0..0xC3, all distinct).
    let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
    for (level, sib) in siblings.iter_mut().enumerate() {
        let v = 0xB0u8.wrapping_add(level as u8);
        for b in sib.iter_mut() {
            *b = v;
        }
    }
    // Directions: alternating 1/0 (so bytes 768..788 are 1,0,1,0,...).
    let mut indices = [false; MERKLE_DEPTH];
    for (i, bit) in indices.iter_mut().enumerate() {
        *bit = i % 2 == 0;
    }
    let proof = MerkleProof { siblings, indices };
    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

    // Boundary 31/32: byte 31 belongs to members_root (0xA1), byte 32
    // belongs to proposal_id (0xA2).
    assert_eq!(buf[31], 0xA1, "byte 31 must still be in members_root");
    assert_eq!(buf[32], 0xA2, "byte 32 must be the first proposal_id byte");

    // Boundary 63/64: byte 63 is the last proposal_id (0xA2), byte 64 is
    // the first sk byte (0xA3).
    assert_eq!(buf[63], 0xA2, "byte 63 must still be in proposal_id");
    assert_eq!(buf[64], 0xA3, "byte 64 must be the first sk byte");

    // Boundary 95/96: byte 95 is the last sk byte (0xA3), byte 96 is the
    // first salt byte (0xA4).
    assert_eq!(buf[95], 0xA3, "byte 95 must still be in sk");
    assert_eq!(buf[96], 0xA4, "byte 96 must be the first salt byte");

    // Boundary 127/128: byte 127 is the last salt byte (0xA4), byte 128 is
    // the first siblings byte (level-0 = 0xB0).
    assert_eq!(buf[127], 0xA4, "byte 127 must still be in salt");
    assert_eq!(buf[128], 0xB0, "byte 128 must be siblings[0] byte-0");

    // Boundary at 767/768: byte 767 is the last sibling byte (level-19 =
    // 0xC3), byte 768 is the first direction byte (level-0 = 1 because
    // index 0 % 2 == 0 ⇒ true).
    assert_eq!(buf[767], 0xC3, "byte 767 must still be in siblings (last)");
    assert_eq!(buf[768], 1, "byte 768 must be direction byte for level 0");

    // Buffer end — byte 787 is direction for level 19. Index 19 % 2 == 1 ⇒
    // indices[19] = false ⇒ byte 787 = 0.
    assert_eq!(buf[787], 0, "byte 787 must be direction byte for level 19");

    // No byte past 787 exists (it's a 788-byte array). Sentinel: len.
    assert_eq!(buf.len(), 788);

    // Interior sibling-level boundary sweep: every level L's first byte
    // must be 0xB0+L, every last byte too.
    for level in 0..MERKLE_DEPTH {
        let start = 128 + level * HASH_LEN;
        let end = start + HASH_LEN - 1;
        let v = 0xB0u8.wrapping_add(level as u8);
        assert_eq!(buf[start], v, "level {level} first byte at offset {start}");
        assert_eq!(buf[end], v, "level {level} last byte at offset {end}");
    }
}

// ===========================================================================
// 7. proof.indices = [true; 20] — pack and pin that the direction tail is
//    twenty 0x01 bytes in a row (no off-by-one, no endian quirk).
// ===========================================================================

#[test]
fn red4_pack_witness_all_directions_true_pinned_layout() {
    let members_root: [u8; 32] = [0xC0; 32];
    let proposal_id: [u8; 32] = [0xC1; 32];
    let identity = Identity::new([0xC2; 32], [0xC3; 32]);
    let siblings = [[0u8; 32]; MERKLE_DEPTH];
    let indices = [true; MERKLE_DEPTH];
    let proof = MerkleProof { siblings, indices };

    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);
    assert_eq!(buf.len(), APPROVE_WITNESS_LEN);

    // The 20-byte tail must be exactly twenty 0x01 bytes.
    assert_eq!(&buf[768..788], &[1u8; MERKLE_DEPTH][..]);

    // And the first 768 bytes must NOT contain any 0x01 from a stray write
    // that leaked outside the directions region — the only 0x01 bytes in
    // the first 768 must come from the legitimate field fillers (which are
    // 0xC0, 0xC1, 0xC2, 0xC3, and 0x00 for siblings). None of those is
    // 0x01, so any 0x01 in [0..768) would be a packing bug.
    for (i, b) in buf[..768].iter().enumerate() {
        assert_ne!(
            *b, 0x01,
            "FINDING: stray 0x01 byte at offset {i} — directions write leaked outside tail"
        );
    }
}

// ===========================================================================
// 8. No silent truncation or padding. Fill siblings with non-zero patterns
//    that have known zero-positions (so we can verify zero-positions
//    survive intact), and confirm every byte in [128..768) matches the
//    expected pattern exactly.
// ===========================================================================

#[test]
fn red4_pack_witness_no_silent_truncation_or_padding() {
    let members_root: [u8; 32] = [0x77; 32];
    let proposal_id: [u8; 32] = [0x88; 32];
    let identity = Identity::new([0x99; 32], [0xAA; 32]);

    // Each sibling holds a per-level pattern: byte j of level L = ((L+1) *
    // (j+1)) mod 256. Carefully chosen so:
    //   - level 0 byte 0 = 1
    //   - level 19 byte 31 = 20*32 mod 256 = 640 mod 256 = 128
    //   - many bytes are 0 (where the product mod 256 == 0, e.g., L=15, j=15
    //     gives 16*16=256 mod 256 = 0). We rely on these zero positions
    //     surviving — if the helper truncated or padded, those positions
    //     would be replaced by stray bytes.
    let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        for byte in 0..HASH_LEN {
            siblings[level][byte] = (((level + 1) * (byte + 1)) % 256) as u8;
        }
    }
    let indices = [false; MERKLE_DEPTH];
    let proof = MerkleProof { siblings, indices };

    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

    // Byte-for-byte check across the siblings region.
    for level in 0..MERKLE_DEPTH {
        for byte in 0..HASH_LEN {
            let expected = (((level + 1) * (byte + 1)) % 256) as u8;
            let offset = 128 + level * HASH_LEN + byte;
            assert_eq!(
                buf[offset], expected,
                "siblings byte at L={level} j={byte} (offset {offset}): expected {:#04x}, got {:#04x}",
                expected, buf[offset]
            );
        }
    }

    // The zero-positions in the pattern: confirm at least one exists and
    // survived. (L=15, byte=15) yields 16*16 mod 256 = 0.
    let zero_offset = 128 + 15 * HASH_LEN + 15;
    assert_eq!(
        buf[zero_offset], 0,
        "pattern's zero-position at offset {zero_offset} did not survive — \
         packer may be silently rewriting zero bytes"
    );

    // No padding bytes in the directions tail (we set every index to false
    // = 0, so the tail is twenty zero bytes — but those zeros are LEGIT
    // direction bytes, not padding).
    assert_eq!(&buf[768..788], &[0u8; MERKLE_DEPTH][..]);
}

// ===========================================================================
// 9. Cross-call determinism — pack 100 times with the same inputs; all 100
//    outputs byte-identical. Trivial but pins the "pure function" contract.
// ===========================================================================

#[test]
fn red4_pack_witness_cross_call_determinism_100x() {
    let (members, tree) = build_member_set();
    let approver = &members[3];
    let proof = tree.proof(3).unwrap();
    let members_root = tree.root();
    let pid = canonical_proposal_id();

    let first = pack_approve_witness(approver, &proof, &members_root, &pid);
    for run in 1..100 {
        let buf = pack_approve_witness(approver, &proof, &members_root, &pid);
        assert_eq!(
            buf, first,
            "FINDING: pack_approve_witness drifted on run {run}"
        );
    }
}

// ===========================================================================
// 10. Tight-loop stability — call pack_approve_witness 10_000 times in a
//     row with the same inputs and confirm:
//        - every output is identical to the first,
//        - no panic / abort.
//
//     This is the closest we can come to an "allocation-free" assertion
//     without bringing in a custom allocator hook. Documented as a code-
//     review observation: the function takes refs and writes into a stack
//     `[u8; 788]`, returning by value. The body holds no `Vec`, no `Box`,
//     no `String` — see lib.rs lines 88..102.
// ===========================================================================

#[test]
fn red4_pack_witness_tight_loop_no_panic_no_drift() {
    let (members, tree) = build_member_set();
    let approver = &members[1];
    let proof = tree.proof(1).unwrap();
    let members_root = tree.root();
    let pid = canonical_proposal_id();

    let first = pack_approve_witness(approver, &proof, &members_root, &pid);

    // Tight loop. 10k iterations is fast enough to not slow the suite
    // noticeably (each call is just memcpy'ing 788 bytes).
    let mut last_xor = [0u8; APPROVE_WITNESS_LEN];
    for i in 0..10_000usize {
        let buf = pack_approve_witness(approver, &proof, &members_root, &pid);
        if buf != first {
            panic!("FINDING: tight-loop drift at iteration {i}");
        }
        // XOR accumulator so the compiler can't elide the loop body. After
        // 10_000 iterations with identical inputs, the XOR alternates: at
        // even iteration counts last_xor == 0, at odd it equals `first`.
        for j in 0..APPROVE_WITNESS_LEN {
            last_xor[j] ^= buf[j];
        }
    }
    // 10_000 is even, so the XOR accumulator must end up all-zero.
    assert_eq!(
        last_xor, [0u8; APPROVE_WITNESS_LEN],
        "XOR accumulator drifted — either the loop was elided or buffers differed"
    );
}

// ===========================================================================
// 11. Helper purity — calling pack_approve_witness must not mutate any of
//     its reference arguments. Take a deep snapshot of every input, call
//     the helper, and confirm the inputs are byte-identical afterwards.
// ===========================================================================

#[test]
fn red4_pack_witness_helper_purity_does_not_mutate_inputs() {
    let (members, tree) = build_member_set();
    let approver = members[2].clone();
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let pid = canonical_proposal_id();

    // Snapshots BEFORE the call.
    let snap_sk = approver.sk;
    let snap_salt = approver.salt;
    let snap_siblings = proof.siblings;
    let snap_indices = proof.indices;
    let snap_root = members_root;
    let snap_pid = pid;

    let _ = pack_approve_witness(&approver, &proof, &members_root, &pid);

    // Snapshots AFTER.
    assert_eq!(approver.sk, snap_sk, "FINDING: helper mutated sk");
    assert_eq!(approver.salt, snap_salt, "FINDING: helper mutated salt");
    assert_eq!(proof.siblings, snap_siblings, "FINDING: helper mutated siblings");
    assert_eq!(proof.indices, snap_indices, "FINDING: helper mutated indices");
    assert_eq!(members_root, snap_root, "FINDING: helper mutated members_root");
    assert_eq!(pid, snap_pid, "FINDING: helper mutated proposal_id");

    // And: call it again and confirm same output (purity).
    let a = pack_approve_witness(&approver, &proof, &members_root, &pid);
    let b = pack_approve_witness(&approver, &proof, &members_root, &pid);
    assert_eq!(a, b, "FINDING: helper is not pure across calls");
}

// ===========================================================================
// 12. sk leak surface — set sk = [0x42; 32], scan the 788-byte output for
//     all occurrences of the 32-byte pattern, and confirm it appears
//     exactly ONCE, starting at offset 64. This catches any accidental
//     double-write (e.g. sk written into the siblings region by a
//     copy/paste bug).
// ===========================================================================

#[test]
fn red4_pack_witness_does_not_leak_sk_outside_offset_64_96() {
    // Choose sk/salt/root/pid/sib patterns that are mutually disjoint and
    // never accidentally form a substring of each other.
    let sk: [u8; 32] = [0x42; 32];
    let salt: [u8; 32] = [0x55; 32];
    let members_root: [u8; 32] = [0x66; 32];
    let proposal_id: [u8; 32] = [0x77; 32];
    let identity = Identity::new(sk, salt);

    // Fill siblings with per-level distinct patterns that are NOT a
    // repetition of any single byte — so no 32-byte sub-window collides
    // with `sk = [0x42; 32]`.
    let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        for byte in 0..HASH_LEN {
            siblings[level][byte] = ((level * 32 + byte) % 256) as u8;
        }
    }
    let indices = [false; MERKLE_DEPTH];
    let proof = MerkleProof { siblings, indices };

    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

    let offsets = find_all_offsets(&buf, &sk);
    assert_eq!(
        offsets,
        vec![64],
        "FINDING: sk = [0x42; 32] appears at offsets {:?}; should be ONLY at offset 64",
        offsets
    );
}

// ===========================================================================
// 13. salt leak surface — same idea as test 12 for salt at [96..128).
// ===========================================================================

#[test]
fn red4_pack_witness_does_not_leak_salt_outside_offset_96_128() {
    let sk: [u8; 32] = [0x11; 32];
    let salt: [u8; 32] = [0x42; 32];
    let members_root: [u8; 32] = [0x66; 32];
    let proposal_id: [u8; 32] = [0x77; 32];
    let identity = Identity::new(sk, salt);

    let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        for byte in 0..HASH_LEN {
            siblings[level][byte] = ((level * 32 + byte + 1) % 256) as u8;
        }
    }
    let indices = [false; MERKLE_DEPTH];
    let proof = MerkleProof { siblings, indices };

    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

    let offsets = find_all_offsets(&buf, &salt);
    assert_eq!(
        offsets,
        vec![96],
        "FINDING: salt = [0x42; 32] appears at offsets {:?}; should be ONLY at offset 96",
        offsets
    );
}

// ===========================================================================
// 14. members_root and proposal_id leak surface — pin each appears ONLY at
//     its canonical offset [0..32) and [32..64), respectively.
// ===========================================================================

#[test]
fn red4_pack_witness_root_and_pid_appear_only_in_their_slots() {
    let members_root: [u8; 32] = [0x42; 32];
    let proposal_id: [u8; 32] = [0x53; 32];
    let sk: [u8; 32] = [0x64; 32];
    let salt: [u8; 32] = [0x75; 32];
    let identity = Identity::new(sk, salt);

    let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        for byte in 0..HASH_LEN {
            siblings[level][byte] = ((level * 17 + byte * 31 + 1) % 256) as u8;
        }
    }
    let indices = [false; MERKLE_DEPTH];
    let proof = MerkleProof { siblings, indices };

    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

    let root_offsets = find_all_offsets(&buf, &members_root);
    assert_eq!(
        root_offsets,
        vec![0],
        "FINDING: members_root appears at offsets {:?}; should be ONLY at offset 0",
        root_offsets
    );
    let pid_offsets = find_all_offsets(&buf, &proposal_id);
    assert_eq!(
        pid_offsets,
        vec![32],
        "FINDING: proposal_id appears at offsets {:?}; should be ONLY at offset 32",
        pid_offsets
    );
}

// ===========================================================================
// 15. CREATIVE — "non-contiguous-collision field placement". Build a
//     witness whose members_root, sk, salt, and ONE non-adjacent sibling
//     all share the same byte pattern, separated by distinct fillers in
//     between. The helper must STILL place exactly one copy at each
//     designated offset — it must NOT, e.g., short-circuit and skip a
//     write when the source/destination happen to share bytes, nor must
//     it bleed the pattern into the divider regions.
//
//     Concretely:
//       members_root = [0x42; 32]   → offset 0
//       proposal_id  = [0xFE; 32]   → offset 32 (disjoint filler)
//       sk           = [0x42; 32]   → offset 64
//       salt         = [0xFD; 32]   → offset 96 (disjoint filler)
//       siblings[0]  = [0xE0; 32]   → offset 128 (disjoint filler)
//       siblings[1]  = [0x42; 32]   → offset 160
//       siblings[L]  for L >= 2     → 0xA0 + L (each disjoint from 0x42)
//
//     Then: the byte pattern [0x42; 32] must appear at EXACTLY three
//     non-adjacent offsets: 0, 64, 160. Each separated by a 32-byte block
//     of NON-0x42 bytes. There is NO way for a 32-byte 0x42 window to
//     span two of these without containing a non-0x42 byte in between, so
//     the substring-occurrence count is unambiguous.
//
//     If the packer accidentally elided a write, the count is < 3.
//     If it wrote a field into the wrong slot, an unexpected slot appears.
//     If it bled across a boundary, a divider byte gets changed and the
//     filler pin fires.
// ===========================================================================

#[test]
fn red4_creative_pack_witness_field_collision_search() {
    let members_root: [u8; 32] = [0x42; 32];
    let proposal_id: [u8; 32] = [0xFE; 32];
    let sk: [u8; 32] = [0x42; 32];
    let salt: [u8; 32] = [0xFD; 32];
    let identity = Identity::new(sk, salt);

    let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
    // Level 0: disjoint divider so siblings[1]'s 0x42 block doesn't merge
    // with anything to its left.
    for b in siblings[0].iter_mut() {
        *b = 0xE0;
    }
    // Level 1: another 0x42 block — separated from sk by salt (0xFD) AND
    // from siblings[2..] by the per-level 0xA0+L bytes (all != 0x42).
    for b in siblings[1].iter_mut() {
        *b = 0x42;
    }
    for level in 2..MERKLE_DEPTH {
        let v = 0xA0u8.wrapping_add(level as u8);
        for b in siblings[level].iter_mut() {
            *b = v;
        }
    }
    let indices = [false; MERKLE_DEPTH];
    let proof = MerkleProof { siblings, indices };

    let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

    // EXACTLY three non-adjacent 32-byte 0x42 blocks: members_root at 0,
    // sk at 64, siblings[1] at 160. Each surrounded by NON-0x42 bytes on
    // both sides, so the 32-byte window has no other valid start position.
    let occ = find_all_offsets(&buf, &[0x42u8; 32]);
    assert_eq!(
        occ,
        vec![0, 64, 160],
        "FINDING: 0x42-pattern occurrences = {:?}; expected exactly [0, 64, 160]",
        occ
    );

    // Field placements untouched by the collision.
    assert_eq!(&buf[..32], &members_root[..]);
    assert_eq!(&buf[32..64], &proposal_id[..]);
    assert_eq!(&buf[64..96], &sk[..]);
    assert_eq!(&buf[96..128], &salt[..]);
    // Divider sibling at level 0.
    assert_eq!(&buf[128..160], &[0xE0u8; 32][..]);
    // Collision sibling at level 1.
    assert_eq!(&buf[160..192], &[0x42u8; 32][..]);
    // Per-level fillers at levels 2..20 — each survives intact.
    for level in 2..MERKLE_DEPTH {
        let v = 0xA0u8.wrapping_add(level as u8);
        let start = 128 + level * HASH_LEN;
        for byte in 0..HASH_LEN {
            assert_eq!(
                buf[start + byte],
                v,
                "level {level} byte {byte} (offset {}) corrupted: got {:#04x}, expected {:#04x}",
                start + byte,
                buf[start + byte],
                v
            );
        }
    }

    // No 0x42 byte must appear in the divider regions: bytes
    // [32..64) = pid (0xFE), [96..128) = salt (0xFD), [128..160) = sib0 (0xE0).
    for off in 32..64 {
        assert_ne!(buf[off], 0x42, "FINDING: stray 0x42 in proposal_id region at offset {off}");
    }
    for off in 96..128 {
        assert_ne!(buf[off], 0x42, "FINDING: stray 0x42 in salt region at offset {off}");
    }
    for off in 128..160 {
        assert_ne!(buf[off], 0x42, "FINDING: stray 0x42 in siblings[0] region at offset {off}");
    }
    for off in 192..768 {
        assert_ne!(
            buf[off], 0x42,
            "FINDING: stray 0x42 in siblings[2..] region at offset {off}"
        );
    }
    // Directions tail must be twenty zero bytes.
    assert_eq!(&buf[768..788], &[0u8; MERKLE_DEPTH][..]);
}
