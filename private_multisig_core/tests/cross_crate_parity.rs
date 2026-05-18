//! Cross-crate bridge parity tests.
//!
//! Validates that `crypto` (foundation primitives) and `private_multisig_core`
//! (shared types) agree byte-for-byte at every interface point. Each named
//! test pins one specific bridge: PDA derivation, `proposal_id` computation,
//! nullifier wiring, public-input packing, hash lengths, domain-separation
//! discipline, action/target hashing, preimage byte layout, `ChainId` lifting,
//! and known-answer vectors.
//!
//! If `crypto` or `core` ever drift from each other or from the spec, the
//! Risc0 guest, the on-chain verifier, and the SDK will compute different
//! `proposal_id` / `nullifier` / `members_root` bytes — this file is the
//! sentinel that catches that drift before it ships.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]

use borsh::to_vec;
use crypto::{
    nullifier as free_nullifier, verify_proof, Hasher, Identity, MerkleTree, Sha256Hasher,
    DOMAIN_LEAF, DOMAIN_NODE, HASH_LEN, MERKLE_DEPTH, SALT_LEN, SK_LEN,
};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id, ApprovePublicInputs, ChainId,
    APPROVE_PUBLIC_INPUTS_LEN, SEED_MULTISIG_STATE,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rand_32(rng: &mut StdRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn rand_identity(rng: &mut StdRng) -> Identity {
    Identity::new(rand_32(rng), rand_32(rng))
}

/// Reference implementation of `proposal_id` written purely in terms of
/// `Sha256Hasher::hash`. This is what step 3 (Risc0 guest), step 4
/// (verifier), and step 5 (SDK) MUST each replicate byte-for-byte. If
/// `derive_proposal_id` drifts from this manual recomputation, every
/// downstream consumer breaks.
fn manual_proposal_id(
    chain_id: &[u8; 32],
    state_pda: &[u8; 32],
    index: u64,
    action_bytes: &[u8],
    target_program: &[u8; 32],
) -> [u8; 32] {
    let action_hash = Sha256Hasher::hash(action_bytes);
    let target_hash = Sha256Hasher::hash(target_program);
    let index_bytes = index.to_le_bytes();

    let mut buf = [0u8; 32 + 32 + 8 + 32 + 32];
    buf[0..32].copy_from_slice(chain_id);
    buf[32..64].copy_from_slice(state_pda);
    buf[64..72].copy_from_slice(&index_bytes);
    buf[72..104].copy_from_slice(&action_hash);
    buf[104..136].copy_from_slice(&target_hash);

    Sha256Hasher::hash(&buf)
}

// ---------------------------------------------------------------------------
// 1. PDA derivation routes through Sha256Hasher::hash
// ---------------------------------------------------------------------------

#[test]
fn bridge_pda_uses_crypto_sha256_hasher() {
    let program_id = [0x42u8; 32];
    let create_key = [0x99u8; 32];

    let via_core = derive_multisig_state_pda(&program_id, &create_key);

    // Independent reconstruction using the round-5 SPEL-compatible formula:
    // combined = SHA-256(pad32(SEED_MULTISIG_STATE) || create_key)
    // pda      = SHA-256(NSSA_PUBLIC_PDA_PREFIX || program_id || combined)
    let mut lit_padded = [0u8; 32];
    lit_padded[..13].copy_from_slice(SEED_MULTISIG_STATE);
    let mut combined_preimage = Vec::with_capacity(64);
    combined_preimage.extend_from_slice(&lit_padded);
    combined_preimage.extend_from_slice(&create_key);
    let combined: [u8; 32] = Sha256Hasher::hash(&combined_preimage);

    let mut outer = [0u8; 96];
    outer[..32].copy_from_slice(b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00");
    outer[32..64].copy_from_slice(&program_id);
    outer[64..96].copy_from_slice(&combined);
    let via_crypto: [u8; 32] = Sha256Hasher::hash(&outer);

    assert_eq!(
        via_core, via_crypto,
        "derive_multisig_state_pda must equal SHA-256(NSSA_PREFIX ‖ program_id ‖ SHA-256(pad32(SEED) ‖ create_key))"
    );
}

// ---------------------------------------------------------------------------
// 2. proposal_id derivation routes through Sha256Hasher::hash (50 samples)
// ---------------------------------------------------------------------------

#[test]
fn bridge_proposal_id_uses_crypto_sha256_hasher() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE_u64);

    for _ in 0..50 {
        let chain_id_bytes = rand_32(&mut rng);
        let state_pda = rand_32(&mut rng);
        let target_program = rand_32(&mut rng);
        let index = rng.next_u64();

        let action_len = (rng.next_u32() % 128) as usize;
        let mut action_bytes = vec![0u8; action_len];
        rng.fill_bytes(&mut action_bytes);

        let via_core = derive_proposal_id(
            &ChainId::new(chain_id_bytes),
            &state_pda,
            index,
            &action_bytes,
            &target_program,
        );
        let via_manual = manual_proposal_id(
            &chain_id_bytes,
            &state_pda,
            index,
            &action_bytes,
            &target_program,
        );
        assert_eq!(via_core, via_manual);
    }
}

// ---------------------------------------------------------------------------
// 3. Identity::nullifier feeds straight into ApprovePublicInputs.nullifier
// ---------------------------------------------------------------------------

#[test]
fn bridge_nullifier_matches_member_to_public_input() {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_u64);

    for _ in 0..100 {
        let identity = rand_identity(&mut rng);
        let proposal_id = rand_32(&mut rng);

        let via_method = identity.nullifier::<Sha256Hasher>(&proposal_id);
        let via_free = free_nullifier::<Sha256Hasher>(&identity.sk, &proposal_id);
        assert_eq!(
            via_method, via_free,
            "Identity::nullifier must equal crypto::nullifier(&sk, &pid)"
        );

        // What an SDK would actually place into the public-input bundle.
        let members_root = rand_32(&mut rng);
        let inputs = ApprovePublicInputs {
            members_root,
            proposal_id,
            nullifier: via_method,
        };
        assert_eq!(inputs.nullifier, via_method);

        // And it must survive the 96-byte canonical pack/unpack round trip
        // byte-for-byte — that is the surface the verifier reads.
        let packed = inputs.to_bytes();
        assert_eq!(&packed[64..96], &via_method);
        let unpacked = ApprovePublicInputs::from_bytes(&packed);
        assert_eq!(unpacked.nullifier, via_method);
    }
}

// ---------------------------------------------------------------------------
// 4. End-to-end enrollment → public-inputs flow
// ---------------------------------------------------------------------------

#[test]
fn bridge_full_enrollment_to_public_inputs_flow() {
    const N_MEMBERS: usize = 5;

    let program_id = [0x77u8; 32];
    let create_key = [0xC1u8; 32];
    let target_program = [0xBBu8; 32];
    let action_bytes = b"transfer(amount=42)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let index: u64 = 7;

    // Five deterministic identities (NOT random — drift-detection sentinels
    // are easier to reason about when inputs are fixed).
    let identities: Vec<Identity> = (0..N_MEMBERS as u8)
        .map(|i| {
            let mut sk = [0u8; SK_LEN];
            let mut salt = [0u8; SALT_LEN];
            for j in 0..32 {
                sk[j] = i.wrapping_mul(13).wrapping_add(j as u8);
                salt[j] = i.wrapping_mul(31).wrapping_add(j as u8 ^ 0x55);
            }
            Identity::new(sk, salt)
        })
        .collect();

    // Merkle tree of commitments.
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut indices_in_tree = Vec::with_capacity(N_MEMBERS);
    for id in &identities {
        let commitment = id.commitment::<Sha256Hasher>();
        let idx = tree.insert(*commitment.as_bytes()).unwrap();
        indices_in_tree.push(idx);
    }
    let members_root = tree.root();
    assert_ne!(members_root, [0u8; HASH_LEN]);

    // PDA + proposal_id derivation via core.
    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let proposal_id =
        derive_proposal_id(&chain_id, &state_pda, index, &action_bytes, &target_program);
    assert_ne!(proposal_id, [0u8; 32]);

    // For each member, build full public inputs, pack to 96 bytes, unpack,
    // and confirm equality. Also verify the Merkle proof against the same
    // root — this is what the Risc0 guest does on the witness path.
    for (i, identity) in identities.iter().enumerate() {
        let leaf_idx = indices_in_tree[i];
        let nullifier = identity.nullifier::<Sha256Hasher>(&proposal_id);

        let inputs = ApprovePublicInputs {
            members_root,
            proposal_id,
            nullifier,
        };
        let packed = inputs.to_bytes();
        assert_eq!(packed.len(), APPROVE_PUBLIC_INPUTS_LEN);
        let unpacked = ApprovePublicInputs::from_bytes(&packed);
        assert_eq!(unpacked.members_root, members_root);
        assert_eq!(unpacked.proposal_id, proposal_id);
        assert_eq!(unpacked.nullifier, nullifier);

        // Member's Merkle proof verifies against the same root.
        let commitment = identity.commitment::<Sha256Hasher>();
        let proof = tree.proof(leaf_idx).unwrap();
        assert!(
            verify_proof::<Sha256Hasher>(&members_root, commitment.as_bytes(), &proof),
            "verify_proof must accept the honest proof for member {i}"
        );
    }

    // Sanity: distinct members produce distinct nullifiers on the same
    // proposal_id — otherwise on-chain double-vote PDA collisions would
    // false-positive against legitimate distinct approvals.
    let nullifiers: Vec<[u8; 32]> = identities
        .iter()
        .map(|m| m.nullifier::<Sha256Hasher>(&proposal_id))
        .collect();
    for i in 0..nullifiers.len() {
        for j in (i + 1)..nullifiers.len() {
            assert_ne!(nullifiers[i], nullifiers[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Hash lengths are consistent across both crates
// ---------------------------------------------------------------------------

#[test]
fn bridge_hash_lengths_consistent() {
    // crypto::HASH_LEN is the bedrock.
    assert_eq!(HASH_LEN, 32);

    // MERKLE_DEPTH pins the path-length budget for the Risc0 guest.
    assert_eq!(MERKLE_DEPTH, 20);

    // Encode-then-introspect the MerkleProof layout: 20 siblings of 32 bytes,
    // plus the indices array. We cannot directly take size_of (`siblings`
    // alone is 640 bytes, but Rust does not commit to repr ordering) so we
    // assert the const that drives it.
    let proof_siblings_len: usize = MERKLE_DEPTH;
    assert_eq!(proof_siblings_len, 20);
    let proof_siblings_bytes: usize = MERKLE_DEPTH * HASH_LEN;
    assert_eq!(proof_siblings_bytes, 20 * 32);

    // 96-byte canonical bundle = 3 × 32-byte hashes.
    assert_eq!(APPROVE_PUBLIC_INPUTS_LEN, 96);
    assert_eq!(APPROVE_PUBLIC_INPUTS_LEN, 3 * HASH_LEN);

    // Secret-key length agreement: core never re-defines SK_LEN, it relies
    // on crypto. SALT_LEN is also re-exposed via crypto::lib.rs and must
    // equal HASH_LEN for the commitment buffer to be sized correctly.
    assert_eq!(SK_LEN, 32);
    assert_eq!(SK_LEN, HASH_LEN);
    assert_eq!(SALT_LEN, 32);
    assert_eq!(SALT_LEN, HASH_LEN);
}

// ---------------------------------------------------------------------------
// 6. Domain-separation constants live in crypto only
// ---------------------------------------------------------------------------

#[test]
fn bridge_domain_separation_constants_are_used_only_in_crypto() {
    // The constants exist in crypto with the documented values.
    assert_eq!(DOMAIN_LEAF, 0x00);
    assert_eq!(DOMAIN_NODE, 0x01);

    // PDA derivation has its own domain-separation prefix (the NSSA public-
    // PDA prefix) but does NOT prepend a Merkle leaf or node byte. Pin that
    // explicitly: derive via core, derive manually with the NSSA prefix, and
    // confirm they match — while a Merkle-leaf-domained re-hash must not.
    let program_id = [0x05u8; 32];
    let create_key = [0x06u8; 32];

    let via_core = derive_multisig_state_pda(&program_id, &create_key);
    let mut lit_padded = [0u8; 32];
    lit_padded[..13].copy_from_slice(SEED_MULTISIG_STATE);
    let mut combined_preimage = Vec::with_capacity(64);
    combined_preimage.extend_from_slice(&lit_padded);
    combined_preimage.extend_from_slice(&create_key);
    let combined: [u8; 32] = Sha256Hasher::hash(&combined_preimage);
    let mut outer = [0u8; 96];
    outer[..32].copy_from_slice(b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00");
    outer[32..64].copy_from_slice(&program_id);
    outer[64..96].copy_from_slice(&combined);
    let via_manual: [u8; 32] = Sha256Hasher::hash(&outer);
    assert_eq!(via_core, via_manual);

    // Sanity: a leaf-domained re-hash would NOT match. This pins the
    // negative — i.e. PDA derivation must not be confusable with
    // Merkle-leaf hashing.
    let leaf_domained = Sha256Hasher::hash_leaf(&via_manual);
    assert_ne!(via_core, leaf_domained);
    let node_domained = Sha256Hasher::hash_node(&via_manual, &via_manual);
    assert_ne!(via_core, node_domained);

    // Same check for proposal_id.
    let chain_id = ChainId::from_u64(1);
    let state_pda = [0x07u8; 32];
    let target_program = [0x08u8; 32];
    let action_bytes = b"x";
    let via_core_pid =
        derive_proposal_id(&chain_id, &state_pda, 0, action_bytes, &target_program);
    let via_manual_pid = manual_proposal_id(
        chain_id.as_bytes(),
        &state_pda,
        0,
        action_bytes,
        &target_program,
    );
    assert_eq!(via_core_pid, via_manual_pid);
    // Domain-prefixed variants must not match — confirms core is using
    // undomained `hash`, not `hash_leaf` / `hash_node`.
    assert_ne!(via_core_pid, Sha256Hasher::hash_leaf(&via_manual_pid));
    assert_ne!(
        via_core_pid,
        Sha256Hasher::hash_node(&via_manual_pid, &via_manual_pid)
    );
}

// ---------------------------------------------------------------------------
// 7. action_bytes are hashed via crypto::Sha256Hasher::hash (50 samples)
// ---------------------------------------------------------------------------

#[test]
fn bridge_action_bytes_hashed_via_crypto_sha256_hasher() {
    let mut rng = StdRng::seed_from_u64(0xA1B2_C3D4_u64);

    // We pin: the action_bytes contribution to the proposal_id preimage is
    // EXACTLY Sha256Hasher::hash(action_bytes) at bytes 72..104. Hold every
    // other input fixed and vary action_bytes — recompute manually with
    // direct hash and confirm equality.
    let chain_id = ChainId::from_u64(1);
    let state_pda = [0x42u8; 32];
    let target_program = [0x84u8; 32];
    let index: u64 = 12345;

    for _ in 0..50 {
        let len = (rng.next_u32() % 256) as usize;
        let mut action_bytes = vec![0u8; len];
        rng.fill_bytes(&mut action_bytes);

        let via_core = derive_proposal_id(
            &chain_id,
            &state_pda,
            index,
            &action_bytes,
            &target_program,
        );

        // Manual recompute calling Sha256Hasher::hash on action_bytes
        // directly — proves no transformation is applied before hashing.
        let action_hash = Sha256Hasher::hash(&action_bytes);
        let target_hash = Sha256Hasher::hash(&target_program);
        let mut buf = [0u8; 136];
        buf[0..32].copy_from_slice(chain_id.as_bytes());
        buf[32..64].copy_from_slice(&state_pda);
        buf[64..72].copy_from_slice(&index.to_le_bytes());
        buf[72..104].copy_from_slice(&action_hash);
        buf[104..136].copy_from_slice(&target_hash);
        let via_manual = Sha256Hasher::hash(&buf);

        assert_eq!(via_core, via_manual);
    }
}

// ---------------------------------------------------------------------------
// 8. target_program is hashed via crypto::Sha256Hasher::hash (50 samples)
// ---------------------------------------------------------------------------

#[test]
fn bridge_target_program_hashed_via_crypto_sha256_hasher() {
    let mut rng = StdRng::seed_from_u64(0xF00D_BABE_u64);

    let chain_id = ChainId::from_u64(7);
    let state_pda = [0x11u8; 32];
    let action_bytes = b"fixed_action_for_target_sweep";
    let index: u64 = 99;

    for _ in 0..50 {
        let target_program = rand_32(&mut rng);

        let via_core =
            derive_proposal_id(&chain_id, &state_pda, index, action_bytes, &target_program);

        let action_hash = Sha256Hasher::hash(action_bytes);
        let target_hash = Sha256Hasher::hash(&target_program);
        let mut buf = [0u8; 136];
        buf[0..32].copy_from_slice(chain_id.as_bytes());
        buf[32..64].copy_from_slice(&state_pda);
        buf[64..72].copy_from_slice(&index.to_le_bytes());
        buf[72..104].copy_from_slice(&action_hash);
        buf[104..136].copy_from_slice(&target_hash);
        let via_manual = Sha256Hasher::hash(&buf);

        assert_eq!(via_core, via_manual);
    }
}

// ---------------------------------------------------------------------------
// 9. proposal_id preimage byte layout pinned to spec
// ---------------------------------------------------------------------------

#[test]
fn bridge_proposal_id_preimage_byte_layout() {
    // This test exists for one purpose: pin the byte-level layout of the
    // 136-byte preimage that the Risc0 guest, the on-chain verifier, and
    // the SDK must each replicate. Any reordering, any padding, any
    // version byte would break consensus the moment a real proof lands.
    //
    //   [ 0.. 32)  chain_id
    //   [32.. 64)  state_pda
    //   [64.. 72)  index (u64, little-endian)
    //   [72..104)  Sha256(action_bytes)
    //   [104..136) Sha256(target_program)
    //   total: 136 bytes
    //   output: Sha256(buf)

    let chain_id_bytes = {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
        b
    };
    let state_pda = [0xABu8; 32];
    let index: u64 = 0x0102_0304_0506_0708;
    let action_bytes: &[u8] = b"proposal-preimage-layout-anchor";
    let target_program = [0xCDu8; 32];

    let action_hash = Sha256Hasher::hash(action_bytes);
    let target_hash = Sha256Hasher::hash(&target_program);
    let mut preimage = [0u8; 136];
    preimage[0..32].copy_from_slice(&chain_id_bytes);
    preimage[32..64].copy_from_slice(&state_pda);
    preimage[64..72].copy_from_slice(&index.to_le_bytes());
    preimage[72..104].copy_from_slice(&action_hash);
    preimage[104..136].copy_from_slice(&target_hash);

    // Independent spot-checks of the slot boundaries — if any byte shifts
    // by one, these assertions catch it before the SHA-256 even runs.
    assert_eq!(preimage[0], chain_id_bytes[0]);
    assert_eq!(preimage[31], chain_id_bytes[31]);
    assert_eq!(preimage[32], state_pda[0]);
    assert_eq!(preimage[63], state_pda[31]);
    assert_eq!(preimage[64], 0x08); // LSB of index in little-endian
    assert_eq!(preimage[71], 0x01); // MSB of index in little-endian
    assert_eq!(preimage[72], action_hash[0]);
    assert_eq!(preimage[103], action_hash[31]);
    assert_eq!(preimage[104], target_hash[0]);
    assert_eq!(preimage[135], target_hash[31]);

    let expected = Sha256Hasher::hash(&preimage);
    let actual = derive_proposal_id(
        &ChainId::new(chain_id_bytes),
        &state_pda,
        index,
        action_bytes,
        &target_program,
    );
    assert_eq!(
        actual, expected,
        "derive_proposal_id must match the manually constructed 136-byte preimage"
    );
}

// ---------------------------------------------------------------------------
// 10. ChainId::from_u64 is byte-equivalent to manual little-endian construction
// ---------------------------------------------------------------------------

#[test]
fn bridge_chainid_from_u64_little_endian_through_proposal_id() {
    let via_from_u64 = ChainId::from_u64(123);

    // 123 == 0x7B; little-endian = [0x7B, 0, 0, ..., 0].
    let mut manual = [0u8; 32];
    manual[0] = 0x7B;
    let via_new = ChainId::new(manual);

    // Byte-level equality at the raw representation.
    assert_eq!(via_from_u64.as_bytes(), via_new.as_bytes());
    assert_eq!(via_from_u64, via_new);

    // And the through-proposal_id surface — what matters in practice. If
    // ChainId::from_u64 ever changed encoding (e.g. big-endian), this
    // would explode.
    let state_pda = [0x33u8; 32];
    let target_program = [0x44u8; 32];
    let action_bytes = b"chainid-equivalence-check";
    let index: u64 = 17;

    let pid_a = derive_proposal_id(
        &via_from_u64,
        &state_pda,
        index,
        action_bytes,
        &target_program,
    );
    let pid_b = derive_proposal_id(
        &via_new,
        &state_pda,
        index,
        action_bytes,
        &target_program,
    );
    assert_eq!(pid_a, pid_b);

    // Negative: a different little-endian value (big-endian misinterpretation
    // of 123 would be [0,...,0,0x7B]) must NOT produce the same pid.
    let mut be_misread = [0u8; 32];
    be_misread[31] = 0x7B;
    let pid_be = derive_proposal_id(
        &ChainId::new(be_misread),
        &state_pda,
        index,
        action_bytes,
        &target_program,
    );
    assert_ne!(pid_a, pid_be);
}

// ---------------------------------------------------------------------------
// 11. Known-answer vectors — regression sentinels visible in every PR diff
// ---------------------------------------------------------------------------

#[test]
fn bridge_kat_pinned() {
    // ------------------------------------------------------------------
    // KAT 1: minimal-input baseline.
    //
    // program_id     = [0x11; 32]
    // create_key     = [0x22; 32]
    // chain_id_u64   = 1
    // index          = 0
    // action_bytes   = b"kat_action_1"
    // target_program = [0x33; 32]
    // ------------------------------------------------------------------
    {
        let program_id = [0x11u8; 32];
        let create_key = [0x22u8; 32];
        let chain_id = ChainId::from_u64(1);
        let index: u64 = 0;
        let action_bytes: &[u8] = b"kat_action_1";
        let target_program = [0x33u8; 32];

        let state_pda = derive_multisig_state_pda(&program_id, &create_key);
        // Round-5: pinned hex recomputed under SPEL-compatible derivation.
        let expected_state_pda = hex::decode(
            "93b8f698cd4ced03f1fa0c7bd3025552f37c6f89ae9d5b482467c264eebfabe7",
        )
        .unwrap();
        assert_eq!(state_pda.as_slice(), expected_state_pda.as_slice());

        let proposal_id =
            derive_proposal_id(&chain_id, &state_pda, index, action_bytes, &target_program);
        let expected_proposal_id = hex::decode(
            "011f06dfcbbc20115b121180f32972ad28edc775c7969d4ec228a979442a179c",
        )
        .unwrap();
        assert_eq!(proposal_id.as_slice(), expected_proposal_id.as_slice());
    }

    // ------------------------------------------------------------------
    // KAT 2: empty action_bytes, non-trivial chain_id and index.
    //
    // program_id     = [0xA0; 32]
    // create_key     = 0..32 ascending
    // chain_id_u64   = 0xABCD_EF01
    // index          = 42
    // action_bytes   = b""
    // target_program = [0xFF; 32]
    // ------------------------------------------------------------------
    {
        let program_id = [0xA0u8; 32];
        let mut create_key = [0u8; 32];
        for i in 0..32 {
            create_key[i] = i as u8;
        }
        let chain_id = ChainId::from_u64(0xABCD_EF01);
        let index: u64 = 42;
        let action_bytes: &[u8] = b"";
        let target_program = [0xFFu8; 32];

        let state_pda = derive_multisig_state_pda(&program_id, &create_key);
        let expected_state_pda = hex::decode(
            "18d93f1fb3524fbe933f86cf2a52d09c80885d18771eefd0efc4b88f2300fd49",
        )
        .unwrap();
        assert_eq!(state_pda.as_slice(), expected_state_pda.as_slice());

        let proposal_id =
            derive_proposal_id(&chain_id, &state_pda, index, action_bytes, &target_program);
        let expected_proposal_id = hex::decode(
            "b01d89ef9e4e0d05198d11a7b31cb1cbc38868ee01d4d76456b435ef78276113",
        )
        .unwrap();
        assert_eq!(proposal_id.as_slice(), expected_proposal_id.as_slice());
    }

    // ------------------------------------------------------------------
    // KAT 3: realistic-shape inputs.
    //
    // program_id     = [0x99; 32]
    // create_key     = [0xAB; 32]
    // chain_id_u64   = 0xDEAD_BEEF
    // index          = 999
    // action_bytes   = b"treasury_withdraw(100,recipient=0xABCD)"
    // target_program = [0xCD; 32]
    // ------------------------------------------------------------------
    {
        let program_id = [0x99u8; 32];
        let create_key = [0xABu8; 32];
        let chain_id = ChainId::from_u64(0xDEAD_BEEF);
        let index: u64 = 999;
        let action_bytes: &[u8] = b"treasury_withdraw(100,recipient=0xABCD)";
        let target_program = [0xCDu8; 32];

        let state_pda = derive_multisig_state_pda(&program_id, &create_key);
        let expected_state_pda = hex::decode(
            "6de3a5cc83e530827b5b8f150028bf92bd4260aa94b101798ad794d72c3f0bb6",
        )
        .unwrap();
        assert_eq!(state_pda.as_slice(), expected_state_pda.as_slice());

        let proposal_id =
            derive_proposal_id(&chain_id, &state_pda, index, action_bytes, &target_program);
        let expected_proposal_id = hex::decode(
            "db41d7e974dc92f89a9506a0f0cf605f88ecd0cde734a329a7b055709ec2ad8f",
        )
        .unwrap();
        assert_eq!(proposal_id.as_slice(), expected_proposal_id.as_slice());
    }
}

// ---------------------------------------------------------------------------
// Bonus: Borsh-encoded ApprovePublicInputs must equal the explicit 96-byte
// pack. Cheap, but it ties the two encodings together as a bridge invariant
// — if Borsh ever changes its `[u8; 32]` encoding, this trips here, not at
// the verifier.
// ---------------------------------------------------------------------------

#[test]
fn bridge_borsh_encoding_matches_explicit_layout() {
    let inputs = ApprovePublicInputs {
        members_root: [0x55; 32],
        proposal_id: [0x66; 32],
        nullifier: [0x77; 32],
    };
    let explicit = inputs.to_bytes();
    let via_borsh = to_vec(&inputs).unwrap();
    assert_eq!(via_borsh.len(), APPROVE_PUBLIC_INPUTS_LEN);
    assert_eq!(via_borsh.as_slice(), explicit.as_slice());
}
