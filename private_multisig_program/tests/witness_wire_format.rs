//! Wire-format sentinels for the host → Risc0-guest witness stream of the
//! LP-0002 approve circuit.
//!
//! The protocol between `tests/approve_circuit.rs` (and eventually the SDK)
//! and `methods/guest/src/bin/approve_circuit.rs` is implicit today: the
//! guest performs five `env::read_slice` calls in a specific order with
//! specific sizes, and the host MUST call `ExecutorEnvBuilder::write_slice`
//! in the EXACT SAME ORDER with the EXACT SAME SIZES. Any silent drift on
//! either side breaks every receipt.
//!
//! This file pins the wire format with byte-level assertions so a future
//! refactor that silently shifts byte positions, swaps two `write_slice`
//! calls, or changes the size of any field is caught by a test failure
//! rather than by a mysterious in-the-wild verification break.
//!
//! ## Wire format being pinned
//!
//! The guest reads, in order:
//!
//! | # | bytes | field                                          |
//! |---|-------|------------------------------------------------|
//! | 1 |    64 | `members_root (32) ‖ proposal_id (32)`         |
//! | 2 |    32 | `sk`                                           |
//! | 3 |    32 | `salt`                                         |
//! | 4 |   640 | flattened siblings: 20 × 32 bytes              |
//! | 5 |    20 | direction bytes (each strictly 0 or 1)         |
//!
//! Total: **788 bytes**.
//!
//! ## What an extra byte means
//!
//! `risc0-zkvm 3.0`'s `ExecutorEnv` concatenates every `write_slice` into a
//! single flat input buffer that the guest reads via stdin-style cursor
//! semantics; the guest reads exactly the bytes it asks for. Trailing
//! unread bytes therefore sit unread without erroring, and the journal is
//! whatever the guest writes. The
//! `wire_extra_bytes_appended_to_witness_dont_change_journal` sentinel pins
//! that behavior (and would catch a future risc0 release that suddenly
//! starts rejecting trailing bytes).

#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::identity_op)]
#![allow(clippy::manual_memcpy)]

use std::env;

use crypto::{
    merkle::MerkleProof, Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH, SALT_LEN,
    SK_LEN,
};
use private_multisig_core::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

// --------------------------------------------------------------------------
// Pinned wire-format constants
// --------------------------------------------------------------------------

/// Public-input prefix size: `members_root (32) || proposal_id (32)`.
const WIRE_PUBLIC_PREFIX_LEN: usize = 64;
/// Length of the flattened siblings buffer: `MERKLE_DEPTH * HASH_LEN`.
const WIRE_SIBLINGS_FLAT_LEN: usize = MERKLE_DEPTH * HASH_LEN;
/// Number of direction bytes — one per Merkle level.
const WIRE_DIRECTION_LEN: usize = MERKLE_DEPTH;

/// Total bytes the guest reads via `env::read_slice` across the five calls.
///
/// 64 (public prefix) + 32 (sk) + 32 (salt) + 640 (siblings) + 20 (directions)
/// = **788 bytes**.
const WIRE_TOTAL_WITNESS_LEN: usize =
    WIRE_PUBLIC_PREFIX_LEN + SK_LEN + SALT_LEN + WIRE_SIBLINGS_FLAT_LEN + WIRE_DIRECTION_LEN;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/// Mirror `approve_circuit.rs::deterministic_identity` so every `tests/*.rs`
/// crate stays independent.
fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

fn enable_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: each `#[test]` runs in a fresh process-thread; we set the
        // var before any prover work spawns auxiliary threads.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

/// Independent re-implementation of the host-side packing in
/// `tests/approve_circuit.rs`. Sentinel #10
/// (`wire_round_trip_repack_via_independent_packer`) uses this to confirm a
/// second, independently-written packer produces an identical 788-byte
/// witness — i.e. the wire format is what the host code claims it is, not
/// what some accidental shared helper makes it appear to be.
fn pack_witness(
    members_root: &[u8; HASH_LEN],
    proposal_id: &[u8; HASH_LEN],
    sk: &[u8; SK_LEN],
    salt: &[u8; SALT_LEN],
    proof: &MerkleProof,
) -> [u8; WIRE_TOTAL_WITNESS_LEN] {
    let mut buf = [0u8; WIRE_TOTAL_WITNESS_LEN];
    // [0..32]  members_root
    // [32..64] proposal_id
    buf[..HASH_LEN].copy_from_slice(members_root);
    buf[HASH_LEN..2 * HASH_LEN].copy_from_slice(proposal_id);
    // [64..96]  sk
    // [96..128] salt
    let mut cursor = WIRE_PUBLIC_PREFIX_LEN;
    buf[cursor..cursor + SK_LEN].copy_from_slice(sk);
    cursor += SK_LEN;
    buf[cursor..cursor + SALT_LEN].copy_from_slice(salt);
    cursor += SALT_LEN;
    // [128..768] siblings flat
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = cursor + level * HASH_LEN;
        buf[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    cursor += WIRE_SIBLINGS_FLAT_LEN;
    // [768..788] direction bytes
    for (level, bit) in proof.indices.iter().enumerate() {
        buf[cursor + level] = u8::from(*bit);
    }
    buf
}

/// Build a tree of `n` deterministic members and return tree + members.
fn build_tree(n: u8) -> (MerkleTree<Sha256Hasher>, Vec<Identity>) {
    let members: Vec<Identity> = (0..n).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    (tree, members)
}

/// Compute `proposal_id` for a fixed synthetic scenario.
fn synthetic_proposal_id() -> [u8; 32] {
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program)
}

/// Prove and return the journal bytes. Asserts the receipt verifies.
fn prove_with_input_bytes(input_bytes: &[u8]) -> Vec<u8> {
    enable_dev_mode();
    let env_builder = ExecutorEnv::builder()
        .write_slice(input_bytes)
        .build()
        .expect("ExecutorEnv build must succeed");
    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid 788-byte witness");
    let receipt = prove_info.receipt;
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");
    receipt.journal.bytes.clone()
}

// --------------------------------------------------------------------------
// Sentinel 1 — total witness size
// --------------------------------------------------------------------------

#[test]
fn wire_total_witness_size_is_788_bytes() {
    // Manually sum each component the guest reads via `env::read_slice`.
    let manual_total = 64 + 32 + 32 + 640 + 20;
    assert_eq!(manual_total, 788, "hand-sum invariant of the wire format");
    assert_eq!(
        WIRE_TOTAL_WITNESS_LEN, 788,
        "the named constant must equal the hand-summed total"
    );

    // Each named subcomponent must match the guest's literal read sizes.
    assert_eq!(WIRE_PUBLIC_PREFIX_LEN, 64);
    assert_eq!(SK_LEN, 32);
    assert_eq!(SALT_LEN, 32);
    assert_eq!(WIRE_SIBLINGS_FLAT_LEN, 640);
    assert_eq!(MERKLE_DEPTH * HASH_LEN, 640);
    assert_eq!(WIRE_DIRECTION_LEN, 20);
    assert_eq!(MERKLE_DEPTH, 20);
    assert_eq!(HASH_LEN, 32);
}

// --------------------------------------------------------------------------
// Sentinel 2 — public-input prefix layout
// --------------------------------------------------------------------------

#[test]
fn wire_public_input_prefix_layout() {
    let members_root: [u8; 32] = [0x11; 32];
    let proposal_id: [u8; 32] = [0x22; 32];

    // Hand-pack the 64-byte prefix the way the host MUST.
    let mut prefix = [0u8; WIRE_PUBLIC_PREFIX_LEN];
    prefix[..32].copy_from_slice(&members_root);
    prefix[32..64].copy_from_slice(&proposal_id);

    assert_eq!(&prefix[..32], &members_root);
    assert_eq!(&prefix[32..64], &proposal_id);

    // The wire prefix is `members_root || proposal_id`. The 96-byte
    // `ApprovePublicInputs::to_bytes()` is `members_root || proposal_id ||
    // nullifier`. The first 64 bytes of the journal happen to match the
    // wire prefix when the witness's `(root, pid)` agree with the bundle —
    // but the two layouts are conceptually distinct (one is host → guest,
    // the other is guest → journal), and we pin them as such.
    let bundle = ApprovePublicInputs {
        members_root,
        proposal_id,
        nullifier: [0x33; 32],
    }
    .to_bytes();
    assert_eq!(bundle.len(), APPROVE_PUBLIC_INPUTS_LEN);
    // The wire prefix is NOT the journal; they only share a 64-byte prefix.
    assert_eq!(&bundle[..64], &prefix[..]);
    assert_ne!(&bundle[..], &prefix[..]); // total lengths differ
}

// --------------------------------------------------------------------------
// Sentinel 3 — siblings flat layout
// --------------------------------------------------------------------------

#[test]
fn wire_siblings_flat_byte_layout() {
    let (tree, members) = build_tree(5);
    let proof = tree.proof(2).unwrap();
    let _ = &members; // members are only used implicitly via the tree

    // Hand-flatten the same way the guest unflatten reads it:
    //   siblings[level][byte] = flat[level * 32 + byte]
    let mut flat = [0u8; WIRE_SIBLINGS_FLAT_LEN];
    for level in 0..MERKLE_DEPTH {
        for byte in 0..HASH_LEN {
            flat[level * HASH_LEN + byte] = proof.siblings[level][byte];
        }
    }

    // Same buffer produced by the existing host packing loop.
    let mut host_flat = [0u8; WIRE_SIBLINGS_FLAT_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        host_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }

    assert_eq!(flat, host_flat, "byte-for-byte sibling flattening");

    // Spot-check level offsets.
    for level in 0..MERKLE_DEPTH {
        let start = level * HASH_LEN;
        assert_eq!(
            &flat[start..start + HASH_LEN],
            &proof.siblings[level][..],
            "level {level} sibling lives at flat[{start}..{}]",
            start + HASH_LEN
        );
    }
}

// --------------------------------------------------------------------------
// Sentinel 4 — direction bytes are 0 or 1 only
// --------------------------------------------------------------------------

#[test]
fn wire_direction_bytes_are_0_or_1_only() {
    // Try every reachable member index in a fully-populated few-leaf tree
    // AND a larger tree, plus the 0/1 boundary indices, and confirm the
    // host packing never emits a non-{0,1} byte. The guest's strict match
    // panics on any other value.
    for n_leaves in [1u8, 2, 3, 5, 8, 15, 16, 17] {
        let (tree, _members) = build_tree(n_leaves);
        for idx in 0..(n_leaves as usize) {
            let proof = tree.proof(idx).unwrap();
            let mut direction_bytes = [0u8; MERKLE_DEPTH];
            for (level, bit) in proof.indices.iter().enumerate() {
                direction_bytes[level] = u8::from(*bit);
            }
            for (level, b) in direction_bytes.iter().enumerate() {
                assert!(
                    *b == 0 || *b == 1,
                    "n_leaves={n_leaves} idx={idx} level={level} direction byte = {b}, must be 0 or 1"
                );
            }
        }
    }
}

// --------------------------------------------------------------------------
// Sentinel 5 — known-answer test for the minimal 1-leaf tree
// --------------------------------------------------------------------------

#[test]
fn wire_known_answer_test_for_minimal_proof() {
    use crypto::hash::Hasher;

    let (tree, members) = build_tree(1);
    let approver = &members[0];
    let proof = tree.proof(0).unwrap();
    let members_root = tree.root();
    let proposal_id = synthetic_proposal_id();

    // Manually rebuild the expected sibling chain for a 1-leaf tree:
    //   level 0 sibling = empty-leaf marker  = hash_leaf([0;32])
    //   level k sibling = hash_node(prev, prev) for k = 1..20
    // (matches `MerkleTree::node_at` for the uninhabited right subtree.)
    let mut expected_siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    expected_siblings[0] = Sha256Hasher::hash_leaf(&[0u8; HASH_LEN]);
    for level in 1..MERKLE_DEPTH {
        let prev = expected_siblings[level - 1];
        expected_siblings[level] = Sha256Hasher::hash_node(&prev, &prev);
    }
    assert_eq!(
        proof.siblings, expected_siblings,
        "1-leaf proof must use the empty-subtree marker chain"
    );

    // Member at index 0 has all-false directions.
    assert_eq!(proof.indices, [false; MERKLE_DEPTH]);

    // Hand-build the 788-byte witness from scratch.
    let mut expected = [0u8; WIRE_TOTAL_WITNESS_LEN];
    expected[..32].copy_from_slice(&members_root);
    expected[32..64].copy_from_slice(&proposal_id);
    expected[64..96].copy_from_slice(&approver.sk);
    expected[96..128].copy_from_slice(&approver.salt);
    for level in 0..MERKLE_DEPTH {
        let start = 128 + level * HASH_LEN;
        expected[start..start + HASH_LEN].copy_from_slice(&expected_siblings[level]);
    }
    // direction bytes — all zero for index 0.
    for level in 0..MERKLE_DEPTH {
        expected[768 + level] = 0u8;
    }

    // Same buffer via the independent packer.
    let actual = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &proof,
    );

    assert_eq!(
        actual.as_slice(),
        expected.as_slice(),
        "1-leaf KAT: independent packer must produce the hand-computed bytes"
    );
}

// --------------------------------------------------------------------------
// Sentinel 6 — known-answer test for a 3-leaf tree, member at index 1
// --------------------------------------------------------------------------

#[test]
fn wire_known_answer_test_for_3_leaf_tree() {
    use crypto::hash::Hasher;

    let (tree, members) = build_tree(3);
    let approver = &members[1];
    let proof = tree.proof(1).unwrap();
    let members_root = tree.root();
    let proposal_id = synthetic_proposal_id();

    // Manually construct what the proof for index 1 in a 3-leaf tree looks
    // like, step by step. Leaves stored at positions 0, 1, 2; positions
    // 3..2^20 are "empty" and represented by the marker chain.
    //
    // Let:
    //   leaf_i  = hash_leaf(commitment_i)
    //   m[0]    = hash_leaf([0; 32])
    //   m[k+1]  = hash_node(m[k], m[k])
    let leaves: [[u8; HASH_LEN]; 3] = [
        *members[0].commitment::<Sha256Hasher>().as_bytes(),
        *members[1].commitment::<Sha256Hasher>().as_bytes(),
        *members[2].commitment::<Sha256Hasher>().as_bytes(),
    ];
    let leaf_hashed: [[u8; HASH_LEN]; 3] = [
        Sha256Hasher::hash_leaf(&leaves[0]),
        Sha256Hasher::hash_leaf(&leaves[1]),
        Sha256Hasher::hash_leaf(&leaves[2]),
    ];
    let mut marker = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
    marker[0] = Sha256Hasher::hash_leaf(&[0u8; HASH_LEN]);
    for k in 1..=MERKLE_DEPTH {
        let prev = marker[k - 1];
        marker[k] = Sha256Hasher::hash_node(&prev, &prev);
    }

    // For index 1 (binary 1, level-0 LSB=1 → right child):
    //   level 0: sibling = leaf_hashed[0] (the left twin), index bit = true
    //   level 1: current is hash_node(leaf_hashed[0], leaf_hashed[1]);
    //            sibling at level 1 covers positions 2..4; index bit = false.
    //            That subtree contains leaf_hashed[2] at pos 2 and marker[0]
    //            at pos 3, so the level-1 sibling node value is
    //            hash_node(leaf_hashed[2], marker[0]).
    //   level k≥2: current sits at position 0 of level k, so sibling sits at
    //            position 1 — which is fully uninhabited and equals
    //            marker[k]. Index bit is false.
    let mut expected_siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    expected_siblings[0] = leaf_hashed[0];
    expected_siblings[1] = Sha256Hasher::hash_node(&leaf_hashed[2], &marker[0]);
    for level in 2..MERKLE_DEPTH {
        expected_siblings[level] = marker[level];
    }
    assert_eq!(
        proof.siblings, expected_siblings,
        "3-leaf index-1 proof: hand-computed sibling chain mismatch"
    );

    let mut expected_indices = [false; MERKLE_DEPTH];
    expected_indices[0] = true;
    assert_eq!(proof.indices, expected_indices);

    // Hand-build the 788-byte witness.
    let mut expected = [0u8; WIRE_TOTAL_WITNESS_LEN];
    expected[..32].copy_from_slice(&members_root);
    expected[32..64].copy_from_slice(&proposal_id);
    expected[64..96].copy_from_slice(&approver.sk);
    expected[96..128].copy_from_slice(&approver.salt);
    for level in 0..MERKLE_DEPTH {
        let start = 128 + level * HASH_LEN;
        expected[start..start + HASH_LEN].copy_from_slice(&expected_siblings[level]);
    }
    expected[768] = 1u8;
    for level in 1..MERKLE_DEPTH {
        expected[768 + level] = 0u8;
    }

    let actual = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &proof,
    );
    assert_eq!(
        actual.as_slice(),
        expected.as_slice(),
        "3-leaf KAT mismatch"
    );
}

// --------------------------------------------------------------------------
// Sentinel 7 — swapping sibling levels changes witness bytes
// --------------------------------------------------------------------------

#[test]
fn wire_swap_sibling_levels_changes_witness_bytes() {
    let (tree, members) = build_tree(5);
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let proposal_id = synthetic_proposal_id();

    // Canonical packing.
    let canonical = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &proof,
    );

    // Swap siblings[0] and siblings[1] before packing.
    let mut swapped_proof = proof.clone();
    swapped_proof.siblings.swap(0, 1);
    let swapped = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &swapped_proof,
    );

    assert_ne!(
        canonical, swapped,
        "swapping siblings[0] and siblings[1] must change the witness bytes"
    );

    // And specifically the change must live in the 640-byte siblings region.
    // Everything outside `[128..768]` is identical.
    assert_eq!(&canonical[..128], &swapped[..128]);
    assert_eq!(&canonical[768..], &swapped[768..]);
    assert_ne!(&canonical[128..768], &swapped[128..768]);
}

// --------------------------------------------------------------------------
// Sentinel 8 — swapping direction levels changes witness bytes
// --------------------------------------------------------------------------

#[test]
fn wire_swap_direction_levels_changes_witness_bytes() {
    // Pick a member whose proof has at least one non-zero direction bit at
    // a level distinct from another bit, so swapping IS observable. Index
    // 2 in a 5-leaf tree gives indices[0]=false, indices[1]=true — perfect.
    let (tree, members) = build_tree(5);
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    assert!(proof.indices[0] != proof.indices[1]);

    let members_root = tree.root();
    let proposal_id = synthetic_proposal_id();

    let canonical = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &proof,
    );

    let mut swapped_proof = proof.clone();
    swapped_proof.indices.swap(0, 1);
    let swapped = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &swapped_proof,
    );

    assert_ne!(
        canonical, swapped,
        "swapping indices[0] and indices[1] must change the witness bytes"
    );

    // The change must live only in the 20-byte direction-bytes tail.
    assert_eq!(&canonical[..768], &swapped[..768]);
    assert_ne!(&canonical[768..], &swapped[768..]);
}

// --------------------------------------------------------------------------
// Sentinel 9 — extra trailing bytes do not change the journal
// --------------------------------------------------------------------------

#[test]
fn wire_extra_bytes_appended_to_witness_dont_change_journal() {
    enable_dev_mode();

    let (tree, members) = build_tree(5);
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let proposal_id = synthetic_proposal_id();
    let canonical = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &proof,
    );

    // Build a "canonical" witness via a single write_slice.
    let env_canonical = ExecutorEnv::builder()
        .write_slice(&canonical)
        .build()
        .expect("canonical env build");
    let prover = default_prover();
    let receipt_canonical = prover
        .prove(env_canonical, APPROVE_CIRCUIT_ELF)
        .expect("canonical prove")
        .receipt;
    receipt_canonical
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("canonical verify");
    let journal_canonical = receipt_canonical.journal.bytes.clone();

    // Build an "extra trailing byte" witness: same 788 bytes + one 0x00.
    let env_extra = ExecutorEnv::builder()
        .write_slice(&canonical)
        .write_slice(&[0u8])
        .build()
        .expect("extra-bytes env build");
    let prover = default_prover();
    let receipt_extra = prover
        .prove(env_extra, APPROVE_CIRCUIT_ELF)
        .expect("extra-bytes prove (Risc0 must tolerate trailing unread bytes)")
        .receipt;
    receipt_extra
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("extra-bytes verify");
    let journal_extra = receipt_extra.journal.bytes.clone();

    assert_eq!(
        journal_canonical, journal_extra,
        "the guest reads exactly 788 bytes — trailing bytes must not affect the journal"
    );
}

// --------------------------------------------------------------------------
// Sentinel 10 — round-trip via an independent packer
// --------------------------------------------------------------------------

#[test]
fn wire_round_trip_repack_via_independent_packer() {
    enable_dev_mode();

    let (tree, members) = build_tree(5);
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let proposal_id = synthetic_proposal_id();
    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&proposal_id);

    // Packing A — five `write_slice` calls (mirrors `tests/approve_circuit.rs`).
    let mut public_prefix = [0u8; WIRE_PUBLIC_PREFIX_LEN];
    public_prefix[..32].copy_from_slice(&members_root);
    public_prefix[32..].copy_from_slice(&proposal_id);
    let mut siblings_flat = [0u8; WIRE_SIBLINGS_FLAT_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }
    let env_a = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&approver.sk)
        .write_slice(&approver.salt)
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build()
        .expect("five-call build");

    // Packing B — one `write_slice` of the independently-packed 788-byte buffer.
    let one_shot = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &proof,
    );
    let env_b = ExecutorEnv::builder()
        .write_slice(&one_shot)
        .build()
        .expect("one-shot build");

    let prover = default_prover();
    let journal_a = prover
        .prove(env_a, APPROVE_CIRCUIT_ELF)
        .expect("five-call prove")
        .receipt
        .journal
        .bytes
        .clone();
    let prover = default_prover();
    let journal_b = prover
        .prove(env_b, APPROVE_CIRCUIT_ELF)
        .expect("one-shot prove")
        .receipt
        .journal
        .bytes
        .clone();

    assert_eq!(journal_a, journal_b, "the two packings must yield identical journals");

    // And the journal must decode to the expected public-input bundle.
    assert_eq!(journal_a.len(), APPROVE_PUBLIC_INPUTS_LEN);
    let mut journal_arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    journal_arr.copy_from_slice(&journal_a);
    let bundle = ApprovePublicInputs::from_bytes(&journal_arr);
    assert_eq!(bundle.members_root, members_root);
    assert_eq!(bundle.proposal_id, proposal_id);
    assert_eq!(bundle.nullifier, expected_nullifier);
}

// --------------------------------------------------------------------------
// Sentinel 11 — direction bits encode the member index, LSB-first
// --------------------------------------------------------------------------

#[test]
fn wire_member_index_encoding_is_implicit_in_direction_bytes() {
    // Build a tree big enough that the proof for index N (for N=0..=10)
    // exists. 11 leaves is enough — every index 0..=10 is populated.
    let (tree, _members) = build_tree(11);

    for n in 0u32..=10 {
        let proof = tree.proof(n as usize).unwrap();
        let mut direction_bytes = [0u8; MERKLE_DEPTH];
        for (level, bit) in proof.indices.iter().enumerate() {
            direction_bytes[level] = u8::from(*bit);
        }

        // Expected: bit `level` of `direction_bytes` equals the `level`-th
        // least-significant bit of `n`. The upper bits (beyond log2 of the
        // tree size) must therefore be zero.
        for level in 0..MERKLE_DEPTH {
            let expected_bit = (n >> level) & 1;
            assert_eq!(
                direction_bytes[level] as u32, expected_bit,
                "member index {n}: direction bit at level {level} should be {expected_bit}, \
                 got {actual} — direction bytes do not encode index as LSB-first",
                actual = direction_bytes[level]
            );
        }

        // Spot-check the spec-line examples from the task brief.
        if n == 0 {
            assert_eq!(direction_bytes, [0u8; MERKLE_DEPTH]);
        }
        if n == 5 {
            // 5 = 0b101 → bits[0]=1, [1]=0, [2]=1, rest 0.
            assert_eq!(direction_bytes[0], 1);
            assert_eq!(direction_bytes[1], 0);
            assert_eq!(direction_bytes[2], 1);
            for b in &direction_bytes[3..] {
                assert_eq!(*b, 0);
            }
        }
    }
}

// --------------------------------------------------------------------------
// Sentinel 12 — total ExecutorEnv input byte count
// --------------------------------------------------------------------------

#[test]
fn wire_total_executor_env_input_byte_count_is_788() {
    // `ExecutorEnvBuilder` does not expose a public accessor for the total
    // bytes it has buffered (`input` is `pub(crate)`), so we cannot directly
    // inspect the env. We pin the total via the per-field sizes that the
    // host writes, summing them the SAME way the guest sums its reads.
    //
    // If a future host call ever adds a new `write_slice`, this sum no
    // longer matches the guest's read total — every other sentinel in this
    // file (KATs, journal cross-check, extra-bytes test) catches the drift.
    //
    // We also pin the total against an actually-packed witness as a
    // belt-and-suspenders check: the independent packer in `pack_witness`
    // emits exactly 788 bytes.
    let (tree, members) = build_tree(5);
    let approver = &members[2];
    let proof = tree.proof(2).unwrap();
    let members_root = tree.root();
    let proposal_id = synthetic_proposal_id();
    let packed = pack_witness(
        &members_root,
        &proposal_id,
        &approver.sk,
        &approver.salt,
        &proof,
    );
    assert_eq!(packed.len(), 788);
    assert_eq!(packed.len(), WIRE_TOTAL_WITNESS_LEN);

    // Cross-check the sum against the guest-side read sizes lifted from
    // crypto / constants. If any constant moves (e.g. MERKLE_DEPTH bumps
    // to 21, SK_LEN bumps to 64) this assertion fails loudly, prompting
    // the wire format to be re-pinned.
    let guest_side_total = 64 + SK_LEN + SALT_LEN + MERKLE_DEPTH * HASH_LEN + MERKLE_DEPTH;
    assert_eq!(guest_side_total, 788);
    assert_eq!(guest_side_total, WIRE_TOTAL_WITNESS_LEN);

    // And the receipt produced from this exact 788-byte buffer must verify
    // and emit the canonical 96-byte journal — a runtime witness that the
    // pinned-size buffer is what the guest actually consumes.
    let journal = prove_with_input_bytes(&packed);
    assert_eq!(journal.len(), APPROVE_PUBLIC_INPUTS_LEN);
}
