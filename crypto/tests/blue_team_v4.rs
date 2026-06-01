//! Blue-team round 4: reliability under varied conditions.
//!
//! Prior rounds locked structural correctness (FINDING-1 / FINDING-1b).
//! This round validates that the crate's outputs are byte-identical across
//! `--release` vs default profiles, are repeatable across 100 runs of the
//! same inputs, and are race-free when exercised from many OS threads at
//! once.
//!
//! Strategy for the "debug vs release parity" tests: a test process can
//! only see one build profile at a time, so we pin hard-coded expected
//! byte vectors (computed independently from the reference SHA-256 path).
//! Both `cargo test` and `cargo test --release` then have to land on the
//! exact same bytes; any compiler optimisation that broke correctness
//! would diverge here. The vectors below were generated from a stand-
//! alone Python reference using the same `H(DOMAIN ‖ payload)` recipe the
//! crate uses, and they also line up with the round-3 KAT pins in
//! `differential.rs::ref_known_answer_vectors`.

#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;
use std::thread;

use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};
use sha2::{Digest, Sha256};

use crypto::{
    nullifier, verify_proof, Hash, Hasher, Identity, MerkleError, MerkleProof, MerkleTree,
    Sha256Hasher, HASH_LEN, MERKLE_DEPTH,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn decode_hex(s: &str) -> Hash {
    let bytes = hex::decode(s).expect("valid hex");
    assert_eq!(bytes.len(), HASH_LEN, "expected 32-byte hex literal");
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&bytes);
    out
}

/// Reference SHA-256 (used by the parity tests to derive expected bytes
/// without going through any `Hasher` machinery — keeps the "pinned"
/// outputs honest).
fn ref_sha256(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Build a fresh tree from a leaf list, deterministically.
fn build_tree(leaves: &[Hash]) -> MerkleTree<Sha256Hasher> {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    for l in leaves {
        t.insert(*l).expect("under capacity");
    }
    t
}

/// Random leaf that is guaranteed non-zero (the all-zero leaf trips the
/// FINDING-1b guard inside `verify_proof`).
fn random_nonzero_leaf<R: Rng>(rng: &mut R) -> Hash {
    loop {
        let mut leaf = [0u8; HASH_LEN];
        rng.fill_bytes(&mut leaf);
        if leaf != [0u8; HASH_LEN] {
            return leaf;
        }
    }
}

// ---------------------------------------------------------------------------
// 1–4. Debug/release parity — pinned expected bytes
// ---------------------------------------------------------------------------

/// Pinned outputs from the size-3 tree (leaves = [1;32], [2;32], [3;32]).
/// Recomputed independently via the reference SHA-256 path. If a compiler
/// optimisation in `--release` ever broke correctness, the assertions
/// below would fail there even though they pass in debug (or vice versa).
const SIZE3_LEAF_BYTES: [u8; 3] = [1, 2, 3];
const SIZE3_ROOT_HEX: &str = "fd7fcba86a73ede96174eb4ccca829adfba7a8cb3e2d5ffe51d71ebabf65c717";

/// Sibling hashes for proofs at indices 0, 1, 2. The first sibling
/// differs by index (it pairs with the leaf's neighbour), the remaining
/// 19 siblings are level-by-level zero-marker hashes that every proof in
/// a size-3 tree shares.
const SIZE3_PROOF0_SIB0_HEX: &str =
    "cba8c596120bdb69debbd923d92cba948bde7c7d06a465a1bb7d98d3116038fa";
const SIZE3_PROOF1_SIB0_HEX: &str =
    "dcffe786ded16d283c663846ad0c4ff26558fccde36ca9d30b2ea19eade9fc0e";
const SIZE3_PROOF2_SIB0_HEX: &str =
    "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9";
const SIZE3_PROOF2_SIB1_HEX: &str =
    "3a066e0f40c6a1981ebfa60d2411625d0517ae22c2fc8c7c1784ff8a75c78565";

/// Levels 1..=19 of every proof in a size-3 tree share the same sibling:
/// the right child of the level is the empty-subtree zero marker for that
/// level (because positions ≥ 4 are unmaterialised). For indices 0 and 1,
/// level 1's sibling is the hash of the size-2 left-subtree pair; for
/// index 2, level 1's sibling is the all-empty pair (KAT2-derived). From
/// level 2 upward the chain is identical for all three proofs.
const SHARED_LEVEL2_PLUS: [&str; MERKLE_DEPTH - 2] = [
    "b46fd516fa6c7dcddd52ac2be2a014d8a8de4eaa059f79ccfcff4b8afc4e7ddc",
    "dcc995ad7e4c442877c1f381f5e9532822114c527a2cb1669696a42105488a5d",
    "3f54a275d259bc683a263f0ae5809e0ca6381536908a2c7b083d0aef044f1956",
    "cc04e6c411121fdbc9d9d9ea13ba2658b1a1e086f3f9f16d6cc418f03d1c4b6b",
    "5306dd8207978ef077b01ca9612225562f3051b027192cb6ef758dfc52670cd3",
    "91ae393299f3722972eb083c65d3da84ebbbec2bad40f900d505cff543d4573e",
    "f76add9d82489f11e3532ba85dfc66dd01d468651a686046c7534d18c5ae4fc8",
    "c6f47196c4c087cad09335bd106416c4896caa73c29324ec44dfe59dc670bf10",
    "d2948da475c50d98dc4528ece6d29b2152781b7badec36925e1ef9f539ba4f86",
    "527410b8f58e3d549c9eb4393586e8bf4b3522a4a105411268241d697492a2c6",
    "ffc30445f8b033cef1b062a277ac202de5b58fc4a4e68f22b8d7e2519bd3a2c2",
    "7ad649618ec6a58f7eb682d01811fb7202f3ab7bf15e849f847cd6ebdafac203",
    "460b0772986c22995335e8e4f738a976a4b4969140e102c4b9ea8083636f63b1",
    "63e87940e6ad90bd30a75b347ff7aac1390d54c2bb85542703c587959ccb032f",
    "f27815d173ff44959dc7f08284b57a28a18b7c329d3f7c2ff98fabcce0651c80",
    "5a27e6ce227b39fc5ef4e32792468ae217aa62b92134ee05cec47fa27b6b27db",
    "282a8df3af2e9dd9d0d565ed8cf9b942e52cef31b1793bd178f4f12a5965fffb",
    "f80c4cc530d5f8c2a9572b4448d20ac923820d858cea1ee06a7a5aa9e4c8cad9",
];

fn size3_leaves() -> Vec<Hash> {
    SIZE3_LEAF_BYTES.iter().map(|b| [*b; HASH_LEN]).collect()
}

/// Reconstruct the expected siblings array for proof at `index` (0, 1, 2)
/// using the pinned hex literals above.
fn expected_siblings_for(index: usize) -> [Hash; MERKLE_DEPTH] {
    let mut sibs = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    let (sib0, sib1) = match index {
        0 => (
            SIZE3_PROOF0_SIB0_HEX,
            // proof 0's level-1 sibling is the hash of the (leaf2, empty)
            // pair — same as proof 1's level-1 sibling. We share it.
            "d39150294c56bc6520394195dc94419c4244dd447ceae2035dfe4f0dc8720278",
        ),
        1 => (
            SIZE3_PROOF1_SIB0_HEX,
            "d39150294c56bc6520394195dc94419c4244dd447ceae2035dfe4f0dc8720278",
        ),
        2 => (SIZE3_PROOF2_SIB0_HEX, SIZE3_PROOF2_SIB1_HEX),
        _ => unreachable!("size-3 tree only has indices 0..3"),
    };
    sibs[0] = decode_hex(sib0);
    sibs[1] = decode_hex(sib1);
    for (i, hex_str) in SHARED_LEVEL2_PLUS.iter().enumerate() {
        sibs[2 + i] = decode_hex(hex_str);
    }
    sibs
}

fn expected_indices_for(index: usize) -> [bool; MERKLE_DEPTH] {
    let mut out = [false; MERKLE_DEPTH];
    out[0] = index & 1 == 1;
    out[1] = (index >> 1) & 1 == 1;
    // levels 2..=19 always 0 because index < 4 < 2^2.
    out
}

#[test]
fn debug_release_parity_verify_proof() {
    let leaves = size3_leaves();
    let tree = build_tree(&leaves);

    // 1. Root must match the pinned value byte-for-byte.
    let expected_root = decode_hex(SIZE3_ROOT_HEX);
    assert_eq!(
        tree.root(),
        expected_root,
        "size-3 root drift (debug-vs-release parity)"
    );

    // 2. Each proof's siblings and indices match the pinned arrays.
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof(i).expect("proof in range");
        assert_eq!(
            proof.siblings,
            expected_siblings_for(i),
            "proof {i} siblings drift"
        );
        assert_eq!(
            proof.indices,
            expected_indices_for(i),
            "proof {i} indices drift"
        );
        // 3. verify_proof must return true and must produce a value
        //    that equals the pinned root if we manually walk the path.
        assert!(
            verify_proof::<Sha256Hasher>(&tree.root(), leaf, &proof),
            "verify_proof drifted for index {i}"
        );

        // 4. Walk the proof by hand using the reference SHA-256 path and
        //    confirm we land on the same root the tree computes — this
        //    is the property a compiler bug could break independently.
        let mut current = ref_sha256(&{
            let mut buf = [0u8; 1 + HASH_LEN];
            buf[0] = 0x00;
            buf[1..].copy_from_slice(leaf);
            buf
        });
        for level in 0..MERKLE_DEPTH {
            let sibling = proof.siblings[level];
            let (l, r) = if proof.indices[level] {
                (sibling, current)
            } else {
                (current, sibling)
            };
            let mut buf = [0u8; 1 + 2 * HASH_LEN];
            buf[0] = 0x01;
            buf[1..1 + HASH_LEN].copy_from_slice(&l);
            buf[1 + HASH_LEN..].copy_from_slice(&r);
            current = ref_sha256(&buf);
        }
        assert_eq!(
            current, expected_root,
            "manual walk failed for index {i} (parity broken)"
        );
    }

    // 5. Negative — wrong leaf should not verify. Pins behaviour in both
    //    profiles.
    let wrong_leaf = [0xEEu8; HASH_LEN];
    let proof0 = tree.proof(0).unwrap();
    assert!(
        !verify_proof::<Sha256Hasher>(&tree.root(), &wrong_leaf, &proof0),
        "verify_proof unexpectedly accepted a wrong leaf"
    );
}

#[test]
fn debug_release_parity_nullifier() {
    // sk = [0xAA;32], pid = [0xBB;32]
    // expected = SHA256(sk ‖ pid) = e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6
    let sk = [0xAAu8; 32];
    let pid = [0xBBu8; HASH_LEN];
    let expected = decode_hex("e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6");
    assert_eq!(
        nullifier::<Sha256Hasher>(&sk, &pid),
        expected,
        "nullifier output drifted between profiles"
    );

    // Same value reached via the Identity helper — both call sites must
    // agree, in both profiles.
    let id = Identity::new(sk, [0u8; 32]);
    assert_eq!(
        id.nullifier::<Sha256Hasher>(&pid),
        expected,
        "Identity::nullifier drifted from free function"
    );

    // And independent reference path: H(sk ‖ pid) via raw SHA-256.
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&sk);
    buf[32..].copy_from_slice(&pid);
    assert_eq!(
        ref_sha256(&buf),
        expected,
        "reference SHA-256 path drifted (compiler/sha2 bug?)"
    );
}

#[test]
fn debug_release_parity_commitment() {
    // sk = [0x55;32], salt = [0x66;32]
    // expected = SHA256(sk ‖ salt) = c0e763c35fb9ae653e27d88907dc7a58e3012f7cedbbc03f9124f25a8dc2d2da
    let id = Identity::new([0x55u8; 32], [0x66u8; 32]);
    let expected = decode_hex("c0e763c35fb9ae653e27d88907dc7a58e3012f7cedbbc03f9124f25a8dc2d2da");
    let c = id.commitment::<Sha256Hasher>();
    assert_eq!(
        *c.as_bytes(),
        expected,
        "Identity::commitment drifted between profiles"
    );

    // Reference path.
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&[0x55u8; 32]);
    buf[32..].copy_from_slice(&[0x66u8; 32]);
    assert_eq!(
        ref_sha256(&buf),
        expected,
        "reference SHA-256 commitment drift"
    );
}

#[test]
fn debug_release_parity_hash_leaf_and_hash_node() {
    // Pin matches differential.rs::ref_known_answer_vectors KAT2 / KAT3.
    let expected_hash_leaf =
        decode_hex("7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9");
    let expected_hash_node =
        decode_hex("b331da6ec49d4547d9942a6727e5123f69bed5a0b97ac171cfbfd6201431fcfa");

    assert_eq!(
        Sha256Hasher::hash_leaf(&[0u8; HASH_LEN]),
        expected_hash_leaf,
        "hash_leaf([0;32]) drifted (debug-vs-release)"
    );
    assert_eq!(
        Sha256Hasher::hash_node(&[1u8; HASH_LEN], &[2u8; HASH_LEN]),
        expected_hash_node,
        "hash_node([1;32],[2;32]) drifted (debug-vs-release)"
    );
}

// ---------------------------------------------------------------------------
// 5. Repeat-run determinism
// ---------------------------------------------------------------------------

#[test]
fn repeat_run_same_inputs_same_outputs_100x() {
    // Five fixed (tree_size, proof_idx) configurations and one fixed
    // leaf-set seed per config. The full enroll-prove-verify loop is run
    // 100 times for each config; every output (root, proof, verify
    // result) must be byte-equal to the first run's output.
    //
    // Sentinel for HashMap order regressions or any other hidden
    // non-determinism introduced in the future.
    let configs: [(usize, usize, u64); 5] = [
        (5, 0, 0xA5A5_A5A5_A5A5_A5A5),
        (16, 7, 0x1234_5678_9ABC_DEF0),
        (32, 31, 0xDEAD_BEEF_CAFE_BABE),
        (64, 13, 0x0F0F_0F0F_0F0F_0F0F),
        (100, 50, 0x0123_4567_89AB_CDEF),
    ];

    for (tree_size, proof_idx, seed) in configs {
        let mut rng = StdRng::seed_from_u64(seed);
        let leaves: Vec<Hash> = (0..tree_size)
            .map(|_| random_nonzero_leaf(&mut rng))
            .collect();

        // Reference run.
        let ref_tree = build_tree(&leaves);
        let ref_root = ref_tree.root();
        let ref_proof = ref_tree.proof(proof_idx).expect("idx in range");
        let ref_verify = verify_proof::<Sha256Hasher>(&ref_root, &leaves[proof_idx], &ref_proof);
        assert!(ref_verify, "reference verify must succeed");

        for run in 1..100 {
            let tree = build_tree(&leaves);
            let root = tree.root();
            let proof = tree.proof(proof_idx).expect("idx in range");
            let ok = verify_proof::<Sha256Hasher>(&root, &leaves[proof_idx], &proof);

            assert_eq!(
                root, ref_root,
                "non-determinism: root differs at run {run} for size {tree_size}"
            );
            assert_eq!(
                proof.siblings, ref_proof.siblings,
                "non-determinism: proof siblings differ at run {run}"
            );
            assert_eq!(
                proof.indices, ref_proof.indices,
                "non-determinism: proof indices differ at run {run}"
            );
            assert!(ok, "non-determinism: verify result differs at run {run}");
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Parallel verify_proof — no race
// ---------------------------------------------------------------------------

#[test]
fn parallel_verify_proof_no_race() {
    // Build a populated tree once, derive 100 proofs, then have 16
    // threads each verify every one of them 100 times against the same
    // root. With 16 × 100 × 100 = 160 000 verifications we'd notice
    // even a rare race or torn read; in practice the Hasher trait is
    // zero-state and this should be rock-solid.
    let mut rng = StdRng::seed_from_u64(0xBEEF_F00D_BEEF_F00D);
    let leaves: Vec<Hash> = (0..100).map(|_| random_nonzero_leaf(&mut rng)).collect();
    let tree = build_tree(&leaves);
    let root = tree.root();
    let proofs: Vec<(Hash, MerkleProof)> = leaves
        .iter()
        .enumerate()
        .map(|(i, l)| (*l, tree.proof(i).expect("in range")))
        .collect();

    let shared_root = Arc::new(root);
    let shared_proofs = Arc::new(proofs);

    let mut handles = Vec::new();
    for _ in 0..16 {
        let r = Arc::clone(&shared_root);
        let p = Arc::clone(&shared_proofs);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                for (leaf, proof) in p.iter() {
                    let ok = verify_proof::<Sha256Hasher>(&r, leaf, proof);
                    assert!(ok, "parallel verify_proof returned false under load");
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("worker panicked");
    }

    // Sanity tail: after all the parallel hammering, the proofs and root
    // are still what we started with.
    assert_eq!(*shared_root, root);
    for (i, (leaf, proof)) in shared_proofs.iter().enumerate() {
        assert!(
            verify_proof::<Sha256Hasher>(&root, leaf, proof),
            "post-parallel verify failed at index {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Parallel independent tree builds — same input ⇒ same root
// ---------------------------------------------------------------------------

#[test]
fn parallel_merkle_tree_builds_independent() {
    let mut rng = StdRng::seed_from_u64(0xC0FF_EE00_C0FF_EE00);
    let leaves: Vec<Hash> = (0..64).map(|_| random_nonzero_leaf(&mut rng)).collect();
    let shared_leaves = Arc::new(leaves);

    let serial_root = build_tree(&shared_leaves).root();

    let mut handles = Vec::new();
    for _ in 0..4 {
        let l = Arc::clone(&shared_leaves);
        handles.push(thread::spawn(move || build_tree(&l).root()));
    }
    for h in handles {
        let r = h.join().expect("worker panicked");
        assert_eq!(
            r, serial_root,
            "parallel build produced a different root from serial build"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Parallel Identity::commitment — no state leak
// ---------------------------------------------------------------------------

#[test]
fn parallel_identity_commitment_no_state_leak() {
    // Eight threads, each computing commitments for a distinct slice of
    // identities. Compare against a serial reference and check that no
    // two distinct (sk, salt) tuples produce the same commitment (under
    // SHA-256 collision resistance — the chance of an accidental
    // collision in 64 random pairs is negligible).
    const PER_THREAD: usize = 8;
    const N_THREADS: usize = 8;

    // Build a deterministic list of 64 distinct identities.
    let mut rng = StdRng::seed_from_u64(0xFACE_FEED_FACE_FEED);
    let mut ids: Vec<Identity> = Vec::with_capacity(N_THREADS * PER_THREAD);
    for _ in 0..(N_THREADS * PER_THREAD) {
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        ids.push(Identity::new(sk, salt));
    }

    // Reference results.
    let reference: Vec<Hash> = ids
        .iter()
        .map(|id| *id.commitment::<Sha256Hasher>().as_bytes())
        .collect();

    let shared_ids = Arc::new(ids);

    let mut handles = Vec::new();
    for t in 0..N_THREADS {
        let ids = Arc::clone(&shared_ids);
        handles.push(thread::spawn(move || {
            let mut out = Vec::with_capacity(PER_THREAD);
            for k in 0..PER_THREAD {
                let i = t * PER_THREAD + k;
                out.push((i, *ids[i].commitment::<Sha256Hasher>().as_bytes()));
            }
            out
        }));
    }

    let mut collected: Vec<(usize, Hash)> = Vec::new();
    for h in handles {
        collected.extend(h.join().expect("worker panicked"));
    }

    // 1. Each thread's commitment matches the serial reference (i.e. no
    //    cross-thread contamination of inputs ⇒ outputs).
    for (i, c) in &collected {
        assert_eq!(
            *c, reference[*i],
            "parallel commitment for id {i} diverged from serial reference"
        );
    }

    // 2. All 64 distinct-input commitments are pairwise distinct. A
    //    collision here would either be a state leak or an astronomical
    //    SHA-256 collision (1 in 2^128 per pair — not happening).
    let mut sorted: Vec<Hash> = collected.iter().map(|(_, c)| *c).collect();
    sorted.sort();
    for w in sorted.windows(2) {
        assert_ne!(
            w[0], w[1],
            "distinct identities produced colliding commitment"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. Root must change on every insert (no stale-cache regression)
// ---------------------------------------------------------------------------

#[test]
fn tree_grow_one_leaf_at_a_time_root_changes_monotonically() {
    let mut rng = StdRng::seed_from_u64(0xDA7A_BA5E_DA7A_BA5E);
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut roots: Vec<Hash> = Vec::with_capacity(32);

    for _ in 0..32 {
        let leaf = random_nonzero_leaf(&mut rng);
        tree.insert(leaf).expect("under capacity");
        roots.push(tree.root());
    }

    assert_eq!(roots.len(), 32);
    for (i, w) in roots.windows(2).enumerate() {
        assert_ne!(
            w[0],
            w[1],
            "consecutive roots after insert {} and {} matched — stale cache?",
            i,
            i + 1
        );
    }

    // Tighter sentinel: ALL 32 roots distinct, not just consecutive.
    let mut sorted = roots.clone();
    sorted.sort();
    for w in sorted.windows(2) {
        assert_ne!(w[0], w[1], "two roots in the growth sequence matched");
    }
}

// ---------------------------------------------------------------------------
// 10. Proof from an earlier state still verifies against the LATEST root
//     (append-only Merkle tree property)
// ---------------------------------------------------------------------------

#[test]
fn tree_proof_after_insert_uses_latest_root() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let a = [0x11u8; HASH_LEN];
    let idx_a = tree.insert(a).unwrap();
    let proof_a = tree.proof(idx_a).expect("proof for a");
    let root_before = tree.root();
    assert!(
        verify_proof::<Sha256Hasher>(&root_before, &a, &proof_a),
        "proof for a fails against its own root"
    );

    // Insert leaf B; the root has now moved.
    let b = [0x22u8; HASH_LEN];
    tree.insert(b).unwrap();
    let root_after = tree.root();
    assert_ne!(root_before, root_after, "root must change after insert");

    // The ORIGINAL proof_a no longer verifies against the new root —
    // append-only Merkle trees do NOT preserve old proofs verbatim,
    // because A's siblings at higher levels were the zero markers and
    // now include B's subtree. The caller must regenerate the proof
    // from the current tree state.
    assert!(
        !verify_proof::<Sha256Hasher>(&root_after, &a, &proof_a),
        "stale proof unexpectedly verified — invariant violated"
    );

    // The freshly issued proof for A against the new tree state DOES
    // verify against the new root. This is the actual append-only
    // property the system relies on: every member can re-derive a valid
    // proof from the public leaf history at the current state.
    let proof_a_fresh = tree.proof(idx_a).expect("a still in tree");
    assert!(
        verify_proof::<Sha256Hasher>(&root_after, &a, &proof_a_fresh),
        "regenerated proof for a fails against the new root"
    );

    // And B's proof verifies too.
    let proof_b = tree.proof(1).expect("b in tree");
    assert!(verify_proof::<Sha256Hasher>(&root_after, &b, &proof_b));
}

// ---------------------------------------------------------------------------
// 11. hash_pair non-associativity sentinel
// ---------------------------------------------------------------------------

#[test]
fn hash_pair_associativity_sentinel() {
    let a = [0x11u8; HASH_LEN];
    let b = [0x22u8; HASH_LEN];
    let c = [0x33u8; HASH_LEN];

    // hash_pair is exposed at the Hasher trait level.
    let left = Sha256Hasher::hash_pair(&Sha256Hasher::hash_pair(&a, &b), &c);
    let right = Sha256Hasher::hash_pair(&a, &Sha256Hasher::hash_pair(&b, &c));
    assert_ne!(
        left, right,
        "hash_pair appears associative — major regression"
    );

    // Same sentinel against hash_node, the domain-separated variant the
    // tree uses internally. If someone accidentally collapses the domain
    // byte path the inequality could vanish.
    let left_n = Sha256Hasher::hash_node(&Sha256Hasher::hash_node(&a, &b), &c);
    let right_n = Sha256Hasher::hash_node(&a, &Sha256Hasher::hash_node(&b, &c));
    assert_ne!(
        left_n, right_n,
        "hash_node appears associative — major regression"
    );
}

// ---------------------------------------------------------------------------
// 12. Error paths must not corrupt state
// ---------------------------------------------------------------------------

#[test]
fn error_paths_dont_corrupt_state() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let l1 = [0x01u8; HASH_LEN];
    let l2 = [0x02u8; HASH_LEN];
    tree.insert(l1).unwrap();
    tree.insert(l2).unwrap();

    let root_before = tree.root();
    let proof_l1_before = tree.proof(0).unwrap();
    assert!(verify_proof::<Sha256Hasher>(
        &root_before,
        &l1,
        &proof_l1_before
    ));

    // Trigger an error: out-of-range proof.
    match tree.proof(usize::MAX) {
        Err(MerkleError::IndexOutOfRange { index, next }) => {
            assert_eq!(index, usize::MAX);
            assert_eq!(next, 2);
        }
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }

    // Trigger a SECOND, different error path: another out-of-range.
    assert!(tree.proof(2).is_err());

    // Now confirm every positive operation still produces the same
    // results as before the errors. State must be untouched.
    assert_eq!(tree.root(), root_before, "root mutated by error path");
    assert_eq!(tree.len(), 2, "len mutated by error path");
    let proof_l1_after = tree.proof(0).unwrap();
    assert_eq!(
        proof_l1_after, proof_l1_before,
        "proof regenerated after error differs from pre-error proof"
    );
    assert!(
        verify_proof::<Sha256Hasher>(&tree.root(), &l1, &proof_l1_after),
        "verify failed after error path"
    );

    // And we can still insert further leaves cleanly.
    let l3 = [0x03u8; HASH_LEN];
    let idx3 = tree.insert(l3).expect("insert after errors should work");
    assert_eq!(idx3, 2);
    let proof_l3 = tree.proof(idx3).unwrap();
    assert!(verify_proof::<Sha256Hasher>(&tree.root(), &l3, &proof_l3));
}

// ---------------------------------------------------------------------------
// 13. MerkleTree::default() === MerkleTree::new()
// ---------------------------------------------------------------------------

#[test]
fn merkle_tree_default_equals_new() {
    let d = MerkleTree::<Sha256Hasher>::default();
    let n = MerkleTree::<Sha256Hasher>::new();
    assert_eq!(
        d.root(),
        n.root(),
        "Default::default and ::new disagree on root"
    );
    assert_eq!(
        d.len(),
        n.len(),
        "Default::default and ::new disagree on len"
    );
    assert!(d.is_empty());
    assert!(n.is_empty());
    assert_eq!(d.capacity(), n.capacity());

    // Behavioural parity: inserting the same leaf into each yields the
    // same post-insert root.
    let mut d = d;
    let mut n = n;
    let leaf = [0x9Au8; HASH_LEN];
    d.insert(leaf).unwrap();
    n.insert(leaf).unwrap();
    assert_eq!(
        d.root(),
        n.root(),
        "trees diverged after identical insert (Default vs new)"
    );
}

// ---------------------------------------------------------------------------
// Small helper sanity — not a defense, just keeps the file honest if the
// random helper ever started yielding the all-zero leaf.
// ---------------------------------------------------------------------------

#[test]
fn helper_random_nonzero_leaf_is_nonzero() {
    let mut rng = StdRng::seed_from_u64(1);
    for _ in 0..1024 {
        let l: Hash = random_nonzero_leaf(&mut rng);
        assert_ne!(l, [0u8; HASH_LEN]);
    }
    // Quick smoke check on a few Rng calls so unused-import lints don't
    // bite if the API ever changes.
    let mut rng2 = StdRng::seed_from_u64(2);
    let _: u32 = rng2.random();
}
