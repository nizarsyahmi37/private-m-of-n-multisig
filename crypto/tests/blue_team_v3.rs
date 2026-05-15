//! Blue-team round 3: confirm prior FINDING-1 and FINDING-1b fixes still hold
//! and validate the round-2 ergonomic additions (`Identity::nullifier` plus
//! the crate-root re-exports).
//!
//! This file is the only file round-3 blue-team is allowed to touch. It does
//! not modify any source under `crypto/src/` nor any other test file.

#![allow(clippy::manual_memcpy, clippy::doc_lazy_continuation)]

use crypto::hash::{Hasher, Sha256Hasher, HASH_LEN};
use crypto::merkle::{MerkleProof, MerkleTree, MERKLE_DEPTH};
use crypto::nullifier;
use crypto::Identity;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

// ---------------------------------------------------------------------------
// Local helpers.
// ---------------------------------------------------------------------------

/// All-zero leaf used in the FINDING-1 forgery vector.
const ZERO_LEAF: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// Pre-fix attacker proof: all-zero siblings + all-zero indices. This is what
/// the original FINDING-1 exploit looked like before domain separation closed
/// it. After the fix, `verify_proof` first hashes the leaf under DOMAIN_LEAF,
/// so this chain can never close back to a real root.
fn undomained_zero_proof() -> MerkleProof {
    MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    }
}

/// Post-fix "real marker chain" — what the tree itself uses for empty subtrees.
/// `m[0] = hash_leaf([0;32])`, `m[k] = hash_node(m[k-1], m[k-1])`. Useful for
/// the FINDING-1b empty-tree forgery vector.
fn real_marker_chain_siblings() -> [[u8; HASH_LEN]; MERKLE_DEPTH] {
    let mut chain = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
    chain[0] = Sha256Hasher::hash_leaf(&[0u8; HASH_LEN]);
    for k in 1..=MERKLE_DEPTH {
        let prev = chain[k - 1];
        chain[k] = Sha256Hasher::hash_node(&prev, &prev);
    }
    let mut sib = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    sib.copy_from_slice(&chain[..MERKLE_DEPTH]);
    sib
}

/// Garbage proof of fixed-pattern bytes, used as a "any proof" sample.
fn garbage_proof(seed: u8) -> MerkleProof {
    let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for (i, s) in siblings.iter_mut().enumerate() {
        *s = [seed.wrapping_add(i as u8); HASH_LEN];
    }
    let mut indices = [false; MERKLE_DEPTH];
    for (i, b) in indices.iter_mut().enumerate() {
        *b = (i & 1) == 0;
    }
    MerkleProof { siblings, indices }
}

/// Build a populated tree of `n` arbitrary non-zero leaves. Leaves are
/// derived from a seeded RNG so the tree is deterministic per test.
fn populated_tree(n: usize, seed: u64) -> MerkleTree<Sha256Hasher> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut t = MerkleTree::<Sha256Hasher>::new();
    for _ in 0..n {
        let mut leaf = [0u8; HASH_LEN];
        rng.fill_bytes(&mut leaf);
        // Avoid the (astronomically unlikely) all-zero leaf — that would hit
        // the FINDING-1b guard at the input level, not what we want here.
        if leaf == ZERO_LEAF {
            leaf[0] = 1;
        }
        t.insert(leaf).unwrap();
    }
    t
}

// ---------------------------------------------------------------------------
// 1. FINDING-1 still closed across many tree sizes.
// ---------------------------------------------------------------------------

#[test]
fn finding1_remains_closed_under_varied_tree_sizes() {
    let sizes = [1usize, 2, 5, 17, 64, 1000];
    let proof = undomained_zero_proof();
    for &n in &sizes {
        let tree = populated_tree(n, 0xF1_F1_F1_F1 ^ n as u64);
        let root = tree.root();
        assert!(
            !crypto::verify_proof::<Sha256Hasher>(&root, &ZERO_LEAF, &proof),
            "FINDING-1 vector accepted at tree size {n}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. FINDING-1b still closed for empty tree regardless of proof contents.
// ---------------------------------------------------------------------------

#[test]
fn finding1b_remains_closed_for_empty_tree() {
    let empty = MerkleTree::<Sha256Hasher>::new();
    let empty_root = empty.root();

    // The real-marker-chain forgery — what FINDING-1b specifically guarded.
    let real_chain_proof = MerkleProof {
        siblings: real_marker_chain_siblings(),
        indices: [false; MERKLE_DEPTH],
    };
    assert!(!crypto::verify_proof::<Sha256Hasher>(&empty_root, &ZERO_LEAF, &real_chain_proof));

    // All-zeros proof (the pre-fix FINDING-1 vector).
    let all_zero_proof = undomained_zero_proof();
    assert!(!crypto::verify_proof::<Sha256Hasher>(&empty_root, &ZERO_LEAF, &all_zero_proof));

    // Garbage proofs across a range of seed bytes.
    for seed in 0u8..32 {
        let proof = garbage_proof(seed);
        assert!(
            !crypto::verify_proof::<Sha256Hasher>(&empty_root, &ZERO_LEAF, &proof),
            "FINDING-1b empty-root accepted garbage proof seed {seed}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. FINDING-1b guard is unconditional — fires regardless of root.
// ---------------------------------------------------------------------------

#[test]
fn finding1b_guard_is_unconditional() {
    let mut rng = StdRng::seed_from_u64(0xB1B1_B1B1_B1B1_B1B1);
    let proof = undomained_zero_proof();
    for i in 0..16 {
        let mut root = [0u8; HASH_LEN];
        rng.fill_bytes(&mut root);
        assert!(
            !crypto::verify_proof::<Sha256Hasher>(&root, &ZERO_LEAF, &proof),
            "FINDING-1b guard skipped for random root sample {i}"
        );
        // Also try with a different proof shape per root for completeness.
        let alt = garbage_proof(i as u8);
        assert!(
            !crypto::verify_proof::<Sha256Hasher>(&root, &ZERO_LEAF, &alt),
            "FINDING-1b guard skipped for random root sample {i} with garbage proof"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Identity::nullifier byte-equals the free function across many inputs.
// ---------------------------------------------------------------------------

#[test]
fn identity_nullifier_helper_byte_equals_free_function() {
    let mut rng = StdRng::seed_from_u64(0x4444_4444_4444_4444);
    for _ in 0..1000 {
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        let mut pid = [0u8; HASH_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut pid);
        let id = Identity::new(sk, salt);
        let via_method = id.nullifier::<Sha256Hasher>(&pid);
        let via_free = nullifier::<Sha256Hasher>(&sk, &pid);
        assert_eq!(via_method, via_free, "nullifier method/free divergence");
    }
}

// ---------------------------------------------------------------------------
// 5. Identity::nullifier ignores salt — canonical scheme property.
// ---------------------------------------------------------------------------

#[test]
fn identity_nullifier_independent_of_salt() {
    let sk = [0x37u8; 32];
    let pid = [0x42u8; HASH_LEN];
    let reference = Identity::new(sk, [0u8; 32]).nullifier::<Sha256Hasher>(&pid);

    let mut rng = StdRng::seed_from_u64(0x5A5A_5A5A);
    for _ in 0..200 {
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let id = Identity::new(sk, salt);
        let n = id.nullifier::<Sha256Hasher>(&pid);
        assert_eq!(n, reference, "salt leaked into nullifier (salt={salt:?})");
    }
}

// ---------------------------------------------------------------------------
// 6. Identity::nullifier varies with proposal_id.
// ---------------------------------------------------------------------------

#[test]
fn identity_nullifier_changes_with_pid() {
    let id = Identity::new([0x7Fu8; 32], [0x1Cu8; 32]);
    let mut rng = StdRng::seed_from_u64(0x6E6E_6E6E_6E6E_6E6E);
    let mut seen: std::collections::HashSet<[u8; HASH_LEN]> = std::collections::HashSet::new();
    for _ in 0..100 {
        let mut pid = [0u8; HASH_LEN];
        rng.fill_bytes(&mut pid);
        let n = id.nullifier::<Sha256Hasher>(&pid);
        assert!(seen.insert(n), "duplicate nullifier across distinct pids: {n:?}");
    }
    assert_eq!(seen.len(), 100);
}

// ---------------------------------------------------------------------------
// 7. Re-exports reachable directly from crate root.
// ---------------------------------------------------------------------------

#[test]
fn reexports_reachable_at_crate_root() {
    // Pulling these in via crate-root paths is the static check; the runtime
    // asserts confirm the values themselves haven't drifted.
    use crypto::{verify_proof, DOMAIN_LEAF, DOMAIN_NODE, MAX_LEAVES, SALT_LEN, SK_LEN};
    assert_eq!(DOMAIN_LEAF, 0x00);
    assert_eq!(DOMAIN_NODE, 0x01);
    assert_eq!(SK_LEN, 32);
    assert_eq!(SALT_LEN, 32);
    assert_eq!(MAX_LEAVES, 1usize << crypto::MERKLE_DEPTH);
    // Reference the re-exported function so an unused-import lint would
    // catch a missing re-export at compile time.
    let proof = undomained_zero_proof();
    let empty_root = MerkleTree::<Sha256Hasher>::new().root();
    let _ = verify_proof::<Sha256Hasher>(&empty_root, &ZERO_LEAF, &proof);
}

// ---------------------------------------------------------------------------
// 8. MAX_LEAVES == 1 << MERKLE_DEPTH exactly.
// ---------------------------------------------------------------------------

#[test]
fn max_leaves_matches_merkle_depth() {
    assert_eq!(crypto::MAX_LEAVES, 1usize << crypto::MERKLE_DEPTH);
}

// ---------------------------------------------------------------------------
// 9. SK_LEN and SALT_LEN are both HASH_LEN — Identity::commitment relies on it.
// ---------------------------------------------------------------------------

#[test]
fn sk_and_salt_lengths_match_hash_len() {
    assert_eq!(crypto::SK_LEN, HASH_LEN);
    assert_eq!(crypto::SALT_LEN, HASH_LEN);
}

// ---------------------------------------------------------------------------
// 10. FINDING-1 + FINDING-1b combined: zero leaf + undomained chain against
//     varied roots, including empty, populated, and random.
// ---------------------------------------------------------------------------

#[test]
fn combined_attack_finding1_and_finding1b_simultaneous() {
    let empty_root = MerkleTree::<Sha256Hasher>::new().root();
    let populated_root = populated_tree(7, 0xC0_FF_EE).root();
    let big_root = populated_tree(123, 0xDEAD_BEEF).root();
    let mut rng = StdRng::seed_from_u64(0xCAFEBABE);
    let mut random_roots: Vec<[u8; HASH_LEN]> = Vec::new();
    for _ in 0..8 {
        let mut r = [0u8; HASH_LEN];
        rng.fill_bytes(&mut r);
        random_roots.push(r);
    }

    let proofs = [
        undomained_zero_proof(),
        MerkleProof {
            siblings: real_marker_chain_siblings(),
            indices: [false; MERKLE_DEPTH],
        },
        garbage_proof(0xAA),
        garbage_proof(0x55),
    ];

    let mut roots = vec![empty_root, populated_root, big_root];
    roots.extend(random_roots);

    for root in &roots {
        for proof in &proofs {
            assert!(
                !crypto::verify_proof::<Sha256Hasher>(root, &ZERO_LEAF, proof),
                "combined zero-leaf attack accepted (root={:?})",
                hex::encode(root)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 11. Positive path still works after both fixes — 32 honest members.
// ---------------------------------------------------------------------------

#[test]
fn positive_path_still_works_after_both_fixes() {
    let mut rng = StdRng::seed_from_u64(0x11_22_33_44);
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut leaves: Vec<[u8; HASH_LEN]> = Vec::new();
    for i in 0..32 {
        let mut l = [0u8; HASH_LEN];
        rng.fill_bytes(&mut l);
        // Per the spec: leaf[31] = 0xFF so no honest leaf can collide with
        // the FINDING-1b zero-leaf guard (and also to make this hermetic
        // against any RNG state that might one day land on [0;32]).
        l[31] = 0xFF;
        leaves.push(l);
        tree.insert(l).unwrap();
        let _ = i;
    }
    let root = tree.root();
    for (i, l) in leaves.iter().enumerate() {
        let p = tree.proof(i).unwrap();
        assert!(
            crypto::verify_proof::<Sha256Hasher>(&root, l, &p),
            "positive verification failed for member {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// 12. Identity Debug still redacts after calling .nullifier(&pid).
// ---------------------------------------------------------------------------

#[test]
fn identity_debug_still_redacts_with_nullifier_call() {
    let id = Identity::new([0xAB; 32], [0xCD; 32]);
    let pid = [0xEFu8; HASH_LEN];
    let _ = id.nullifier::<Sha256Hasher>(&pid);
    let rendered = format!("{:?}", id);
    assert!(rendered.contains("[REDACTED]"), "Debug stopped redacting: {rendered}");
    assert!(!rendered.contains("ab"), "Debug leaked sk hex: {rendered}");
    assert!(!rendered.contains("cd"), "Debug leaked salt hex: {rendered}");
}

// ---------------------------------------------------------------------------
// 13. The re-exported verify_proof is the same function as merkle::verify_proof.
// ---------------------------------------------------------------------------

#[test]
fn reexported_verify_proof_is_same_function() {
    // Same function-pointer would also be a fine assertion, but the contract
    // we care about is identical behavior on identical inputs across both
    // positive and negative cases.
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut rng = StdRng::seed_from_u64(0x13_13_13_13);
    let mut leaves = Vec::new();
    for _ in 0..8 {
        let mut l = [0u8; HASH_LEN];
        rng.fill_bytes(&mut l);
        l[31] |= 1; // keep away from the FINDING-1b guard
        leaves.push(l);
        tree.insert(l).unwrap();
    }
    let root = tree.root();

    // Positive cases.
    for (i, l) in leaves.iter().enumerate() {
        let p = tree.proof(i).unwrap();
        let via_root = crypto::verify_proof::<Sha256Hasher>(&root, l, &p);
        let via_module = crypto::merkle::verify_proof::<Sha256Hasher>(&root, l, &p);
        assert_eq!(via_root, via_module, "verify_proof divergence on leaf {i}");
        assert!(via_root);
    }

    // Negative cases: bad root, bad leaf, FINDING-1 vector, FINDING-1b vector.
    let proof_for_0 = tree.proof(0).unwrap();
    let bad_root = [0xFFu8; HASH_LEN];
    assert_eq!(
        crypto::verify_proof::<Sha256Hasher>(&bad_root, &leaves[0], &proof_for_0),
        crypto::merkle::verify_proof::<Sha256Hasher>(&bad_root, &leaves[0], &proof_for_0),
    );

    let mut wrong_leaf = leaves[0];
    wrong_leaf[0] ^= 0xFF;
    assert_eq!(
        crypto::verify_proof::<Sha256Hasher>(&root, &wrong_leaf, &proof_for_0),
        crypto::merkle::verify_proof::<Sha256Hasher>(&root, &wrong_leaf, &proof_for_0),
    );

    let f1 = undomained_zero_proof();
    assert_eq!(
        crypto::verify_proof::<Sha256Hasher>(&root, &ZERO_LEAF, &f1),
        crypto::merkle::verify_proof::<Sha256Hasher>(&root, &ZERO_LEAF, &f1),
    );

    let f1b = MerkleProof {
        siblings: real_marker_chain_siblings(),
        indices: [false; MERKLE_DEPTH],
    };
    let empty_root = MerkleTree::<Sha256Hasher>::new().root();
    assert_eq!(
        crypto::verify_proof::<Sha256Hasher>(&empty_root, &ZERO_LEAF, &f1b),
        crypto::merkle::verify_proof::<Sha256Hasher>(&empty_root, &ZERO_LEAF, &f1b),
    );
}

// ---------------------------------------------------------------------------
// 14. FINDING-1b guard is `[0;32]`-specific, not over-broad.
//     - [0xFF;32], [0xAA;32], hash_leaf([0;32]) all clear the input-level guard.
//     - The walk may still reject them on root mismatch; that's expected.
// ---------------------------------------------------------------------------

#[test]
fn finding1b_does_not_reject_other_special_values() {
    // Build a tree that actually contains each of these as members so we can
    // observe the guard is not the rejection reason (the proof verifies).
    let special_leaves: [[u8; HASH_LEN]; 3] = [
        [0xFFu8; HASH_LEN],
        [0xAAu8; HASH_LEN],
        Sha256Hasher::hash_leaf(&[0u8; HASH_LEN]),
    ];
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for l in &special_leaves {
        tree.insert(*l).unwrap();
    }
    let root = tree.root();

    // Positive: each special leaf with its honest proof verifies. The
    // FINDING-1b guard fires ONLY for `[0;32]`, never for these values.
    for (i, l) in special_leaves.iter().enumerate() {
        let p = tree.proof(i).unwrap();
        assert!(
            crypto::verify_proof::<Sha256Hasher>(&root, l, &p),
            "leaf {i} ({}) wrongly rejected by FINDING-1b guard",
            hex::encode(l)
        );
    }

    // Negative-but-not-via-guard: a wrong root with one of these leaves fails
    // because the walk doesn't close, not because of any input-level guard.
    let wrong_root = [0u8; HASH_LEN];
    for l in &special_leaves {
        let p = tree.proof(0).unwrap();
        assert!(!crypto::verify_proof::<Sha256Hasher>(&wrong_root, l, &p));
    }

    // Final sanity: confirm the guard explicitly only fires on ZERO_LEAF by
    // showing that a single-bit perturbation of ZERO_LEAF *does not* hit the
    // guard. (It will still fail verification — that's fine; we are only
    // proving the guard isn't trapping more values than `[0;32]`.)
    let mut almost_zero = [0u8; HASH_LEN];
    almost_zero[0] = 1;
    let mini_tree = {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        t.insert(almost_zero).unwrap();
        t
    };
    let p = mini_tree.proof(0).unwrap();
    assert!(
        crypto::verify_proof::<Sha256Hasher>(&mini_tree.root(), &almost_zero, &p),
        "near-zero leaf (single bit set) wrongly rejected"
    );
    // And nudge the Rng import alive so clippy doesn't complain.
    let _ = StdRng::seed_from_u64(0).gen::<u8>();
}
