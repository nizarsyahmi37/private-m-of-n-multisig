//! Round-2 blue-team validation suite for the LP-0002 crypto core.
//!
//! Round 1 found FINDING-1 (HIGH): an undomained Merkle tree allowed any
//! attacker who knew `members_root` to forge membership at any unused slot
//! using `leaf = [0;32]` and an all-zero sibling chain. The fix introduced
//! domain separation:
//!   - `Hasher::hash_leaf(leaf)`  = H(DOMAIN_LEAF=0x00 ‖ leaf)
//!   - `Hasher::hash_node(l, r)`  = H(DOMAIN_NODE=0x01 ‖ l ‖ r)
//! `MerkleTree` now builds `zero_hashes` from `hash_leaf(&[0;32])` at level 0
//! and `hash_node(...)` upward; `verify_proof` applies `hash_leaf` to the
//! input leaf first, then walks the path with `hash_node`. `hash_pair` remains
//! exposed but is no longer used by the Merkle tree.
//!
//! Each test below confirms ONE post-fix property the rest of the system
//! relies on. Failures here invalidate the FINDING-1 mitigation.

#![allow(clippy::manual_memcpy, clippy::doc_lazy_continuation)]

use crypto::{
    hash::{DOMAIN_LEAF, DOMAIN_NODE},
    merkle::verify_proof,
    Hash, Hasher, MerkleProof, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ZERO_LEAF: Hash = [0u8; HASH_LEN];

/// Manually walk the post-fix domain-separated zero-chain.
/// `m[0] = hash_leaf(&[0;32])`, `m[i] = hash_node(&m[i-1], &m[i-1])`.
fn domain_separated_zero_chain() -> [Hash; MERKLE_DEPTH + 1] {
    let mut m = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
    m[0] = Sha256Hasher::hash_leaf(&ZERO_LEAF);
    for i in 1..=MERKLE_DEPTH {
        m[i] = Sha256Hasher::hash_node(&m[i - 1], &m[i - 1]);
    }
    m
}

/// Manually walk the OLD undomained zero-chain via `hash_pair` from `[0;32]`.
/// Pre-fix `MerkleTree` produced its empty-root using this chain.
fn undomained_zero_chain() -> [Hash; MERKLE_DEPTH + 1] {
    let mut z = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
    for i in 1..=MERKLE_DEPTH {
        z[i] = Sha256Hasher::hash_pair(&z[i - 1], &z[i - 1]);
    }
    z
}

fn random_hash(rng: &mut impl RngCore) -> Hash {
    let mut h = [0u8; HASH_LEN];
    rng.fill_bytes(&mut h);
    h
}

// ---------------------------------------------------------------------------
// 1. Empty-tree root equals the post-fix domain-separated chain.
// ---------------------------------------------------------------------------

#[test]
fn empty_tree_root_matches_domain_separated_chain() {
    let m = domain_separated_zero_chain();
    let t = MerkleTree::<Sha256Hasher>::new();
    assert_eq!(
        t.root(),
        m[MERKLE_DEPTH],
        "empty-tree root must equal the manually-computed domain-separated zero chain top"
    );
}

// ---------------------------------------------------------------------------
// 2. Empty-tree root does NOT equal the pre-fix undomained chain (FINDING-1).
// ---------------------------------------------------------------------------

#[test]
fn empty_tree_root_does_not_match_undomained_chain() {
    let z = undomained_zero_chain();
    let t = MerkleTree::<Sha256Hasher>::new();
    assert_ne!(
        t.root(),
        z[MERKLE_DEPTH],
        "post-fix: empty-tree root must NOT equal the old undomained zero-chain top \
         (otherwise FINDING-1 still applies)"
    );
}

// ---------------------------------------------------------------------------
// 3. The level-0 zero marker is not the trivial all-zero hash.
// ---------------------------------------------------------------------------

#[test]
fn hash_leaf_of_zero_marker_is_not_all_zeros() {
    let marker = Sha256Hasher::hash_leaf(&ZERO_LEAF);
    assert_ne!(
        marker, ZERO_LEAF,
        "hash_leaf(&[0;32]) must not equal [0;32] — otherwise an attacker can present \
         the empty-slot marker trivially"
    );
}

// ---------------------------------------------------------------------------
// 4. hash_leaf and hash_node never collide on shared payload bytes.
// ---------------------------------------------------------------------------

#[test]
fn hash_leaf_and_hash_node_differ_for_same_payload() {
    // For every byte pattern, hash_leaf(x) and hash_node(x, x) must be
    // distinct — this is the DOMAIN_LEAF vs DOMAIN_NODE separation.
    let patterns: &[Hash] = &[
        [0u8; HASH_LEN],
        [0xFFu8; HASH_LEN],
        [0xAAu8; HASH_LEN],
        [0x55u8; HASH_LEN],
        [0x01u8; HASH_LEN],
        [0x7Fu8; HASH_LEN],
        [0x80u8; HASH_LEN],
        [0xDEu8; HASH_LEN],
        [0xADu8; HASH_LEN],
        [0xBEu8; HASH_LEN],
        [0xEFu8; HASH_LEN],
    ];
    for x in patterns {
        let l = Sha256Hasher::hash_leaf(x);
        let n = Sha256Hasher::hash_node(x, x);
        assert_ne!(
            l,
            n,
            "hash_leaf and hash_node collided for payload {:02x?}",
            &x[..4]
        );
    }
    // Also exercise a deterministic random sweep.
    let mut rng = StdRng::seed_from_u64(0xB10E_7EAA_4444_4444);
    for _ in 0..200 {
        let x = random_hash(&mut rng);
        assert_ne!(
            Sha256Hasher::hash_leaf(&x),
            Sha256Hasher::hash_node(&x, &x),
            "hash_leaf and hash_node collided on a random payload"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. verify_proof applies the leaf domain step internally.
// ---------------------------------------------------------------------------

#[test]
fn verify_proof_applies_leaf_domain_internally() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let leaf: Hash = [0x42u8; HASH_LEN];
    let idx = t.insert(leaf).unwrap();
    let proof = t.proof(idx).unwrap();
    let root = t.root();

    // Manually compute the path using hash_leaf at level 0 and hash_node above.
    let mut current = Sha256Hasher::hash_leaf(&leaf);
    for level in 0..MERKLE_DEPTH {
        let sib = &proof.siblings[level];
        current = if proof.indices[level] {
            Sha256Hasher::hash_node(sib, &current)
        } else {
            Sha256Hasher::hash_node(&current, sib)
        };
    }
    assert_eq!(
        current, root,
        "manual hash_leaf-then-hash_node walk must equal tree.root() — \
         confirms verify_proof's internal leaf-domain step"
    );
    // And the actual verify_proof must agree.
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &proof));
}

// ---------------------------------------------------------------------------
// 6. Internal levels use hash_node, not hash_pair.
// ---------------------------------------------------------------------------

#[test]
fn proof_uses_hash_node_not_hash_pair_at_internal_levels() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let leaves: [Hash; 4] = [
        [0x10u8; HASH_LEN],
        [0x20u8; HASH_LEN],
        [0x30u8; HASH_LEN],
        [0x40u8; HASH_LEN],
    ];
    for l in &leaves {
        t.insert(*l).unwrap();
    }
    let root = t.root();
    let proof = t.proof(0).unwrap();

    // Walk using hash_node — must match the real root.
    let mut node_walk = Sha256Hasher::hash_leaf(&leaves[0]);
    for level in 0..MERKLE_DEPTH {
        let sib = &proof.siblings[level];
        node_walk = if proof.indices[level] {
            Sha256Hasher::hash_node(sib, &node_walk)
        } else {
            Sha256Hasher::hash_node(&node_walk, sib)
        };
    }
    assert_eq!(
        node_walk, root,
        "internal levels must use hash_node — the domain-separated walk must close to root"
    );

    // Walk using hash_pair — must NOT match the real root.
    let mut pair_walk = Sha256Hasher::hash_leaf(&leaves[0]);
    for level in 0..MERKLE_DEPTH {
        let sib = &proof.siblings[level];
        pair_walk = if proof.indices[level] {
            Sha256Hasher::hash_pair(sib, &pair_walk)
        } else {
            Sha256Hasher::hash_pair(&pair_walk, sib)
        };
    }
    assert_ne!(
        pair_walk, root,
        "an undomained hash_pair walk must NOT close to the real root — \
         otherwise the domain separation is only cosmetic"
    );

    // Also: a fully-undomained walk (hash_pair at every level including no
    // hash_leaf step) must also differ from the real root. This is the
    // strongest form of the property.
    let mut full_pair_walk = leaves[0];
    for level in 0..MERKLE_DEPTH {
        let sib = &proof.siblings[level];
        full_pair_walk = if proof.indices[level] {
            Sha256Hasher::hash_pair(sib, &full_pair_walk)
        } else {
            Sha256Hasher::hash_pair(&full_pair_walk, sib)
        };
    }
    assert_ne!(full_pair_walk, root);
}

// ---------------------------------------------------------------------------
// 7. Sample-size preimage resistance against the empty-marker.
// ---------------------------------------------------------------------------

#[test]
fn zero_chain_marker_does_not_collide_with_any_real_hash_leaf_in_sample() {
    let marker = Sha256Hasher::hash_leaf(&ZERO_LEAF);
    let mut rng = StdRng::seed_from_u64(0xCAFE_F00D_DEAD_BEEF);
    for i in 0..1_000 {
        let x = random_hash(&mut rng);
        let h = Sha256Hasher::hash_leaf(&x);
        assert_ne!(
            h, marker,
            "sample {i}: random leaf's hash_leaf collided with empty-marker — \
             SHA-256 preimage resistance violated?"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. FINDING-1 regression: zero leaf + all-zero siblings is rejected.
// ---------------------------------------------------------------------------

#[test]
fn finding1_regression_zero_leaf_with_zero_siblings_rejected() {
    let attacker_leaf = ZERO_LEAF;
    let attacker_proof = MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };

    // Empty tree.
    let empty = MerkleTree::<Sha256Hasher>::new();
    assert!(
        !verify_proof::<Sha256Hasher>(&empty.root(), &attacker_leaf, &attacker_proof),
        "FINDING-1 regression: zero-leaf with zero-siblings must NOT verify against empty tree"
    );

    // Partially populated tree.
    let mut partial = MerkleTree::<Sha256Hasher>::new();
    partial.insert([1u8; HASH_LEN]).unwrap();
    partial.insert([2u8; HASH_LEN]).unwrap();
    partial.insert([3u8; HASH_LEN]).unwrap();
    assert!(
        !verify_proof::<Sha256Hasher>(&partial.root(), &attacker_leaf, &attacker_proof),
        "FINDING-1 regression: zero-leaf with zero-siblings must NOT verify against partial tree"
    );
}

// ---------------------------------------------------------------------------
// 9. FINDING-1 regression: zero leaf + real post-fix marker siblings rejected.
// ---------------------------------------------------------------------------

#[test]
fn finding1_regression_zero_leaf_with_real_zero_marker_siblings_rejected() {
    // The sophisticated variant: the attacker uses the actual post-fix
    // domain-separated marker values as siblings, hoping to construct a path
    // that closes to the empty root with `leaf = [0;32]`. This must fail
    // because verify_proof applies `hash_leaf` to the leaf input — so the
    // level-0 contribution is hash_leaf([0;32]), not [0;32], and that doesn't
    // line up with how the empty-marker chain was constructed (the chain
    // *starts* with hash_leaf([0;32]) — feeding hash_leaf([0;32]) ON TOP gives
    // a different result).
    let m = domain_separated_zero_chain();
    let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        siblings[level] = m[level];
    }
    let attacker_proof = MerkleProof {
        siblings,
        indices: [false; MERKLE_DEPTH],
    };
    let attacker_leaf = ZERO_LEAF;

    let empty = MerkleTree::<Sha256Hasher>::new();
    assert!(
        !verify_proof::<Sha256Hasher>(&empty.root(), &attacker_leaf, &attacker_proof),
        "FINDING-1 regression: zero-leaf with real-marker siblings must NOT verify against empty tree"
    );

    let mut partial = MerkleTree::<Sha256Hasher>::new();
    partial.insert([0xAAu8; HASH_LEN]).unwrap();
    assert!(
        !verify_proof::<Sha256Hasher>(&partial.root(), &attacker_leaf, &attacker_proof),
        "FINDING-1 regression: zero-leaf with real-marker siblings must NOT verify against partial tree"
    );
}

// ---------------------------------------------------------------------------
// 10. Empty marker bytes as leaf is still rejected (double-domain protection).
// ---------------------------------------------------------------------------

#[test]
fn empty_marker_as_leaf_still_rejected() {
    // The attacker tries `leaf = hash_leaf([0;32])` — the actual bytes of the
    // empty-slot marker. The verifier will compute hash_leaf(hash_leaf([0;32]))
    // i.e. it double-domains, so the level-0 contribution still doesn't match
    // the empty-marker chain.
    let m = domain_separated_zero_chain();
    let attacker_leaf: Hash = m[0]; // = hash_leaf([0;32])

    // Try with both the zero-sibling proof and the real-marker-sibling proof.
    let zero_proof = MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };

    let mut marker_siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        marker_siblings[level] = m[level];
    }
    let marker_proof = MerkleProof {
        siblings: marker_siblings,
        indices: [false; MERKLE_DEPTH],
    };

    let empty = MerkleTree::<Sha256Hasher>::new();
    assert!(
        !verify_proof::<Sha256Hasher>(&empty.root(), &attacker_leaf, &zero_proof),
        "double-domain protection: marker-bytes-as-leaf must NOT verify with zero siblings"
    );
    assert!(
        !verify_proof::<Sha256Hasher>(&empty.root(), &attacker_leaf, &marker_proof),
        "double-domain protection: marker-bytes-as-leaf must NOT verify with real-marker siblings"
    );

    // And against a partial tree.
    let mut partial = MerkleTree::<Sha256Hasher>::new();
    partial.insert([0x11u8; HASH_LEN]).unwrap();
    partial.insert([0x22u8; HASH_LEN]).unwrap();
    assert!(
        !verify_proof::<Sha256Hasher>(&partial.root(), &attacker_leaf, &zero_proof),
        "double-domain protection: marker-bytes-as-leaf must NOT verify against partial tree"
    );
}

// ---------------------------------------------------------------------------
// 11. hash_pair remains the undomained utility (T5.3 parity invariant).
// ---------------------------------------------------------------------------

#[test]
fn hash_pair_unchanged_remains_undomained_utility() {
    // hash_pair(a, b) must continue to equal hash(a ‖ b) byte-for-byte —
    // no DOMAIN_* byte prefixed. Callers who legitimately want undomained
    // concatenation hashing rely on this.
    let mut rng = StdRng::seed_from_u64(0xABCD_1234_5678_9012);
    for _ in 0..100 {
        let a = random_hash(&mut rng);
        let b = random_hash(&mut rng);
        let pair = Sha256Hasher::hash_pair(&a, &b);
        let mut concat = [0u8; 2 * HASH_LEN];
        concat[..HASH_LEN].copy_from_slice(&a);
        concat[HASH_LEN..].copy_from_slice(&b);
        let manual = Sha256Hasher::hash(&concat);
        assert_eq!(
            pair, manual,
            "hash_pair must equal hash(a ‖ b) — T5.3 parity invariant"
        );

        // And hash_pair must NOT equal either hash_leaf or hash_node forms of
        // the same inputs, otherwise the "undomained" claim is false.
        let leafed = Sha256Hasher::hash_leaf(&a);
        let noded = Sha256Hasher::hash_node(&a, &b);
        assert_ne!(pair, noded, "hash_pair must not equal hash_node");
        assert_ne!(pair, leafed, "hash_pair must not equal hash_leaf");
    }

    // Sanity-pin the domain bytes themselves so any accidental change is loud.
    assert_eq!(DOMAIN_LEAF, 0x00);
    assert_eq!(DOMAIN_NODE, 0x01);
}

// ---------------------------------------------------------------------------
// 12. Positive-path smoke: every inserted leaf verifies across many sizes.
// ---------------------------------------------------------------------------

#[test]
fn merkle_proof_for_every_inserted_leaf_still_works() {
    let mut rng = StdRng::seed_from_u64(0x5_7_9_B_D_F_0_2);
    for &n in &[1usize, 2, 4, 8, 16, 33, 100] {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        let mut leaves = Vec::with_capacity(n);
        for _ in 0..n {
            let l = random_hash(&mut rng);
            t.insert(l).unwrap();
            leaves.push(l);
        }
        let root = t.root();
        for (i, l) in leaves.iter().enumerate() {
            let proof = t.proof(i).expect("proof must exist for inserted leaf");
            assert!(
                verify_proof::<Sha256Hasher>(&root, l, &proof),
                "positive-path failure: n={n} idx={i} — the fix broke happy-path verification"
            );
        }
    }
}
