//! Blue-team validation suite for the LP-0002 crypto core.
//!
//! Each test confirms one defensive property the rest of the system relies on.
//! Failures here invalidate assumptions in PLAN.md and THREAT_MODEL.md.

use crypto::{
    merkle::verify_proof, nullifier, Hash, Hasher, Identity, MerkleTree, Sha256Hasher, HASH_LEN,
    MERKLE_DEPTH,
};
use rand::RngCore;

// ---------- helpers ----------

fn random_hash(rng: &mut impl RngCore) -> Hash {
    let mut h = [0u8; HASH_LEN];
    rng.fill_bytes(&mut h);
    h
}

fn random_sk(rng: &mut impl RngCore) -> [u8; 32] {
    let mut s = [0u8; 32];
    rng.fill_bytes(&mut s);
    s
}

fn build_tree(n: usize, rng: &mut impl RngCore) -> (MerkleTree<Sha256Hasher>, Vec<Hash>) {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let mut leaves = Vec::with_capacity(n);
    for _ in 0..n {
        let leaf = random_hash(rng);
        t.insert(leaf).unwrap();
        leaves.push(leaf);
    }
    (t, leaves)
}

// ---------- 1 ----------

#[test]
fn merkle_positive_path_accepts() {
    let mut rng = rand::thread_rng();
    for &n in &[1usize, 2, 5, 17, 64] {
        let (tree, leaves) = build_tree(n, &mut rng);
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).expect("proof exists");
            assert!(
                verify_proof::<Sha256Hasher>(&root, leaf, &proof),
                "n={n} idx={i}: positive proof must verify"
            );
        }
    }
}

// ---------- 2 ----------

#[test]
fn merkle_tamper_each_sibling_byte_rejects() {
    let mut rng = rand::thread_rng();
    let (tree, leaves) = build_tree(17, &mut rng);
    let root = tree.root();
    // Iterate over each leaf, each sibling level, each byte: 17 * 20 * 32 = 10_880 flips.
    for (i, leaf) in leaves.iter().enumerate() {
        let base = tree.proof(i).unwrap();
        for level in 0..MERKLE_DEPTH {
            for byte in 0..HASH_LEN {
                let mut tampered = base.clone();
                tampered.siblings[level][byte] ^= 0x01;
                assert!(
                    !verify_proof::<Sha256Hasher>(&root, leaf, &tampered),
                    "tampered sibling byte must reject: leaf={i} level={level} byte={byte}"
                );
            }
        }
    }
}

// ---------- 3 ----------

#[test]
fn merkle_tamper_each_direction_bit_rejects() {
    let mut rng = rand::thread_rng();
    // Use a tree where the leaf has a meaningful right-or-left placement at every
    // level. n=17 means index 16 sits in a freshly-opened subtree, so every
    // direction bit interacts with a non-zero sibling for at least some indices.
    let (tree, leaves) = build_tree(17, &mut rng);
    let root = tree.root();
    for (i, leaf) in leaves.iter().enumerate() {
        let base = tree.proof(i).unwrap();
        for level in 0..MERKLE_DEPTH {
            let mut tampered = base.clone();
            tampered.indices[level] = !tampered.indices[level];
            assert!(
                !verify_proof::<Sha256Hasher>(&root, leaf, &tampered),
                "flipped direction bit must reject: leaf={i} level={level}"
            );
        }
    }
}

// ---------- 4 ----------

#[test]
fn merkle_root_stable_across_clones() {
    // Note: `MerkleTree<Sha256Hasher>` doesn't currently satisfy `Clone` (the
    // derive's auto-bound requires `Sha256Hasher: Clone`, which it isn't).
    // We emulate "clone" by recording the leaf sequence and replaying it into
    // a second tree — which is the only state a clone would carry anyway, and
    // is exactly how callers persist Merkle state. The behavioural property
    // (independence of two trees with shared history) is what matters.
    let mut rng = rand::thread_rng();
    let mut original = MerkleTree::<Sha256Hasher>::new();
    let mut shared_leaves = Vec::new();
    for _ in 0..5 {
        let leaf = random_hash(&mut rng);
        original.insert(leaf).unwrap();
        shared_leaves.push(leaf);
    }
    let root_before = original.root();

    let mut twin = MerkleTree::<Sha256Hasher>::new();
    for leaf in &shared_leaves {
        twin.insert(*leaf).unwrap();
    }
    assert_eq!(
        original.root(),
        twin.root(),
        "two trees built from the same leaf sequence must agree on the root"
    );

    // Mutate only the twin.
    for _ in 0..3 {
        twin.insert(random_hash(&mut rng)).unwrap();
    }

    let root_after = original.root();
    assert_eq!(
        root_before, root_after,
        "inserts into a parallel tree must not mutate the original's root"
    );
    assert_ne!(
        twin.root(),
        original.root(),
        "the twin with extra leaves must produce a different root"
    );
}

// ---------- 5 ----------

#[test]
fn nullifier_deterministic_across_many_inputs() {
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let sk = random_sk(&mut rng);
        let pid = random_hash(&mut rng);
        let a = nullifier::<Sha256Hasher>(&sk, &pid);
        let b = nullifier::<Sha256Hasher>(&sk, &pid);
        assert_eq!(a, b, "nullifier must be deterministic for fixed inputs");
    }
}

// ---------- 6 ----------

#[test]
fn nullifier_bit_distribution_looks_random() {
    // 256 nullifiers × 256 bit positions. For a uniform output, each column's
    // set-count is Binomial(256, 0.5) with mean 128, std ≈ 8. ±25% (= ±32) is a
    // loose-but-non-trivial smoke test — well past 4σ, so a competent hash
    // shouldn't trigger this even once in practice.
    const N: usize = 256;
    let mut rng = rand::thread_rng();
    let mut nulls = Vec::with_capacity(N);
    for _ in 0..N {
        let sk = random_sk(&mut rng);
        let pid = random_hash(&mut rng);
        nulls.push(nullifier::<Sha256Hasher>(&sk, &pid));
    }
    for bit in 0..(HASH_LEN * 8) {
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        let set_count = nulls
            .iter()
            .filter(|n| (n[byte_idx] >> bit_idx) & 1 == 1)
            .count();
        let low = 128 - 32; // 96
        let high = 128 + 32; // 160
        assert!(
            set_count >= low && set_count <= high,
            "bit {bit} set in {set_count}/256 nullifiers, expected within [{low},{high}]"
        );
    }
}

// ---------- 7 ----------

#[test]
fn identity_debug_redacts_for_many_inputs() {
    let mut rng = rand::thread_rng();
    let mut random_sk_arr = [0u8; 32];
    let mut random_salt_arr = [0u8; 32];
    rng.fill_bytes(&mut random_sk_arr);
    rng.fill_bytes(&mut random_salt_arr);

    let cases: [([u8; 32], [u8; 32]); 4] = [
        ([0x00; 32], [0x00; 32]),
        ([0xFF; 32], [0xFF; 32]),
        ([0xAB; 32], [0xCD; 32]),
        (random_sk_arr, random_salt_arr),
    ];

    for (sk, salt) in cases.iter() {
        let id = Identity::new(*sk, *salt);
        let rendered = format!("{:?}", id);

        assert!(
            rendered.contains("[REDACTED]"),
            "Debug output must contain `[REDACTED]`, got: {rendered}"
        );

        let sk_hex = hex::encode(sk);
        let salt_hex = hex::encode(salt);
        // For every 2-character (one-byte) hex window, the redacted Debug
        // output must not leak it. Length-2 windows are the smallest unit that
        // proves "this exact byte appears in the rendering" — and we want zero
        // bytes of secret material in the output.
        for i in 0..(sk_hex.len() - 1) {
            let window = &sk_hex[i..i + 2];
            assert!(
                !rendered.contains(window),
                "Debug leaked sk byte window `{window}` at offset {i}: {rendered}"
            );
        }
        for i in 0..(salt_hex.len() - 1) {
            let window = &salt_hex[i..i + 2];
            assert!(
                !rendered.contains(window),
                "Debug leaked salt byte window `{window}` at offset {i}: {rendered}"
            );
        }
    }
}

// ---------- 8 ----------

#[test]
fn empty_tree_root_is_nontrivial() {
    let tree = MerkleTree::<Sha256Hasher>::new();
    let root = tree.root();
    let trivial = [0u8; HASH_LEN];
    assert_ne!(
        root, trivial,
        "empty-tree root must not be all-zero — otherwise an attacker who can \
         present a [0;32] leaf could claim membership in any not-yet-rooted tree"
    );
}

// ---------- 9 ----------

#[test]
fn hasher_pair_matches_manual_concat() {
    let mut rng = rand::thread_rng();
    for _ in 0..50 {
        let a = random_hash(&mut rng);
        let b = random_hash(&mut rng);
        let pair = Sha256Hasher::hash_pair(&a, &b);

        let mut concat = [0u8; 2 * HASH_LEN];
        concat[..HASH_LEN].copy_from_slice(&a);
        concat[HASH_LEN..].copy_from_slice(&b);
        let manual = Sha256Hasher::hash(&concat);

        assert_eq!(
            pair, manual,
            "hash_pair must equal hash(a‖b) byte-for-byte (THREAT_MODEL T5.3)"
        );
    }
}

// ---------- 10 ----------

#[test]
fn outsider_cannot_forge_membership() {
    let mut rng = rand::thread_rng();
    const N: usize = 8;

    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut victim_leaves = Vec::with_capacity(N);
    for _ in 0..N {
        let sk = random_sk(&mut rng);
        let salt = random_sk(&mut rng);
        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();
        let leaf = *c.as_bytes();
        tree.insert(leaf).unwrap();
        victim_leaves.push(leaf);
    }
    let root = tree.root();

    // The outsider holds their own (sk, salt) and computes their commitment —
    // never enrolled. They then borrow each victim's path shape and try to
    // claim that slot. None of them can verify.
    let outsider = Identity::new(random_sk(&mut rng), random_sk(&mut rng));
    let outsider_leaf = *outsider.commitment::<Sha256Hasher>().as_bytes();

    // Sanity: the outsider's leaf isn't accidentally equal to a victim's
    // (probability 2^-256, but assert to keep the test honest).
    for v in &victim_leaves {
        assert_ne!(&outsider_leaf, v, "test setup: outsider must be distinct");
    }

    for victim_idx in 0..N {
        let proof = tree.proof(victim_idx).expect("victim's path exists");
        assert!(
            !verify_proof::<Sha256Hasher>(&root, &outsider_leaf, &proof),
            "outsider must not be able to pose as victim at index {victim_idx}"
        );
    }
}
