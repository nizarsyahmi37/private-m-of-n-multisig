//! Differential tests against an INDEPENDENT minimal SHA-256 reference.
//!
//! THREAT_MODEL.md T5.3 invariant: the on-chain verifier, the Risc0 guest, and
//! this crate must agree byte-for-byte on every hash they emit. This file
//! reconstructs each crate primitive from raw `sha2::Sha256` calls — never
//! touching the crate's own hashing path — and asserts the two outputs match
//! bit-for-bit across thousands of random inputs plus a handful of fixed
//! known-answer vectors.
//!
//! Why a reference impl: if the crate and a downstream verifier ever drift
//! (e.g. someone reorders concatenation, drops a domain byte, swaps `sk` and
//! `salt`), a regression here catches it before the divergent build ever runs.
//!
//! Reference rules:
//! - Only `sha2::{Digest, Sha256}` is used to compute reference digests.
//! - No crate hashing function is called from the reference path.
//! - All concatenation is built explicitly so the wire layout is auditable.

use crypto::{
    hash::{DOMAIN_LEAF, DOMAIN_NODE},
    merkle::{verify_proof, MerkleProof, MERKLE_DEPTH},
    nullifier, Hasher, Identity, MerkleTree, Sha256Hasher, HASH_LEN,
};
use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};
use sha2::{Digest, Sha256};

// ---- Reference primitives -------------------------------------------------
//
// Each function below is the minimal SHA-256 expression of the spec. They MUST
// NOT call back into the crate; that is what makes this a differential check.

fn ref_hash(input: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(input).finalize().into()
}

fn ref_hash_pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(l)
        .chain_update(r)
        .finalize()
        .into()
}

fn ref_hash_leaf(leaf: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([0x00u8])
        .chain_update(leaf)
        .finalize()
        .into()
}

fn ref_hash_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([0x01u8])
        .chain_update(l)
        .chain_update(r)
        .finalize()
        .into()
}

fn ref_commitment(sk: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(sk)
        .chain_update(salt)
        .finalize()
        .into()
}

fn ref_nullifier(sk: &[u8; 32], pid: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(sk)
        .chain_update(pid)
        .finalize()
        .into()
}

/// Reference computation of the empty-tree root at the given depth, mirroring
/// `MerkleTree::new()` but using only reference SHA-256 calls.
fn ref_empty_tree_root(depth: usize) -> [u8; 32] {
    let mut cur = ref_hash_leaf(&[0u8; 32]);
    for _ in 0..depth {
        cur = ref_hash_node(&cur, &cur);
    }
    cur
}

/// Reference proof walk: starting from a raw leaf commitment, apply
/// `hash_leaf`, then walk each (sibling, index) level via `hash_node` in the
/// orientation the index dictates. This is exactly what a from-scratch
/// on-chain verifier would do.
fn ref_walk_proof(leaf: &[u8; 32], siblings: &[[u8; 32]], indices: &[bool]) -> [u8; 32] {
    assert_eq!(siblings.len(), indices.len());
    let mut current = ref_hash_leaf(leaf);
    for level in 0..siblings.len() {
        current = if indices[level] {
            ref_hash_node(&siblings[level], &current)
        } else {
            ref_hash_node(&current, &siblings[level])
        };
    }
    current
}

// Fixed seed keeps the suite reproducible — every CI run hits the same
// (input, expected) pairs, so a flake here always points at real drift.
const SEED: u64 = 0xD1FF_5AFE_1234_5678;
const N: usize = 1000;

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

// ---- 1. hash --------------------------------------------------------------

#[test]
fn ref_sha256_matches_hash() {
    let mut r = rng();
    for i in 0..N {
        let len = r.random_range(0..=4096);
        let mut input = vec![0u8; len];
        r.fill_bytes(&mut input);

        let got = Sha256Hasher::hash(&input);
        let expected = ref_hash(&input);

        assert_eq!(
            got, expected,
            "iter {i}, len {len}: crate hash diverges from reference"
        );
    }
}

// ---- 2. hash_pair ---------------------------------------------------------

#[test]
fn ref_hash_pair_matches() {
    let mut r = rng();
    for i in 0..N {
        let mut l = [0u8; HASH_LEN];
        let mut rt = [0u8; HASH_LEN];
        r.fill_bytes(&mut l);
        r.fill_bytes(&mut rt);

        let got = Sha256Hasher::hash_pair(&l, &rt);
        let expected = ref_hash_pair(&l, &rt);
        assert_eq!(got, expected, "iter {i}: hash_pair diverges from reference");

        // Layout check: hash_pair is exactly H(l || r) — no padding, no length
        // prefix, no domain byte. Build the concat by hand and compare.
        let mut concat = [0u8; 2 * HASH_LEN];
        concat[..HASH_LEN].copy_from_slice(&l);
        concat[HASH_LEN..].copy_from_slice(&rt);
        assert_eq!(
            got,
            ref_hash(&concat),
            "iter {i}: hash_pair layout is not raw concat"
        );
        assert_eq!(concat.len(), 64, "hash_pair input must be exactly 64 bytes");
    }
}

// ---- 3. hash_leaf ---------------------------------------------------------

#[test]
fn ref_hash_leaf_matches() {
    let mut r = rng();
    for i in 0..N {
        let mut leaf = [0u8; HASH_LEN];
        r.fill_bytes(&mut leaf);

        let got = Sha256Hasher::hash_leaf(&leaf);
        let expected = ref_hash_leaf(&leaf);
        assert_eq!(got, expected, "iter {i}: hash_leaf diverges from reference");

        // Confirm the domain byte is exactly 0x00 by reconstructing the input
        // explicitly and re-hashing through the reference.
        let mut buf = [0u8; 1 + HASH_LEN];
        buf[0] = 0x00;
        buf[1..].copy_from_slice(&leaf);
        assert_eq!(
            got,
            ref_hash(&buf),
            "iter {i}: hash_leaf domain byte is not 0x00"
        );
        assert_eq!(DOMAIN_LEAF, 0x00, "DOMAIN_LEAF constant must equal 0x00");
    }
}

// ---- 4. hash_node ---------------------------------------------------------

#[test]
fn ref_hash_node_matches() {
    let mut r = rng();
    for i in 0..N {
        let mut l = [0u8; HASH_LEN];
        let mut rt = [0u8; HASH_LEN];
        r.fill_bytes(&mut l);
        r.fill_bytes(&mut rt);

        let got = Sha256Hasher::hash_node(&l, &rt);
        let expected = ref_hash_node(&l, &rt);
        assert_eq!(got, expected, "iter {i}: hash_node diverges from reference");

        // Confirm the domain byte is exactly 0x01.
        let mut buf = [0u8; 1 + 2 * HASH_LEN];
        buf[0] = 0x01;
        buf[1..1 + HASH_LEN].copy_from_slice(&l);
        buf[1 + HASH_LEN..].copy_from_slice(&rt);
        assert_eq!(
            got,
            ref_hash(&buf),
            "iter {i}: hash_node domain byte is not 0x01"
        );
        assert_eq!(DOMAIN_NODE, 0x01, "DOMAIN_NODE constant must equal 0x01");
    }
}

// ---- 5. commitment --------------------------------------------------------

#[test]
fn ref_commitment_matches() {
    let mut r = rng();
    for i in 0..N {
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        r.fill_bytes(&mut sk);
        r.fill_bytes(&mut salt);

        let got = *Identity::new(sk, salt)
            .commitment::<Sha256Hasher>()
            .as_bytes();
        let expected = ref_commitment(&sk, &salt);
        assert_eq!(
            got, expected,
            "iter {i}: commitment diverges from reference"
        );

        // Ordering check: sk-then-salt. Swap the order in the reference and
        // confirm that produces a *different* digest — guards against a future
        // refactor that silently reorders inputs.
        if sk != salt {
            let mut swapped = [0u8; 64];
            swapped[..32].copy_from_slice(&salt);
            swapped[32..].copy_from_slice(&sk);
            assert_ne!(
                got,
                ref_hash(&swapped),
                "iter {i}: commitment must be sk||salt, not salt||sk"
            );
        }
    }
}

// ---- 6. nullifier ---------------------------------------------------------

#[test]
fn ref_nullifier_matches() {
    let mut r = rng();
    for i in 0..N {
        let mut sk = [0u8; 32];
        let mut pid = [0u8; 32];
        r.fill_bytes(&mut sk);
        r.fill_bytes(&mut pid);

        let got = nullifier::<Sha256Hasher>(&sk, &pid);
        let expected = ref_nullifier(&sk, &pid);
        assert_eq!(got, expected, "iter {i}: nullifier diverges from reference");

        // Ordering check: sk-then-pid.
        if sk != pid {
            let mut swapped = [0u8; 64];
            swapped[..32].copy_from_slice(&pid);
            swapped[32..].copy_from_slice(&sk);
            assert_ne!(
                got,
                ref_hash(&swapped),
                "iter {i}: nullifier must be sk||pid, not pid||sk"
            );
        }
    }
}

// ---- 7. empty tree root ---------------------------------------------------

#[test]
fn ref_empty_tree_root_matches() {
    let tree_root = MerkleTree::<Sha256Hasher>::new().root();
    let ref_root = ref_empty_tree_root(MERKLE_DEPTH);
    assert_eq!(
        tree_root, ref_root,
        "depth-{MERKLE_DEPTH} empty-tree root diverges from reference zero-chain"
    );
}

// ---- 8. single-leaf tree root --------------------------------------------

#[test]
fn ref_single_leaf_tree_root_matches() {
    let mut r = rng();
    let mut leaf = [0u8; HASH_LEN];
    r.fill_bytes(&mut leaf);

    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let idx = tree.insert(leaf).unwrap();
    assert_eq!(idx, 0);
    let got_root = tree.root();

    // Reference: leaf gets wrapped in hash_leaf at level 0, then paired with
    // the zero-chain sibling at every level above, with the leaf always on the
    // left because index 0 = all left children.
    let mut zero = ref_hash_leaf(&[0u8; 32]);
    let mut current = ref_hash_leaf(&leaf);
    for _ in 0..MERKLE_DEPTH {
        current = ref_hash_node(&current, &zero);
        zero = ref_hash_node(&zero, &zero);
    }

    assert_eq!(
        got_root, current,
        "single-leaf tree root diverges from reference walk"
    );
}

// ---- 9. proof walk --------------------------------------------------------

#[test]
fn ref_proof_walk_matches() {
    for &size in &[3usize, 5, 17] {
        let mut r = StdRng::seed_from_u64(SEED.wrapping_add(size as u64));
        let mut tree = MerkleTree::<Sha256Hasher>::new();
        let mut leaves = Vec::with_capacity(size);
        for _ in 0..size {
            let mut l = [0u8; HASH_LEN];
            r.fill_bytes(&mut l);
            tree.insert(l).unwrap();
            leaves.push(l);
        }
        let root = tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            // Cross-check with the crate's own verifier first — sanity that
            // the tree is internally consistent before we compare against the
            // reference.
            assert!(
                verify_proof::<Sha256Hasher>(&root, leaf, &proof),
                "size {size} index {i}: crate's verify_proof rejected its own proof"
            );

            let walked = ref_walk_proof(leaf, &proof.siblings, &proof.indices);
            assert_eq!(
                walked, root,
                "size {size} index {i}: reference walk does not reach crate's stored root"
            );
        }
    }
}

// ---- 10. known-answer vectors --------------------------------------------
//
// Hard-coded outputs computed once from the reference SHA-256 (see the README
// comment in this file's header). If the crate AND the reference both drift in
// the same direction, the random tests above could still pass; these fixed
// vectors catch that case because they pin the bytes a third party would have
// computed independently.

#[test]
fn ref_known_answer_vectors() {
    // KAT1: empty-input SHA-256. RFC 6234 test vector; if this drifts the
    // underlying `sha2` crate itself has broken.
    let kat1: [u8; 32] =
        hex_literal_arr("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(Sha256Hasher::hash(b""), kat1, "KAT1 hash(\"\") drift");

    // KAT2: level-0 empty marker — `hash_leaf(&[0;32])`.
    let kat2: [u8; 32] =
        hex_literal_arr("7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9");
    assert_eq!(
        Sha256Hasher::hash_leaf(&[0u8; 32]),
        kat2,
        "KAT2 hash_leaf([0;32]) drift"
    );

    // KAT3: `hash_node([1;32], [2;32])`.
    let kat3: [u8; 32] =
        hex_literal_arr("b331da6ec49d4547d9942a6727e5123f69bed5a0b97ac171cfbfd6201431fcfa");
    assert_eq!(
        Sha256Hasher::hash_node(&[1u8; 32], &[2u8; 32]),
        kat3,
        "KAT3 hash_node([1;32],[2;32]) drift"
    );

    // KAT4: commitment for sk=[0x11;32], salt=[0x22;32].
    let kat4: [u8; 32] =
        hex_literal_arr("5189c77d29fe5d546a045ec46986852785fea5c13ac7da9c115ff5fb6edf817c");
    assert_eq!(
        *Identity::new([0x11; 32], [0x22; 32])
            .commitment::<Sha256Hasher>()
            .as_bytes(),
        kat4,
        "KAT4 commitment drift"
    );

    // KAT5: nullifier for sk=[0x33;32], pid=[0x44;32].
    let kat5: [u8; 32] =
        hex_literal_arr("71cdd0136a799e7ef615ddd2aaeee3d0bae2eb8dbcac7b88ceb70ff131ecce55");
    assert_eq!(
        nullifier::<Sha256Hasher>(&[0x33; 32], &[0x44; 32]),
        kat5,
        "KAT5 nullifier drift"
    );

    // KAT6: depth-20 empty tree root. This is the value the on-chain verifier
    // and the Risc0 guest must both bake in as the genesis members_root.
    let kat6: [u8; 32] =
        hex_literal_arr("ac5b1c358a294dec99146ebb2fea0c8a528fc4dad578485d7f279c2b359099f3");
    assert_eq!(
        MerkleTree::<Sha256Hasher>::new().root(),
        kat6,
        "KAT6 empty depth-20 root drift"
    );
}

/// Tiny helper so we don't need the `hex-literal` macro crate. Decodes a 64-
/// char hex string to a [u8;32] at runtime — fine for test setup.
fn hex_literal_arr(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

// ---- 11. domain-byte sentinel --------------------------------------------

#[test]
fn leaf_domain_byte_is_zero_node_domain_byte_is_one() {
    // Direct check on the constants — guards against a future patch that
    // accidentally swaps them.
    assert_eq!(DOMAIN_LEAF, 0x00, "DOMAIN_LEAF must be 0x00");
    assert_eq!(DOMAIN_NODE, 0x01, "DOMAIN_NODE must be 0x01");

    // Behavioural check: the byte that `hash_leaf`/`hash_node` prepend before
    // the rest of the payload must match the constants. We re-derive the
    // expected digest from the explicit byte literal `0x00` / `0x01` (not the
    // exported constants) so this catches a swap of the constants too.
    let sample_leaf = [0xAAu8; 32];
    let leaf_expected = Sha256::new()
        .chain_update([0x00u8])
        .chain_update(sample_leaf)
        .finalize();
    let leaf_expected: [u8; 32] = leaf_expected.into();
    assert_eq!(
        Sha256Hasher::hash_leaf(&sample_leaf),
        leaf_expected,
        "hash_leaf does not prepend literal 0x00"
    );

    let sample_l = [0xBBu8; 32];
    let sample_r = [0xCCu8; 32];
    let node_expected = Sha256::new()
        .chain_update([0x01u8])
        .chain_update(sample_l)
        .chain_update(sample_r)
        .finalize();
    let node_expected: [u8; 32] = node_expected.into();
    assert_eq!(
        Sha256Hasher::hash_node(&sample_l, &sample_r),
        node_expected,
        "hash_node does not prepend literal 0x01"
    );

    // And confirm the two domains cannot coincide — `hash_leaf(x)` over a
    // 64-byte input is structurally impossible since the leaf is 32 bytes,
    // but a sentinel pair-check still catches a future widening bug.
    let leaf_h = Sha256Hasher::hash_leaf(&[0u8; 32]);
    let node_h = Sha256Hasher::hash_node(&[0u8; 32], &[0u8; 32]);
    assert_ne!(
        leaf_h, node_h,
        "leaf and node domains must produce disjoint digests"
    );
}

// Compile-time guard: keep `Hasher` in scope so the `hash` trait method can be
// called on `Sha256Hasher`. (Removing this would surface as an unused-import
// warning rather than a hard error, but we want the trait visible for clarity.)
#[allow(dead_code)]
fn _trait_anchor() -> [u8; 32] {
    <Sha256Hasher as Hasher>::hash(b"anchor")
}

// Compile-time guard: ensure the `MerkleProof` type stays at depth 20 — if
// MERKLE_DEPTH ever changes, KAT6 must be recomputed.
#[allow(dead_code)]
const _DEPTH_CHECK: usize = {
    let _ = [(); MERKLE_DEPTH - 20];
    let _ = [(); 20 - MERKLE_DEPTH];
    MERKLE_DEPTH
};

// Compile-time guard: `MerkleProof` has the depth we expect.
#[allow(dead_code)]
fn _proof_shape_check(p: &MerkleProof) -> (usize, usize) {
    (p.siblings.len(), p.indices.len())
}
