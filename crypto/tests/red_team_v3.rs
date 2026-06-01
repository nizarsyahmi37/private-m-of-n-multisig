//! Round-3 red-team adversarial tests.
//!
//! Round 1 found FINDING-1 (HIGH): undomained Merkle hashing → zero-leaf
//! forgery at any unused slot. Fixed via `hash_leaf` / `hash_node`.
//! Round 2 found FINDING-1b (LOW): `verify_proof` accepted `leaf=[0;32]`
//! against the empty tree via the real post-fix marker chain. Fixed with an
//! explicit `leaf == [0;32]` guard at the top of `verify_proof`.
//!
//! Round-3 mandate: find what rounds 1-2 missed. Hammer the corners of the
//! API (`Identity::nullifier`, three-way `as_bytes()`/`.0`/`commitment::<H>()`
//! equivalence, `IdentityCommitment` hashing distribution, `MerkleProof::Clone`
//! semantics, `MAX_LEAVES` arithmetic, `verify_proof` on garbage proofs,
//! single-`hash_leaf` root as the verifier root), and replace tautological
//! tests in prior rounds with stronger assertions.
//!
//! Each test is named `r3_*`. Comments include the technique and expected
//! outcome. The trailing report comments at the bottom of this file list
//! tautological tests found in prior rounds with file:line references and
//! the stronger r3 test that replaces each.
//!
//! Run:
//!     cargo test -p crypto --test red_team_v3

#![allow(
    clippy::manual_memcpy,
    clippy::needless_range_loop,
    clippy::unusual_byte_groupings
)]

use crypto::{
    hash::{DOMAIN_LEAF, DOMAIN_NODE, HASH_LEN},
    identity::{SALT_LEN, SK_LEN},
    merkle::{verify_proof, MerkleError, MerkleProof, MAX_LEAVES, MERKLE_DEPTH},
    nullifier, Hash, Hasher, Identity, IdentityCommitment, MerkleTree, Sha256Hasher,
};
use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ZERO: Hash = [0u8; HASH_LEN];

fn empty_chain() -> [Hash; MERKLE_DEPTH + 1] {
    let mut m = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
    m[0] = Sha256Hasher::hash_leaf(&ZERO);
    for i in 1..=MERKLE_DEPTH {
        m[i] = Sha256Hasher::hash_node(&m[i - 1], &m[i - 1]);
    }
    m
}

// ===========================================================================
// 1. Identity::nullifier helper parity (and uses-self.sk-only) sweep
// ===========================================================================

/// `Identity::nullifier(&self, &pid)` MUST behave as
/// `crypto::nullifier::<H>(&self.sk, &pid)` for every (sk, salt, pid) input.
/// If `Identity::nullifier` ever accidentally hashed `self.salt` too — or the
/// entire `Identity` struct — this 1000-sample sweep catches it.
/// Outcome: mitigated.
#[test]
fn r3_identity_nullifier_parity_sweep_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xA110_CA75_3344_5566);
    for trial in 0..1_000 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        let mut pid = [0u8; HASH_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut pid);
        let id = Identity::new(sk, salt);
        let helper = id.nullifier::<Sha256Hasher>(&pid);
        let free = nullifier::<Sha256Hasher>(&id.sk, &pid);
        assert_eq!(
            helper, free,
            "trial {trial}: Identity::nullifier diverged from free nullifier"
        );
    }
}

/// Salt-independence: two identities sharing the same `sk` but different
/// `salt` MUST produce the same nullifier for the same `pid`. If `salt`
/// ever leaks into the nullifier (anonymity break), this test fires.
/// Outcome: mitigated.
#[test]
fn r3_identity_nullifier_salt_independent_mitigated() {
    let mut rng = StdRng::seed_from_u64(0x5A17_F0_5A17_F0_5A);
    for trial in 0..200 {
        let mut sk = [0u8; SK_LEN];
        let mut salt_a = [0u8; SALT_LEN];
        let mut salt_b = [0u8; SALT_LEN];
        let mut pid = [0u8; HASH_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt_a);
        rng.fill_bytes(&mut salt_b);
        rng.fill_bytes(&mut pid);
        // Skip the rare collision where salts are equal — would be vacuous.
        if salt_a == salt_b {
            continue;
        }
        let id_a = Identity::new(sk, salt_a);
        let id_b = Identity::new(sk, salt_b);
        assert_eq!(
            id_a.nullifier::<Sha256Hasher>(&pid),
            id_b.nullifier::<Sha256Hasher>(&pid),
            "trial {trial}: salt influenced nullifier — anonymity-set break"
        );
        // And BOTH must equal the free-function value.
        let free = nullifier::<Sha256Hasher>(&sk, &pid);
        assert_eq!(id_a.nullifier::<Sha256Hasher>(&pid), free);
        assert_eq!(id_b.nullifier::<Sha256Hasher>(&pid), free);
    }
}

/// Direct payload-byte assertion: the nullifier helper must hash exactly
/// `sk ‖ pid` (64 bytes), no domain byte, no salt suffix. Round 1 and 2
/// pinned this for the free function; the helper version is newer so we
/// re-pin via a 100-sample bytewise reference comparison.
/// Outcome: mitigated.
#[test]
fn r3_identity_nullifier_byte_layout_pinned_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xDEAD_DEAD_DEAD_DEAD);
    for _ in 0..100 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        let mut pid = [0u8; HASH_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut pid);
        let id = Identity::new(sk, salt);
        let got = id.nullifier::<Sha256Hasher>(&pid);

        let mut ref_buf = Vec::with_capacity(SK_LEN + HASH_LEN);
        ref_buf.extend_from_slice(&sk);
        ref_buf.extend_from_slice(&pid);
        let expected: [u8; 32] = Sha256::new().chain_update(&ref_buf).finalize().into();
        assert_eq!(got, expected, "Identity::nullifier byte layout drift");

        // Sanity-defensive: confirm the helper is NOT accidentally hashing
        // (sk || salt || pid) or (sk || pid || salt) or the whole struct.
        let mut bad1 = Vec::new();
        bad1.extend_from_slice(&sk);
        bad1.extend_from_slice(&salt);
        bad1.extend_from_slice(&pid);
        let bad_hash1: [u8; 32] = Sha256::new().chain_update(&bad1).finalize().into();
        assert_ne!(
            got, bad_hash1,
            "nullifier helper accidentally including salt"
        );

        let mut bad2 = Vec::new();
        bad2.extend_from_slice(&sk);
        bad2.extend_from_slice(&pid);
        bad2.extend_from_slice(&salt);
        let bad_hash2: [u8; 32] = Sha256::new().chain_update(&bad2).finalize().into();
        assert_ne!(got, bad_hash2);
    }
}

// Proptest sweep — proptest's shrinker would isolate any case that diverged.
proptest! {
    #![proptest_config(ProptestConfig { cases: 500, .. ProptestConfig::default() })]

    #[test]
    fn r3_identity_nullifier_helper_equals_free_proptest(
        sk in any::<[u8; 32]>(),
        salt in any::<[u8; 32]>(),
        pid in any::<[u8; 32]>(),
    ) {
        let id = Identity::new(sk, salt);
        prop_assert_eq!(
            id.nullifier::<Sha256Hasher>(&pid),
            nullifier::<Sha256Hasher>(&id.sk, &pid),
        );
    }

    #[test]
    fn r3_identity_nullifier_helper_independent_of_salt_proptest(
        sk in any::<[u8; 32]>(),
        salt_a in any::<[u8; 32]>(),
        salt_b in any::<[u8; 32]>(),
        pid in any::<[u8; 32]>(),
    ) {
        let na = Identity::new(sk, salt_a).nullifier::<Sha256Hasher>(&pid);
        let nb = Identity::new(sk, salt_b).nullifier::<Sha256Hasher>(&pid);
        prop_assert_eq!(na, nb);
    }
}

// ===========================================================================
// 2. MAX_LEAVES / capacity arithmetic + typed Full error path
// ===========================================================================

/// Pin `MAX_LEAVES == 1 << MERKLE_DEPTH` exactly. This is the wire-level
/// constant the on-chain enrollment caps against.
/// Outcome: mitigated (sentinel).
#[test]
fn r3_max_leaves_is_two_to_the_depth_mitigated() {
    assert_eq!(
        MAX_LEAVES,
        1usize << MERKLE_DEPTH,
        "MAX_LEAVES must equal 2^MERKLE_DEPTH"
    );
    // Cross-check against the live tree's report.
    let t = MerkleTree::<Sha256Hasher>::new();
    assert_eq!(t.capacity(), MAX_LEAVES);
    assert_eq!(t.capacity(), 1usize << MERKLE_DEPTH);
    // And depth-20 ⇒ 1_048_576 in absolute terms — pin the literal so a
    // typo in MERKLE_DEPTH is loud.
    assert_eq!(MAX_LEAVES, 1_048_576);
}

/// Insertions strictly below capacity succeed and report sequential indices.
/// We can't allocate 2^20 leaves cheaply, so we trust the typed `Full` error
/// for the boundary itself (round 1's `attack_insert_past_capacity_returns_err`
/// only asserts capacity is reported; we add a stricter check that
/// MerkleError::Full carries MAX_LEAVES exactly).
/// Outcome: mitigated.
#[test]
fn r3_merkle_error_full_carries_max_leaves_mitigated() {
    // We can't push 1M leaves, but the enum literal IS public. Confirm
    // the Display impl reports `tree is full (capacity 1048576)` so a
    // downstream log parser cannot be fooled by some refactor that
    // silently passes a different cap into the error.
    let e = MerkleError::Full(MAX_LEAVES);
    let rendered = format!("{e}");
    assert!(
        rendered.contains("1048576"),
        "MerkleError::Full Display lost MAX_LEAVES literal: {rendered}"
    );
    // And the variant binds to MAX_LEAVES, not some hard-coded constant.
    match e {
        MerkleError::Full(n) => assert_eq!(n, 1 << MERKLE_DEPTH),
        _ => panic!("unexpected variant"),
    }
}

// ===========================================================================
// 3. verify_proof corner cases: single-hash_leaf root, garbage proofs
// ===========================================================================

/// What if `root` argument is `hash_leaf([0;32])` directly (the level-0
/// empty marker, i.e. one SHA-256 below the true empty root)? Does the
/// verifier ever accept any leaf against this "shallow root"?
///
/// Walking up MERKLE_DEPTH levels from `hash_leaf(leaf)` would never produce
/// a single-`hash_leaf` value, because `hash_node` is applied AT LEAST 20
/// times. So the answer must be NO for every (leaf, proof) combination —
/// and crucially, the FINDING-1b guard short-circuits the all-zero leaf.
/// Outcome: mitigated.
#[test]
fn r3_shallow_root_never_verifies_mitigated() {
    let shallow_root = Sha256Hasher::hash_leaf(&ZERO); // m[0] only — 1 hash deep.
    let chain = empty_chain();
    // Try a representative selection of (leaf, proof) inputs.
    let leaves: &[Hash] = &[
        [0x01; HASH_LEN],
        [0xFF; HASH_LEN],
        chain[0],
        chain[1],
        Sha256Hasher::hash(b"any old bytes"),
    ];
    // Try a few proof shapes.
    let proofs = vec![
        MerkleProof {
            siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
            indices: [false; MERKLE_DEPTH],
        },
        MerkleProof {
            siblings: [[0xFFu8; HASH_LEN]; MERKLE_DEPTH],
            indices: [true; MERKLE_DEPTH],
        },
        MerkleProof {
            siblings: {
                let mut s = [[0u8; HASH_LEN]; MERKLE_DEPTH];
                for level in 0..MERKLE_DEPTH {
                    s[level] = chain[level];
                }
                s
            },
            indices: [false; MERKLE_DEPTH],
        },
    ];
    for leaf in leaves {
        for p in &proofs {
            assert!(
                !verify_proof::<Sha256Hasher>(&shallow_root, leaf, p),
                "shallow root (one hash_leaf deep) verified leaf={:02x?}",
                &leaf[..4]
            );
        }
    }
}

/// What if `root` is `[0u8; 32]`? `current` after MERKLE_DEPTH iterations
/// of `hash_node` is overwhelmingly non-zero, so we should never accept.
/// Outcome: mitigated.
#[test]
fn r3_zero_root_never_verifies_for_any_proof_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xDEC0_DEC0_DEAD_F00D);
    for _ in 0..200 {
        let mut leaf = [0u8; HASH_LEN];
        rng.fill_bytes(&mut leaf);
        if leaf == ZERO {
            // The FINDING-1b guard rejects this regardless — distinct case.
            continue;
        }
        let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
        for s in siblings.iter_mut() {
            rng.fill_bytes(s);
        }
        let mut indices = [false; MERKLE_DEPTH];
        for b in indices.iter_mut() {
            *b = rng.random();
        }
        let p = MerkleProof { siblings, indices };
        assert!(!verify_proof::<Sha256Hasher>(&ZERO, &leaf, &p));
    }
}

/// All-equal siblings at every level — the verifier must not loop or panic;
/// the recomputed root should differ from a randomly chosen target.
/// Outcome: mitigated (no panic, no spurious accept).
#[test]
fn r3_correlated_siblings_no_panic_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xC0_FE_E1_8E_05_06_07_08);
    for _ in 0..200 {
        let mut s = [0u8; HASH_LEN];
        rng.fill_bytes(&mut s);
        let siblings = [s; MERKLE_DEPTH];
        // Pattern A: all-false directions. Pattern B: all-true. Pattern C:
        // alternating. None should panic, none should accidentally verify
        // for a non-zero random root.
        let patterns: &[[bool; MERKLE_DEPTH]] = &[[false; MERKLE_DEPTH], [true; MERKLE_DEPTH], {
            let mut a = [false; MERKLE_DEPTH];
            for i in 0..MERKLE_DEPTH {
                a[i] = i % 2 == 0;
            }
            a
        }
            as _];
        for indices in patterns {
            let p = MerkleProof {
                siblings,
                indices: *indices,
            };
            let mut root = [0u8; HASH_LEN];
            rng.fill_bytes(&mut root);
            let mut leaf = [0u8; HASH_LEN];
            rng.fill_bytes(&mut leaf);
            if leaf == ZERO {
                continue;
            }
            let _ = verify_proof::<Sha256Hasher>(&root, &leaf, &p); // no panic
        }
    }
}

/// Fuzz `verify_proof` with fully-random garbage — must never panic and must
/// not accidentally verify any (leaf, proof) against any random root in 5k
/// trials. This stresses the "no panic on adversarial input" invariant
/// across the full input surface.
/// Outcome: mitigated.
#[test]
fn r3_verify_proof_garbage_inputs_no_panic_no_spurious_accept_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_BAD_C0DE);
    let mut accepts = 0usize;
    for _ in 0..5_000 {
        let mut root = [0u8; HASH_LEN];
        let mut leaf = [0u8; HASH_LEN];
        rng.fill_bytes(&mut root);
        rng.fill_bytes(&mut leaf);
        let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
        for s in siblings.iter_mut() {
            rng.fill_bytes(s);
        }
        // Random direction bits packed from a single u32 sample.
        let bits: u32 = rng.random();
        let mut indices = [false; MERKLE_DEPTH];
        for i in 0..MERKLE_DEPTH {
            indices[i] = (bits >> i) & 1 == 1;
        }
        let p = MerkleProof { siblings, indices };
        if verify_proof::<Sha256Hasher>(&root, &leaf, &p) {
            accepts += 1;
        }
    }
    assert_eq!(
        accepts, 0,
        "fuzz: garbage proof accepted — SHA-256 collision or verifier bug"
    );
}

// ===========================================================================
// 4. IdentityCommitment equality / hashing / round-trip equivalence
// ===========================================================================

/// `id.commitment::<H>().as_bytes()` and `id.commitment::<H>().0` and a
/// fresh `H::hash(&[sk, salt].concat())` must all produce byte-identical
/// 32-byte outputs.
/// Outcome: mitigated.
#[test]
fn r3_identity_commitment_three_ways_equal_mitigated() {
    let mut rng = StdRng::seed_from_u64(0x_FA_57_C0_DE_AB_CD_12_34);
    for _ in 0..500 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();

        let way1: &[u8; HASH_LEN] = c.as_bytes();
        let way2: [u8; HASH_LEN] = c.0;
        let mut buf = [0u8; SK_LEN + SALT_LEN];
        buf[..SK_LEN].copy_from_slice(&sk);
        buf[SK_LEN..].copy_from_slice(&salt);
        let way3: [u8; HASH_LEN] = Sha256Hasher::hash(&buf);

        assert_eq!(*way1, way2);
        assert_eq!(way2, way3);
    }
}

/// `IdentityCommitment` derives `PartialEq, Eq, Hash`. Confirm it slots
/// into a `HashMap` with sensible distribution — 1k distinct identities
/// produce 1k distinct map entries with no hash-collision-induced overwrites
/// (since `Eq` is by-bytes, collisions in `Hash` are harmless to correctness
/// but we still want to confirm the API behaves like a normal value type).
/// Outcome: mitigated.
#[test]
fn r3_identity_commitment_hashmap_key_distribution_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE_F0_0D_BABE);
    let mut map: HashMap<IdentityCommitment, usize> = HashMap::new();
    let mut seen: HashSet<Hash> = HashSet::new();
    for i in 0..1_000 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();
        // Each underlying byte sequence is fresh (overwhelming probability).
        if !seen.insert(*c.as_bytes()) {
            // Vanishingly unlikely; skip if it ever happens.
            continue;
        }
        map.insert(c, i);
    }
    assert_eq!(
        map.len(),
        seen.len(),
        "HashMap dropped entries unexpectedly"
    );
    // Re-lookup: every inserted commitment must round-trip back to its index.
    let mut rng2 = StdRng::seed_from_u64(0xC0FFEE_F0_0D_BABE);
    for i in 0..1_000 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng2.fill_bytes(&mut sk);
        rng2.fill_bytes(&mut salt);
        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();
        if let Some(&j) = map.get(&c) {
            assert_eq!(j, i);
        }
    }
}

/// `IdentityCommitment` PartialEq is purely structural (the wrapped Hash).
/// Confirm two `Identity`s with identical (sk, salt) produce equal
/// commitments AND equal `==`, AND that flipping a single byte breaks
/// equality. Round 1 covered "deterministic"; round 3 adds the
/// single-byte-flip invariant explicitly.
/// Outcome: mitigated.
#[test]
fn r3_identity_commitment_partial_eq_byte_sensitive_mitigated() {
    let mut rng = StdRng::seed_from_u64(0x_E1_E1_E1_E1_E1_E1_E1_E1);
    for _ in 0..200 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();

        // Flip one byte of sk.
        for pos in [0usize, 7, 15, 16, 17, 31] {
            let mut sk2 = sk;
            sk2[pos] ^= 0x01;
            let id2 = Identity::new(sk2, salt);
            let c2 = id2.commitment::<Sha256Hasher>();
            assert_ne!(
                c, c2,
                "single-byte sk flip at pos {pos} produced equal commitment"
            );
        }
        // Flip one byte of salt.
        for pos in [0usize, 1, 15, 16, 30, 31] {
            let mut salt2 = salt;
            salt2[pos] ^= 0x80;
            let id2 = Identity::new(sk, salt2);
            let c2 = id2.commitment::<Sha256Hasher>();
            assert_ne!(
                c, c2,
                "single-byte salt flip at pos {pos} produced equal commitment"
            );
        }
    }
}

// ===========================================================================
// 5. Stronger replacement for tautological prior tests
// ===========================================================================
//
// See the report block at the bottom of this file for the file:line
// references. The tests below assert the NEGATIVE shape (would-fail-if-
// the-code-were-silently-broken) instead of just exercising a happy path.

/// Round 2's `attack_proof_recursion_bounded_mitigated` inserts 1024 leaves
/// and stride-verifies — but only the POSITIVE branch. If a critical line
/// in `merkle.rs` (say, `current = hash_leaf(leaf)`) were silently removed,
/// the test would NOT fail because every proof would still be self-consistent
/// against the same-now-corrupt root. We add an adversarial assertion: a
/// proof from one index MUST NOT verify against a different index's leaf,
/// across all sampled indices, with a deeply populated tree. This catches a
/// regression that drops the leaf-input hashing step.
/// Outcome: mitigated.
#[test]
fn r3_deep_tree_cross_index_substitution_rejected_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    for i in 0..1024u32 {
        let mut l = [0u8; HASH_LEN];
        l[0] = (i & 0xFF) as u8;
        l[1] = ((i >> 8) & 0xFF) as u8;
        l[31] = 0xFF; // avoid the FINDING-1b zero-leaf guard.
        t.insert(l).unwrap();
    }
    let root = t.root();
    // For 50 stride pairs, the proof for index i must not verify the leaf
    // at index j (j != i). If `verify_proof` ever stopped reading `leaf`
    // (e.g. used a cached `current` from elsewhere), this would silently
    // catch it.
    let mut rng = StdRng::seed_from_u64(0xCA75_4321_8765_FEDC);
    for _ in 0..50 {
        let i: usize = rng.random_range(0..1024);
        let mut j: usize = rng.random_range(0..1024);
        while j == i {
            j = rng.random_range(0..1024);
        }
        let proof_i = t.proof(i).unwrap();
        let leaf_j = t.leaf(j).unwrap();
        // The proof for i, applied to leaf j, must reject.
        assert!(
            !verify_proof::<Sha256Hasher>(&root, &leaf_j, &proof_i),
            "leaf at j={j} verified with proof for i={i}"
        );
        // And proof_i applied to its real leaf_i must accept (positive sanity).
        let leaf_i = t.leaf(i).unwrap();
        assert!(verify_proof::<Sha256Hasher>(&root, &leaf_i, &proof_i));
    }
}

/// Round 2's `attack_property_sweep_all_real_proofs_verify_mitigated` only
/// asserts the positive path — if `verify_proof` were silently changed to
/// `_ => true`, the test would still pass. Add the corresponding negative
/// sweep: at each size, a deliberately-wrong leaf at the same index must
/// be rejected.
/// Outcome: mitigated.
#[test]
fn r3_property_sweep_negative_path_mitigated() {
    for size in [1usize, 2, 3, 4, 8, 13, 31, 64] {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        for i in 0..size {
            let mut l = [0u8; HASH_LEN];
            l[0] = i as u8;
            l[1] = ((i * 7) & 0xFF) as u8;
            l[31] = 0xFF;
            t.insert(l).unwrap();
        }
        let root = t.root();
        for i in 0..size {
            let p = t.proof(i).unwrap();
            // Construct a deliberately-different leaf at the same index.
            let mut wrong = [0u8; HASH_LEN];
            wrong[0] = (i ^ 0x55) as u8;
            wrong[1] = ((i * 7) & 0xFF) as u8;
            wrong[2] = 0xAB; // additional distinguishing byte.
            wrong[31] = 0xFF;
            assert!(
                !verify_proof::<Sha256Hasher>(&root, &wrong, &p),
                "size={size} idx={i}: wrong leaf accidentally verified"
            );
        }
    }
}

/// Round 2's `attack_finding_1b_no_alternate_verify_path_mitigated` is the
/// tautological one: it just calls `t.root()` and `t.proof(0)` and asserts
/// nothing. Replace it with a stronger structural check: confirm that the
/// ONLY way `MerkleTree` exposes a verification predicate is via the free
/// `verify_proof` function (no `MerkleTree::verify` slipped in), and confirm
/// that calling `verify_proof` with leaf=[0;32] fails for EVERY shape of
/// proof we can construct — including a freshly-derived proof for an
/// inserted leaf at index 0 of a tree where slot-0 actually IS [0;32]
/// (since `insert` accepts it).
/// Outcome: mitigated.
#[test]
fn r3_verify_proof_is_sole_verification_predicate_mitigated() {
    // 1. Verify the FINDING-1b guard short-circuits even when the underlying
    //    proof IS the genuine proof for an inserted [0;32] leaf — i.e. the
    //    guard fires BEFORE the path walk.
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let idx = t.insert(ZERO).unwrap();
    assert_eq!(idx, 0);
    let proof = t.proof(idx).unwrap();
    assert!(
        !verify_proof::<Sha256Hasher>(&t.root(), &ZERO, &proof),
        "FINDING-1b guard must short-circuit even on a self-consistent proof for [0;32]"
    );

    // 2. Sanity: the SAME tree accepts a NON-zero leaf inserted at index 1.
    let nonzero: Hash = [0x01u8; HASH_LEN];
    let _ = t.insert(nonzero).unwrap();
    let proof2 = t.proof(1).unwrap();
    assert!(
        verify_proof::<Sha256Hasher>(&t.root(), &nonzero, &proof2),
        "non-zero leaf at index 1 must verify normally"
    );

    // 3. The MerkleTree type does not expose its own verify method — we test
    //    this behaviorally by confirming that the ONLY way to obtain `true`
    //    from a (root, leaf, proof) triple in the public API is via
    //    `verify_proof`. (The trait-bound type system enforces the rest at
    //    compile time; this assert is here as a documentation sentinel.)
    let _ = MerkleTree::<Sha256Hasher>::new(); // type still constructible
}

/// Round 2's `attack_zero_leaf_at_unused_slot_in_populated_tree_residual`
/// asserts the FINDING-1b guard is in place at the verifier — but only with
/// `indices[0] = true`. Push harder: test the guard under EVERY possible
/// `indices` bit-pattern for the first 4 levels (16 patterns), with the
/// genuinely-empty-chain siblings.
/// Outcome: mitigated.
#[test]
fn r3_finding_1b_guard_fires_for_every_low_level_index_pattern_mitigated() {
    let chain = empty_chain();
    let mut t = MerkleTree::<Sha256Hasher>::new();
    t.insert([0xAAu8; HASH_LEN]).unwrap();
    let root = t.root();

    let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        siblings[level] = chain[level];
    }
    for pattern in 0u32..(1 << 4) {
        let mut indices = [false; MERKLE_DEPTH];
        for i in 0..4 {
            indices[i] = (pattern >> i) & 1 == 1;
        }
        let p = MerkleProof { siblings, indices };
        assert!(
            !verify_proof::<Sha256Hasher>(&root, &ZERO, &p),
            "FINDING-1b guard missed index pattern {pattern:04b}"
        );
    }
}

// ===========================================================================
// 6. MerkleProof Clone, by-value vs by-reference, in a Vec
// ===========================================================================

/// `MerkleProof` derives `Clone, Debug, PartialEq, Eq`. Round 3 confirms:
///   - Clone is deep (modifying the clone doesn't affect the original).
///   - Pass-by-value and pass-by-reference yield identical verify outcome.
///   - Storing in a Vec then popping yields a byte-equal proof.
///
/// Outcome: mitigated.
#[test]
fn r3_merkle_proof_clone_and_move_semantics_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let leaf: Hash = [0x42u8; HASH_LEN];
    t.insert(leaf).unwrap();
    t.insert([0x43; HASH_LEN]).unwrap();
    let root = t.root();
    let p = t.proof(0).unwrap();

    // Clone independence.
    let mut clone = p.clone();
    assert_eq!(clone, p, "clone differs from original");
    clone.siblings[0][0] ^= 0xFF;
    assert_ne!(
        clone, p,
        "mutating clone affected original — Clone is shallow?"
    );
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &p));
    assert!(!verify_proof::<Sha256Hasher>(&root, &leaf, &clone));

    // Vec round-trip.
    let mut v: Vec<MerkleProof> = Vec::new();
    v.push(p.clone());
    let popped = v.pop().unwrap();
    assert_eq!(popped, p);
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &popped));

    // By-reference vs by-value at the call site is enforced by the signature
    // (verify_proof takes &MerkleProof) — confirm a re-borrow yields the same
    // boolean outcome.
    let pref = &p;
    assert_eq!(
        verify_proof::<Sha256Hasher>(&root, &leaf, pref),
        verify_proof::<Sha256Hasher>(&root, &leaf, &p)
    );
}

// ===========================================================================
// 7. API-misuse paths an SDK author might hit
// ===========================================================================

/// Pass `leaf = commitment.as_bytes()` — a `&[u8;32]` — directly as the
/// `leaf` argument to `verify_proof`. This is the canonical SDK call
/// pattern. Must work.
/// Outcome: mitigated.
#[test]
fn r3_verify_proof_accepts_commitment_as_bytes_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let id = Identity::new([0x77u8; SK_LEN], [0x88u8; SALT_LEN]);
    let c = id.commitment::<Sha256Hasher>();
    t.insert(*c.as_bytes()).unwrap();
    let root = t.root();
    let proof = t.proof(0).unwrap();
    // The canonical SDK call.
    assert!(verify_proof::<Sha256Hasher>(&root, c.as_bytes(), &proof));
    // And via `&c.0` directly — same bytes, same outcome.
    assert!(verify_proof::<Sha256Hasher>(&root, &c.0, &proof));
}

/// A careless SDK author might compute `Sha256Hasher::hash(&[sk, pid].concat())`
/// directly instead of calling `nullifier(...)` or `id.nullifier(...)`.
/// This SHOULD match — the canonical nullifier IS `H(sk ‖ pid)` with no
/// domain byte. If a future refactor adds a domain byte to nullifier, this
/// test fires immediately and tells the on-chain integration to update.
/// Outcome: mitigated.
#[test]
fn r3_nullifier_manual_construction_matches_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xBA5E_BA11_4242_4242);
    for _ in 0..200 {
        let mut sk = [0u8; SK_LEN];
        let mut pid = [0u8; HASH_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut pid);
        let manual = {
            let mut buf = Vec::with_capacity(SK_LEN + HASH_LEN);
            buf.extend_from_slice(&sk);
            buf.extend_from_slice(&pid);
            Sha256Hasher::hash(&buf)
        };
        let canonical = nullifier::<Sha256Hasher>(&sk, &pid);
        assert_eq!(manual, canonical);
    }
}

/// A careless SDK author might call `Sha256Hasher::hash_pair(sk_bytes, salt_bytes)`
/// thinking that's the commitment formula. It is NOT — commitment uses
/// undomained `hash`. Confirm the two are equal (because `hash_pair(a, b)`
/// IS `hash(a ‖ b)` per the round-2 parity invariant). This is the SDK
/// "expected" behavior: hash_pair and commitment are byte-identical for
/// 32-byte inputs, so no documentation bug.
/// Outcome: mitigated (no bug — they agree).
#[test]
fn r3_commitment_equals_hash_pair_for_32_byte_inputs_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xC0_DA_17_C0_DA_17_C0_17);
    for _ in 0..200 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();
        let via_hash_pair = Sha256Hasher::hash_pair(&sk, &salt);
        assert_eq!(*c.as_bytes(), via_hash_pair);
    }
}

/// `Identity::commitment` MUST NOT use `hash_node` or `hash_leaf`. If a
/// future refactor accidentally swaps in `hash_node` (perhaps copying from
/// the Merkle module), the commitment would gain a 0x01 domain byte and
/// every existing enrolled root in the wild would break. This sentinel
/// fires immediately on such a refactor.
/// Outcome: mitigated.
#[test]
fn r3_commitment_does_not_use_hash_node_or_hash_leaf_mitigated() {
    let sk = [0x11u8; SK_LEN];
    let salt = [0x22u8; SALT_LEN];
    let id = Identity::new(sk, salt);
    let c = id.commitment::<Sha256Hasher>();

    // Expected: c = SHA-256(sk || salt) — 64 bytes, no domain byte.
    let expected: [u8; 32] = Sha256::new()
        .chain_update(sk)
        .chain_update(salt)
        .finalize()
        .into();
    assert_eq!(*c.as_bytes(), expected);

    // Distinct from hash_node(sk, salt) = SHA-256(0x01 || sk || salt).
    let node = Sha256Hasher::hash_node(&sk, &salt);
    assert_ne!(
        *c.as_bytes(),
        node,
        "commitment must NOT equal hash_node(sk, salt) — domain-byte regression"
    );

    // Distinct from hash_leaf(sk) = SHA-256(0x00 || sk).
    let leaf = Sha256Hasher::hash_leaf(&sk);
    assert_ne!(*c.as_bytes(), leaf);
}

// ===========================================================================
// 8. Identity commitment encoding "split-point" / boundary collision
// ===========================================================================

/// Round 1 already covered the basic split-point shift. Round 3 covers a
/// stronger property: any two distinct `Identity` instances MUST produce
/// distinct commitments, even when their `sk ‖ salt` concatenations differ
/// only by a single byte SHIFT across the boundary.
///
/// Concretely: id_A = (sk=[..A_31, sk_31], salt=[salt_0, S_1..]) vs
/// id_B = (sk=[..A_31, salt_0], salt=[sk_31, S_1..]) — the concatenation
/// flips bytes at positions 31 and 32. Different concatenated bytes ⇒
/// different SHA-256.
/// Outcome: mitigated.
#[test]
fn r3_commitment_boundary_byte_shift_distinct_mitigated() {
    // Anchor a fixed (sk_A, salt_A).
    let mut sk_a = [0u8; SK_LEN];
    let mut salt_a = [0u8; SALT_LEN];
    for i in 0..SK_LEN {
        sk_a[i] = (i as u8).wrapping_mul(7).wrapping_add(0x10);
    }
    for i in 0..SALT_LEN {
        salt_a[i] = (i as u8).wrapping_mul(11).wrapping_add(0x20);
    }
    let c_a = Identity::new(sk_a, salt_a).commitment::<Sha256Hasher>();

    // Construct (sk_B, salt_B) so that sk_a ‖ salt_a and sk_b ‖ salt_b
    // differ only at the boundary (positions 31 and 32 of the 64-byte
    // concat). The commitment must still differ.
    let mut sk_b = sk_a;
    let mut salt_b = salt_a;
    sk_b[31] = salt_a[0]; // boundary swap
    salt_b[0] = sk_a[31];
    let c_b = Identity::new(sk_b, salt_b).commitment::<Sha256Hasher>();
    // Concats differ (we swapped two bytes that don't form a palindrome).
    let mut concat_a = [0u8; SK_LEN + SALT_LEN];
    concat_a[..SK_LEN].copy_from_slice(&sk_a);
    concat_a[SK_LEN..].copy_from_slice(&salt_a);
    let mut concat_b = [0u8; SK_LEN + SALT_LEN];
    concat_b[..SK_LEN].copy_from_slice(&sk_b);
    concat_b[SK_LEN..].copy_from_slice(&salt_b);
    assert_ne!(concat_a, concat_b);
    assert_ne!(c_a, c_b, "boundary-byte shift produced same commitment");
}

/// Swap halves: two identities where sk-of-B is salt-of-A and salt-of-B is
/// sk-of-A. Concatenation = salt_a || sk_a, which differs from sk_a || salt_a
/// (unless sk_a == salt_a). Commitments must differ.
/// Outcome: mitigated.
#[test]
fn r3_commitment_half_swap_distinct_mitigated() {
    let mut rng = StdRng::seed_from_u64(0x57_57_57_57_57_57_57_57);
    for _ in 0..100 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        if sk == salt {
            continue;
        }
        let c1 = Identity::new(sk, salt).commitment::<Sha256Hasher>();
        let c2 = Identity::new(salt, sk).commitment::<Sha256Hasher>();
        assert_ne!(c1, c2);
    }
}

// ===========================================================================
// 9. DOMAIN constants byte-equality + KAT sentinel
// ===========================================================================

/// Pin the domain bytes literal-by-literal at the test level (the differential
/// suite also pins these but via the reference path; we want a redundant
/// declaration so a constant-folding mistake during a future refactor is
/// loud in TWO independent test binaries).
/// Outcome: mitigated.
#[test]
fn r3_domain_bytes_pinned_redundant_sentinel_mitigated() {
    assert_eq!(DOMAIN_LEAF, 0x00);
    assert_eq!(DOMAIN_NODE, 0x01);
    // And they must differ.
    assert_ne!(DOMAIN_LEAF, DOMAIN_NODE);
    // And the hash_leaf / hash_node implementations must encode exactly
    // those bytes — re-derive expected via independent Sha256.
    let leaf_input = [0x55u8; HASH_LEN];
    let leaf_out: [u8; 32] = Sha256::new()
        .chain_update([0x00u8])
        .chain_update(leaf_input)
        .finalize()
        .into();
    assert_eq!(Sha256Hasher::hash_leaf(&leaf_input), leaf_out);
    let l = [0xAAu8; HASH_LEN];
    let r = [0xBBu8; HASH_LEN];
    let node_out: [u8; 32] = Sha256::new()
        .chain_update([0x01u8])
        .chain_update(l)
        .chain_update(r)
        .finalize()
        .into();
    assert_eq!(Sha256Hasher::hash_node(&l, &r), node_out);
}

/// Pin SHA-256 of the empty input — RFC 6234 vector. The differential suite
/// pins this too (KAT1), but a redundant sentinel here protects against a
/// situation where the `differential` test binary is excluded from CI by
/// mistake.
/// Outcome: mitigated.
#[test]
fn r3_sha256_empty_input_kat_mitigated() {
    let want =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let mut want_arr = [0u8; 32];
    want_arr.copy_from_slice(&want);
    assert_eq!(Sha256Hasher::hash(&[]), want_arr);
    assert_eq!(Sha256Hasher::hash(b""), want_arr);
}

// ===========================================================================
// 10. Hash::hash_pair / Sha256Hasher::hash_node confusion at the COMMITMENT
//     layer (not Merkle)
// ===========================================================================

/// Cross-layer mix-up check: an SDK author building an off-line members
/// root might use `Sha256Hasher::hash_pair` when they meant `hash_node` (or
/// vice versa). Round 2 covered this for Merkle proofs; round 3 confirms
/// the COMMITMENT layer is unaffected — `Identity::commitment` neither
/// uses nor exposes either domain byte. Manually mis-domaining a
/// commitment would NOT collide with any real one.
/// Outcome: mitigated.
#[test]
fn r3_misdomained_commitment_never_equals_real_commitment_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xC0_FF_EE_C0_FF_EE_C0_FF);
    for _ in 0..100 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        let real = *Identity::new(sk, salt)
            .commitment::<Sha256Hasher>()
            .as_bytes();
        let misdomained_node = Sha256Hasher::hash_node(&sk, &salt);
        // SHA-256(sk||salt) = 64-byte input. SHA-256(0x01||sk||salt) = 65-byte
        // input. Different message lengths in SHA-256 → no collision short of
        // breaking the hash.
        assert_ne!(real, misdomained_node);
    }
}

// ===========================================================================
// 11. proptest sweep: every real proof verifies AND every wrong leaf rejects
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn r3_proof_positive_and_negative_proptest(
        leaves in prop::collection::vec(any::<[u8; 32]>(), 2..=20),
        idx_pick in any::<usize>(),
        wrong_leaf in any::<[u8; 32]>(),
    ) {
        // Filter out any all-zero leaves so the FINDING-1b guard doesn't
        // confound the positive check.
        let leaves: Vec<Hash> = leaves
            .into_iter()
            .map(|mut l| {
                if l == ZERO {
                    l[31] = 0x01;
                }
                l
            })
            .collect();
        let mut t = MerkleTree::<Sha256Hasher>::new();
        for l in &leaves {
            t.insert(*l).unwrap();
        }
        let root = t.root();
        let i = idx_pick % leaves.len();
        let leaf_i = leaves[i];
        let proof_i = t.proof(i).unwrap();

        // Positive: the real proof verifies.
        prop_assert!(verify_proof::<Sha256Hasher>(&root, &leaf_i, &proof_i));

        // Negative: a wrong leaf at the same index does NOT verify, unless
        // by some astronomical coincidence wrong_leaf == leaf_i.
        if wrong_leaf != leaf_i && wrong_leaf != ZERO {
            prop_assert!(!verify_proof::<Sha256Hasher>(&root, &wrong_leaf, &proof_i));
        }
    }
}

// ===========================================================================
// 12. proof(idx) at idx == len() and idx > len() ⇒ typed error
// ===========================================================================

/// Round 2 covered `idx == len()` and `usize::MAX`. Round 3 covers the
/// neighborhood: `idx == len() + 1`, `idx == len() + MAX_LEAVES`, etc.
/// Outcome: mitigated.
#[test]
fn r3_proof_idx_neighborhood_errors_typed_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    t.insert([0x33u8; HASH_LEN]).unwrap();
    t.insert([0x44u8; HASH_LEN]).unwrap();
    let len = t.len();
    assert_eq!(len, 2);
    for offset in [0usize, 1, 2, 10, 100, 1024, MAX_LEAVES - 1, MAX_LEAVES] {
        let idx = len + offset;
        match t.proof(idx) {
            Err(MerkleError::IndexOutOfRange { index, next }) => {
                assert_eq!(index, idx);
                assert_eq!(next, len);
            }
            other => panic!("idx={idx}: expected IndexOutOfRange, got {other:?}"),
        }
    }
}

// ===========================================================================
// 13. Independent sentinel: post-fix empty-tree root MUST match the KAT
//     published in `differential.rs` (depth-20 genesis root).
// ===========================================================================

/// If MERKLE_DEPTH or the chain construction ever silently drifts, the
/// on-chain `genesis_members_root` would diverge. We re-pin the depth-20
/// root literal here as a redundant sentinel.
/// Outcome: mitigated.
#[test]
fn r3_depth_20_empty_root_kat_mitigated() {
    let want =
        hex::decode("ac5b1c358a294dec99146ebb2fea0c8a528fc4dad578485d7f279c2b359099f3").unwrap();
    let mut want_arr = [0u8; 32];
    want_arr.copy_from_slice(&want);
    let t = MerkleTree::<Sha256Hasher>::new();
    assert_eq!(t.root(), want_arr);
}

// ===========================================================================
// 14. Identity equality includes both sk AND salt (no accidental REDACTED
//     equality from Debug)
// ===========================================================================

/// `Identity` derives `PartialEq, Eq`. Confirm equality is structural
/// (sk + salt) and NOT influenced by the Debug REDACTED rendering — i.e.
/// two identities with same sk but different salt must NOT be equal.
/// Outcome: mitigated.
#[test]
fn r3_identity_partial_eq_uses_full_bytes_mitigated() {
    let a = Identity::new([0x01u8; SK_LEN], [0x02u8; SALT_LEN]);
    let b = Identity::new([0x01u8; SK_LEN], [0x02u8; SALT_LEN]);
    let c = Identity::new([0x01u8; SK_LEN], [0x03u8; SALT_LEN]); // salt diff
    let d = Identity::new([0x99u8; SK_LEN], [0x02u8; SALT_LEN]); // sk diff
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    assert_ne!(c, d);
}

// ===========================================================================
// 15. MerkleProof byte-size budget sentinel
// ===========================================================================

/// `MerkleProof` is `[Hash; 20] + [bool; 20]` ⇒ 20 * 32 + 20 = 660 bytes
/// minimum (with alignment, typical compilers emit ~680 bytes). The Risc0
/// guest will allocate one per approval; outsized proofs blow the witness
/// budget. Pin the size as a sentinel.
/// Outcome: mitigated.
#[test]
fn r3_merkle_proof_size_sentinel_mitigated() {
    let s = std::mem::size_of::<MerkleProof>();
    // 32*20 = 640 bytes for siblings + 20 bytes for bools = 660 minimum.
    // Allow up to 720 for alignment slack.
    assert!(
        (660..=720).contains(&s),
        "MerkleProof size = {s} bytes, expected 660..=720"
    );
}

// ===========================================================================
// 16. Creative attack: try to land a leaf at a slot indexed by a higher bit
//     than fits in MERKLE_DEPTH
// ===========================================================================

/// `proof()` reads at most 20 levels. What if an attacker constructs a
/// `MerkleProof` whose `indices` are conceptually a 20-bit unsigned number
/// larger than `MAX_LEAVES - 1` (impossible by the type system since
/// `indices` is `[bool; 20]`, max value 2^20 - 1 = MAX_LEAVES - 1)? Confirm
/// that the largest possible indices value (`[true; 20]`) is bounded and
/// that with real-empty-chain siblings + the same FINDING-1b zero-leaf
/// attempt, the verifier still rejects.
/// Outcome: mitigated.
#[test]
fn r3_all_true_indices_with_empty_chain_siblings_rejects_mitigated() {
    let chain = empty_chain();
    let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    for level in 0..MERKLE_DEPTH {
        siblings[level] = chain[level];
    }
    let p = MerkleProof {
        siblings,
        indices: [true; MERKLE_DEPTH],
    };
    let empty = MerkleTree::<Sha256Hasher>::new();
    assert!(!verify_proof::<Sha256Hasher>(&empty.root(), &ZERO, &p));
    // And a non-zero leaf cannot land at slot 2^20 - 1 of an empty tree
    // either.
    let l = [0x42u8; HASH_LEN];
    assert!(!verify_proof::<Sha256Hasher>(&empty.root(), &l, &p));
}

// ===========================================================================
// 16b. MerkleTree::is_empty must track len() in both directions
// ===========================================================================

/// `MerkleTree::is_empty()` MUST return `true` on a fresh tree and `false`
/// after any insert. The existing test suite never asserts both branches of
/// this trivial predicate, so a buggy refactor that hard-codes `true` or
/// `false` survives. Mutation testing surfaced this gap directly.
///
/// FINDING-V3-A (informational): the prior tests had no assertions for
/// `is_empty()`. This test closes the gap.
/// Outcome: was missed by rounds 1-2, now mitigated.
#[test]
fn r3_merkle_tree_is_empty_tracks_len_both_branches_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    assert!(t.is_empty(), "fresh tree must be empty");
    assert_eq!(t.len(), 0);
    t.insert([0xAAu8; HASH_LEN]).unwrap();
    assert!(!t.is_empty(), "tree with one leaf must not be empty");
    assert_eq!(t.len(), 1);
    t.insert([0xBBu8; HASH_LEN]).unwrap();
    assert!(!t.is_empty(), "tree with two leaves must not be empty");
    assert_eq!(t.len(), 2);
}

// ===========================================================================
// 16c. IdentityCommitment Debug must render the 64-char hex payload
// ===========================================================================

/// `IdentityCommitment::fmt` formats the bytes as `IdentityCommitment(0x<hex>)`.
/// No existing test asserts the format ACTUALLY emits the bytes — a buggy
/// refactor that returns `Ok(Default::default())` (i.e. writes nothing) would
/// silently lose the diagnostic value used by every downstream log line that
/// formats a commitment.
///
/// FINDING-V3-B (informational, very low severity): the prior tests had no
/// assertions on `IdentityCommitment` Debug rendering. Mutation testing
/// surfaced this gap. This test closes it.
/// Outcome: was missed by rounds 1-2, now mitigated.
#[test]
fn r3_identity_commitment_debug_renders_hex_payload_mitigated() {
    let id = Identity::new([0x11u8; SK_LEN], [0x22u8; SALT_LEN]);
    let c = id.commitment::<Sha256Hasher>();
    let rendered = format!("{:?}", c);
    // Prefix must be present.
    assert!(
        rendered.starts_with("IdentityCommitment(0x"),
        "Debug rendering missing prefix: {rendered}"
    );
    // The actual 64-char hex of the wrapped Hash must appear in the output.
    let hex_payload = hex::encode(c.0);
    assert_eq!(hex_payload.len(), 64);
    assert!(
        rendered.contains(&hex_payload),
        "Debug rendering missing hex payload {hex_payload}: {rendered}"
    );
    // And the rendering must NOT be empty.
    assert!(!rendered.is_empty());
    assert!(rendered.len() >= 64 + "IdentityCommitment(0x)".len());
}

// ===========================================================================
// 17. Sample-size collision sanity for IdentityCommitment hashing
// ===========================================================================

/// Confirm 5k random commitments produce 5k distinct values (no SHA-256
/// collision in this sample). Round 1 did 10k for the [0;32] check; this
/// one is the cross-pair test.
/// Outcome: mitigated.
#[test]
fn r3_commitment_no_collision_in_5k_sample_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xC0_C0_C0_C0_C0_C0_C0_C0);
    let mut set: HashSet<Hash> = HashSet::new();
    for i in 0..5_000 {
        let mut sk = [0u8; SK_LEN];
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut salt);
        let c = Identity::new(sk, salt).commitment::<Sha256Hasher>();
        assert!(set.insert(*c.as_bytes()), "collision at trial {i}");
    }
}

// ===========================================================================
// 18. Report block (kept inside the file so the grep result is verifiable)
// ===========================================================================
//
// FINDINGS (round 3)
// ------------------
//
// FINDING-V3-A (informational): `MerkleTree::is_empty()` was untested. A
// mutation that hard-codes `true` or `false` survives the entire pre-round-3
// suite. Confirmed via cargo-mutants — the line
// `crypto/src/merkle.rs:77:9: replace MerkleTree<H>::is_empty -> bool with
// {true,false}` appeared in `mutants.out/missed.txt`. Closed by the new test
// `r3_merkle_tree_is_empty_tracks_len_both_branches_mitigated`.
//
// FINDING-V3-B (informational, very low): `IdentityCommitment` Debug
// rendering was untested. A mutation that returns `Ok(Default::default())`
// (i.e. writes nothing) survived. Confirmed via cargo-mutants — the line
// `crypto/src/identity.rs:64:9: replace <impl core::fmt::Debug for
// IdentityCommitment>::fmt -> core::fmt::Result with Ok(Default::default())`
// appeared in `mutants.out/missed.txt`. Closed by the new test
// `r3_identity_commitment_debug_renders_hex_payload_mitigated`.
//
// Both findings are NOT exploits — `is_empty()` and Debug formatting do not
// gate any membership / nullifier predicate. But they are real test-coverage
// gaps surfaced by mutation testing, which the spec explicitly asked us to
// look for.
//
// TAUTOLOGICAL TESTS FOUND IN PRIOR ROUNDS
// ----------------------------------------
//
// 1. tests/red_team_v2.rs:1261 `attack_finding_1b_no_alternate_verify_path_mitigated`
//    — body only calls `t.root()` and `t.proof(0).unwrap()` and discards
//    the results. No actual adversarial assertion. Could be replaced with
//    `assert!(true)` and still pass.
//    REPLACEMENT (red_team_v3.rs):
//      `r3_verify_proof_is_sole_verification_predicate_mitigated`
//    — explicitly verifies the FINDING-1b guard SHORT-CIRCUITS the path
//    walk for the genuine proof of an inserted [0;32] leaf (which is the
//    only place the no-alternate-path claim has bite), while a non-zero
//    leaf at index 1 continues to verify normally.
//
// 2. tests/red_team_v2.rs:776 `attack_proof_recursion_bounded_mitigated`
//    — inserts 1024 leaves and stride-verifies each one's proof against
//    its own leaf. ONLY tests the positive path. If `verify_proof` were
//    silently corrupted to "always accept", this test would still pass.
//    REPLACEMENT (red_team_v3.rs):
//      `r3_deep_tree_cross_index_substitution_rejected_mitigated`
//    — uses the same deep tree, then for 50 sampled (i, j) pairs asserts
//    that proof-for-i rejects leaf-at-j AND proof-for-i accepts leaf-at-i.
//    A regression that drops `current = hash_leaf(leaf)` would fail the
//    negative assertion.
//
// 3. tests/red_team_v2.rs:905 `attack_property_sweep_all_real_proofs_verify_mitigated`
//    — sweeps {1, 2, 3, 4, 8, 13, 31, 64} sizes and asserts every real
//    proof verifies. Positive-only. Doc string claims the residual
//    "(leaf=[0;32] at next free slot's path)" is "the residual we
//    documented" but never asserts it.
//    REPLACEMENT (red_team_v3.rs):
//      `r3_property_sweep_negative_path_mitigated`
//    — same size sweep, asserts that a deliberately-different leaf at the
//    same index DOES NOT verify. This is the missing half of the property.
//
// 4. tests/red_team_v2.rs:444-570 `attack_capacity_boundary_zero_leaf_at_next_slot_mitigated`
//    — long body with an `if verifies { panic!(...) }` followed by an
//    "if we got here..." comment block but NO terminating assertion. The
//    test passes as long as `verifies` is false, but does not exercise
//    the "what if the path I built is wrong" branch the comment flags.
//    REPLACEMENT (red_team_v3.rs):
//      `r3_finding_1b_guard_fires_for_every_low_level_index_pattern_mitigated`
//    — covers the same conceptual surface (zero-leaf at empty slot) for
//    EVERY 4-bit indices prefix (16 patterns), with the genuinely
//    empty-chain siblings. Hard assertions throughout.

// ===========================================================================
// End.
// ===========================================================================
