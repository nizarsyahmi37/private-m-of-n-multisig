//! Property-based tests for the LP-0002 crypto core.
//!
//! Covers the invariants the Risc0 guest, the on-chain verifier, and the SDK
//! all rely on: deterministic commitments, deterministic nullifiers, Merkle
//! proof round-trips, and the parity invariant between `hash_pair` and
//! `hash(left ‖ right)` (THREAT_MODEL.md T5.3).
//!
//! Per the task brief: cheap properties bump `cases: 1000`; properties that
//! insert many leaves stay on the default (256) to keep the suite snappy.

use crypto::{
    merkle::verify_proof, Hash, Hasher, Identity, MerkleTree, Sha256Hasher, HASH_LEN,
    MERKLE_DEPTH,
};
use proptest::prelude::*;

// ---- Strategies -----------------------------------------------------------

fn arb_hash() -> impl Strategy<Value = Hash> {
    any::<[u8; 32]>()
}

fn arb_sk() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_salt() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_leaves(max_len: usize) -> impl Strategy<Value = Vec<Hash>> {
    prop::collection::vec(arb_hash(), 1..=max_len)
}

// ---- Cheap properties (cases: 1000) ---------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, .. ProptestConfig::default() })]

    #[test]
    fn commitment_deterministic(sk in arb_sk(), salt in arb_salt()) {
        let id = Identity::new(sk, salt);
        let c1 = id.commitment::<Sha256Hasher>();
        let c2 = id.commitment::<Sha256Hasher>();
        prop_assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_sensitive_to_inputs(
        sk1 in arb_sk(), salt1 in arb_salt(),
        sk2 in arb_sk(), salt2 in arb_salt(),
    ) {
        prop_assume!((sk1, salt1) != (sk2, salt2));
        let c1 = Identity::new(sk1, salt1).commitment::<Sha256Hasher>();
        let c2 = Identity::new(sk2, salt2).commitment::<Sha256Hasher>();
        prop_assert_ne!(c1, c2);
    }

    #[test]
    fn nullifier_deterministic(sk in arb_sk(), pid in arb_hash()) {
        let n1 = crypto::nullifier::<Sha256Hasher>(&sk, &pid);
        let n2 = crypto::nullifier::<Sha256Hasher>(&sk, &pid);
        prop_assert_eq!(n1, n2);
    }

    #[test]
    fn nullifier_changes_when_sk_changes(
        sk1 in arb_sk(), sk2 in arb_sk(), pid in arb_hash(),
    ) {
        prop_assume!(sk1 != sk2);
        let n1 = crypto::nullifier::<Sha256Hasher>(&sk1, &pid);
        let n2 = crypto::nullifier::<Sha256Hasher>(&sk2, &pid);
        prop_assert_ne!(n1, n2);
    }

    #[test]
    fn nullifier_changes_when_pid_changes(
        sk in arb_sk(), pid1 in arb_hash(), pid2 in arb_hash(),
    ) {
        prop_assume!(pid1 != pid2);
        let n1 = crypto::nullifier::<Sha256Hasher>(&sk, &pid1);
        let n2 = crypto::nullifier::<Sha256Hasher>(&sk, &pid2);
        prop_assert_ne!(n1, n2);
    }

    #[test]
    fn hash_output_is_32_bytes(input in prop::collection::vec(any::<u8>(), 0..=1024)) {
        let out = Sha256Hasher::hash(&input);
        prop_assert_eq!(out.len(), 32);
    }

    #[test]
    fn hash_pair_matches_concat(a in arb_hash(), b in arb_hash()) {
        let pair = Sha256Hasher::hash_pair(&a, &b);
        let concat = [a.as_slice(), b.as_slice()].concat();
        prop_assert_eq!(pair, Sha256Hasher::hash(&concat));
    }
}

// ---- Merkle properties (default cases: 256, since each test inserts many leaves) ----

proptest! {
    #[test]
    fn merkle_inserted_leaf_verifies(leaves in arb_leaves(64)) {
        let mut tree = MerkleTree::<Sha256Hasher>::new();
        for l in &leaves {
            tree.insert(*l).unwrap();
        }
        let root = tree.root();
        for (i, l) in leaves.iter().enumerate() {
            let proof = tree.proof(i).expect("proof for own leaf");
            prop_assert!(
                verify_proof::<Sha256Hasher>(&root, l, &proof),
                "proof failed for leaf {}", i,
            );
        }
    }

    #[test]
    fn merkle_sibling_bit_flip_invalidates(
        leaves in arb_leaves(32),
        idx_pick in any::<usize>(),
        level_pick in 0usize..MERKLE_DEPTH,
        byte_pick in 0usize..HASH_LEN,
        bit_pick in 0u8..8,
    ) {
        let mut tree = MerkleTree::<Sha256Hasher>::new();
        for l in &leaves {
            tree.insert(*l).unwrap();
        }
        let root = tree.root();
        let i = idx_pick % leaves.len();
        let leaf = leaves[i];
        let mut proof = tree.proof(i).unwrap();

        // Flip a single bit in a sibling. Sanity-check the original proof
        // verifies, otherwise the flip invariant is vacuous.
        prop_assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &proof));
        proof.siblings[level_pick][byte_pick] ^= 1u8 << bit_pick;
        prop_assert!(
            !verify_proof::<Sha256Hasher>(&root, &leaf, &proof),
            "flipped bit at level={} byte={} bit={} still verified",
            level_pick, byte_pick, bit_pick,
        );
    }

    #[test]
    fn merkle_substitute_leaf_invalidates(
        leaves in prop::collection::vec(arb_hash(), 2..=32),
        idx_pick in any::<usize>(),
        replacement in arb_hash(),
    ) {
        let mut tree = MerkleTree::<Sha256Hasher>::new();
        for l in &leaves {
            tree.insert(*l).unwrap();
        }
        let root = tree.root();
        let i = idx_pick % leaves.len();
        let real_leaf = leaves[i];
        // Skip the rare equal-byte case — the property is only meaningful when
        // we're truly substituting.
        prop_assume!(replacement != real_leaf);
        let proof = tree.proof(i).unwrap();
        prop_assert!(verify_proof::<Sha256Hasher>(&root, &real_leaf, &proof));
        prop_assert!(
            !verify_proof::<Sha256Hasher>(&root, &replacement, &proof),
            "substituted leaf still verified at index {}", i,
        );
    }
}
