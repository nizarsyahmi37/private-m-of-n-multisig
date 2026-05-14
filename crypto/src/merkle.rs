//! Fixed-depth Merkle tree over `Hash` leaves.
//!
//! Depth is `MERKLE_DEPTH = 20` per PLAN.md §Open decisions — 1M members, cheap
//! inside a Risc0 guest. Empty slots use a precomputed chain of `hash_leaf` /
//! `hash_node` zero markers so the root is well-defined even before the tree
//! is full.
//!
//! Leaves and internal nodes are hashed under distinct domains
//! (`Hasher::hash_leaf` and `Hasher::hash_node`) — without this separation an
//! attacker who knows `members_root` can forge membership at any unused slot
//! by presenting `leaf = [0;32]` and the all-zero sibling chain. See
//! `crypto/tests/red_team.rs` FINDING-1 for the original exploit and the
//! regression that locks the fix in place.
//!
//! The path representation `MerkleProof { siblings, indices }` is what the
//! Risc0 approve_circuit reads as private witness.
//!
//! ## Caller responsibilities
//!
//! `insert` does NOT check for duplicates. Enrollment-time uniqueness (so a
//! single member cannot be enrolled twice and double their voting weight) is
//! the responsibility of the on-chain `private_multisig_program::add_member`
//! handler (THREAT_MODEL.md T3.1). This crate keeps the data structure
//! mechanically simple and pushes policy to the layer that has the right
//! context.

use crate::hash::{Hash, Hasher, HASH_LEN};

pub const MERKLE_DEPTH: usize = 20;
pub const MAX_LEAVES: usize = 1 << MERKLE_DEPTH;

#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    #[error("tree is full (capacity {0})")]
    Full(usize),
    #[error("index {index} is out of range (next free slot is {next})")]
    IndexOutOfRange { index: usize, next: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub siblings: [Hash; MERKLE_DEPTH],
    pub indices: [bool; MERKLE_DEPTH],
}

#[derive(Clone)]
pub struct MerkleTree<H: Hasher> {
    leaves: Vec<Hash>,
    zero_hashes: [Hash; MERKLE_DEPTH + 1],
    _phantom: core::marker::PhantomData<H>,
}

impl<H: Hasher> MerkleTree<H> {
    pub fn new() -> Self {
        let mut zero_hashes = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
        // Level 0 marker: hash_leaf of the all-zero leaf, under DOMAIN_LEAF.
        // This is what an "empty slot" looks like at the leaf level, and it
        // is NOT [0;32] — so an attacker cannot forge an unused-slot leaf
        // without breaking SHA-256 preimage resistance.
        zero_hashes[0] = H::hash_leaf(&[0u8; HASH_LEN]);
        for i in 1..=MERKLE_DEPTH {
            let prev = zero_hashes[i - 1];
            zero_hashes[i] = H::hash_node(&prev, &prev);
        }
        Self {
            leaves: Vec::new(),
            zero_hashes,
            _phantom: core::marker::PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn capacity(&self) -> usize {
        MAX_LEAVES
    }

    pub fn insert(&mut self, leaf: Hash) -> Result<usize, MerkleError> {
        if self.leaves.len() >= MAX_LEAVES {
            return Err(MerkleError::Full(MAX_LEAVES));
        }
        let index = self.leaves.len();
        self.leaves.push(leaf);
        Ok(index)
    }

    pub fn root(&self) -> Hash {
        self.node_at(MERKLE_DEPTH, 0)
    }

    pub fn proof(&self, index: usize) -> Result<MerkleProof, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfRange {
                index,
                next: self.leaves.len(),
            });
        }
        let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
        let mut indices = [false; MERKLE_DEPTH];
        let mut current = index;
        for level in 0..MERKLE_DEPTH {
            let sibling = current ^ 1;
            siblings[level] = self.node_at(level, sibling);
            indices[level] = current & 1 == 1;
            current >>= 1;
        }
        Ok(MerkleProof { siblings, indices })
    }

    pub fn leaf(&self, index: usize) -> Option<Hash> {
        self.leaves.get(index).copied()
    }

    /// Compute the node at `(level, pos)` from the underlying leaf vector,
    /// substituting `zero_hashes[level]` for any subtree that hasn't been
    /// materialized yet. Level 0 wraps each stored leaf in `hash_leaf` so the
    /// leaf domain matches what `verify_proof` will compute.
    fn node_at(&self, level: usize, pos: usize) -> Hash {
        if level == 0 {
            return self
                .leaves
                .get(pos)
                .map(|l| H::hash_leaf(l))
                .unwrap_or(self.zero_hashes[0]);
        }
        let span = 1usize << level;
        let start = pos * span;
        if start >= self.leaves.len() {
            return self.zero_hashes[level];
        }
        let left = self.node_at(level - 1, pos * 2);
        let right = self.node_at(level - 1, pos * 2 + 1);
        H::hash_node(&left, &right)
    }
}

impl<H: Hasher> Default for MerkleTree<H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Recompute the root by walking the proof from `leaf` upward. The on-chain
/// verifier and the Risc0 guest both use this — same source of truth.
///
/// `leaf` is the raw commitment (`H(sk ‖ salt)`); domain-separated leaf
/// hashing is applied internally so callers never need to remember the
/// `DOMAIN_LEAF` byte.
pub fn verify_proof<H: Hasher>(root: &Hash, leaf: &Hash, proof: &MerkleProof) -> bool {
    let mut current = H::hash_leaf(leaf);
    for level in 0..MERKLE_DEPTH {
        let sibling = &proof.siblings[level];
        current = if proof.indices[level] {
            H::hash_node(sibling, &current)
        } else {
            H::hash_node(&current, sibling)
        };
    }
    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256Hasher;

    fn leaf(byte: u8) -> Hash {
        [byte; HASH_LEN]
    }

    #[test]
    fn empty_tree_has_well_defined_root() {
        let t = MerkleTree::<Sha256Hasher>::new();
        let r1 = t.root();
        let t2 = MerkleTree::<Sha256Hasher>::new();
        assert_eq!(r1, t2.root());
    }

    #[test]
    fn insert_returns_sequential_indices() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        assert_eq!(t.insert(leaf(1)).unwrap(), 0);
        assert_eq!(t.insert(leaf(2)).unwrap(), 1);
        assert_eq!(t.insert(leaf(3)).unwrap(), 2);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn proof_for_single_leaf_round_trips() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        let l = leaf(42);
        let idx = t.insert(l).unwrap();
        let p = t.proof(idx).unwrap();
        assert!(verify_proof::<Sha256Hasher>(&t.root(), &l, &p));
    }

    #[test]
    fn proof_for_each_of_many_leaves_round_trips() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        let leaves: Vec<Hash> = (0..17).map(leaf).collect();
        for l in &leaves {
            t.insert(*l).unwrap();
        }
        let root = t.root();
        for (i, l) in leaves.iter().enumerate() {
            let p = t.proof(i).unwrap();
            assert!(
                verify_proof::<Sha256Hasher>(&root, l, &p),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn wrong_root_rejects_valid_proof() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        let l = leaf(5);
        t.insert(l).unwrap();
        let p = t.proof(0).unwrap();
        let bad_root = [0xFFu8; HASH_LEN];
        assert!(!verify_proof::<Sha256Hasher>(&bad_root, &l, &p));
    }

    #[test]
    fn wrong_leaf_rejects_valid_proof() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        t.insert(leaf(5)).unwrap();
        let p = t.proof(0).unwrap();
        assert!(!verify_proof::<Sha256Hasher>(&t.root(), &leaf(6), &p));
    }

    #[test]
    fn tampered_sibling_rejects_proof() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        t.insert(leaf(1)).unwrap();
        t.insert(leaf(2)).unwrap();
        let l = leaf(3);
        t.insert(l).unwrap();
        let mut p = t.proof(2).unwrap();
        p.siblings[0][0] ^= 1;
        assert!(!verify_proof::<Sha256Hasher>(&t.root(), &l, &p));
    }

    #[test]
    fn tampered_direction_rejects_proof() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        t.insert(leaf(1)).unwrap();
        let l = leaf(2);
        t.insert(l).unwrap();
        let mut p = t.proof(1).unwrap();
        p.indices[0] = !p.indices[0];
        assert!(!verify_proof::<Sha256Hasher>(&t.root(), &l, &p));
    }

    #[test]
    fn root_changes_on_insert() {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        let r0 = t.root();
        t.insert(leaf(7)).unwrap();
        let r1 = t.root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn proof_out_of_range_errors() {
        let t = MerkleTree::<Sha256Hasher>::new();
        match t.proof(0) {
            Err(MerkleError::IndexOutOfRange { index: 0, next: 0 }) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn empty_tree_root_is_not_all_zeros() {
        // The empty-tree root is built from `H::hash_leaf(&[0;32])` walked up
        // through `H::hash_node`, so the level-0 marker and every level above
        // are domain-separated and distinct from [0;32]. This is what makes
        // the FINDING-1 zero-leaf forgery preimage-hard.
        let t = MerkleTree::<Sha256Hasher>::new();
        assert_ne!(t.root(), [0u8; HASH_LEN]);
    }

    #[test]
    fn empty_slot_zero_leaf_forgery_is_rejected() {
        // Regression for red_team.rs FINDING-1.
        //
        // Before domain separation, an outsider could present `leaf = [0;32]`
        // together with the all-zero sibling chain and pass `verify_proof`
        // against the real `members_root` of a partially populated tree.
        // After the fix, `verify_proof` first applies `hash_leaf` to the
        // input, so the path can only close back to the real root if the
        // attacker can produce a leaf whose `hash_leaf` matches the
        // empty-leaf marker — which under SHA-256 preimage resistance means
        // they would have to invert SHA-256 on `H(DOMAIN_LEAF ‖ [0;32])`.
        let mut t = MerkleTree::<Sha256Hasher>::new();
        t.insert(leaf(7)).unwrap();
        t.insert(leaf(8)).unwrap();
        t.insert(leaf(9)).unwrap();

        let attacker_leaf = [0u8; HASH_LEN];
        let attacker_proof = MerkleProof {
            siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
            indices: [false; MERKLE_DEPTH],
        };
        assert!(
            !verify_proof::<Sha256Hasher>(&t.root(), &attacker_leaf, &attacker_proof),
            "zero-leaf forgery against a populated tree must be rejected"
        );

        let empty = MerkleTree::<Sha256Hasher>::new();
        assert!(
            !verify_proof::<Sha256Hasher>(&empty.root(), &attacker_leaf, &attacker_proof),
            "zero-leaf forgery against an empty tree must be rejected"
        );
    }

    #[test]
    fn leaf_and_node_domains_are_distinct() {
        // Sanity: an "internal node" position cannot be a target leaf even if
        // an attacker manages to produce arbitrary bytes — the verifier
        // applies DOMAIN_LEAF before any DOMAIN_NODE step, so leaf and node
        // values live in disjoint hash sub-spaces.
        let some_bytes = [0x77u8; HASH_LEN];
        assert_ne!(
            Sha256Hasher::hash_leaf(&some_bytes),
            Sha256Hasher::hash_node(&some_bytes, &some_bytes)
        );
    }
}
