//! Fixed-depth Merkle tree over `Hash` leaves.
//!
//! Depth is `MERKLE_DEPTH = 20` per PLAN.md §Open decisions — 1M members, cheap
//! inside a Risc0 guest. Empty slots use a precomputed chain of "zero" hashes so
//! the root is well-defined even before the tree is full.
//!
//! The path representation `MerkleProof { siblings, indices }` is what the
//! Risc0 approve_circuit reads as private witness.

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
        for i in 1..=MERKLE_DEPTH {
            let prev = zero_hashes[i - 1];
            zero_hashes[i] = H::hash_pair(&prev, &prev);
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
    /// materialized yet.
    fn node_at(&self, level: usize, pos: usize) -> Hash {
        if level == 0 {
            return self.leaves.get(pos).copied().unwrap_or(self.zero_hashes[0]);
        }
        let span = 1usize << level;
        let start = pos * span;
        if start >= self.leaves.len() {
            return self.zero_hashes[level];
        }
        let left = self.node_at(level - 1, pos * 2);
        let right = self.node_at(level - 1, pos * 2 + 1);
        H::hash_pair(&left, &right)
    }
}

impl<H: Hasher> Default for MerkleTree<H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Recompute the root by walking the proof from `leaf` upward. The on-chain
/// verifier and the Risc0 guest both use this — same source of truth.
pub fn verify_proof<H: Hasher>(root: &Hash, leaf: &Hash, proof: &MerkleProof) -> bool {
    let mut current = *leaf;
    for level in 0..MERKLE_DEPTH {
        let sibling = &proof.siblings[level];
        current = if proof.indices[level] {
            H::hash_pair(sibling, &current)
        } else {
            H::hash_pair(&current, sibling)
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
}
