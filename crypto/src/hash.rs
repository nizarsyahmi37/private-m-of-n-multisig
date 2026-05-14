//! Hasher trait + SHA-256 implementation.
//!
//! `Hash` is fixed at 32 bytes — sized for both SHA-256 and Poseidon over BN254
//! so the trait can hold either implementation without changing call sites.
//!
//! ## Domain separation
//!
//! Merkle hashing uses two domains:
//! - `DOMAIN_LEAF = 0x00` for leaf-level hashing (`hash_leaf`)
//! - `DOMAIN_NODE = 0x01` for internal-node pair hashing (`hash_node`)
//!
//! Without domain separation, an attacker who knows `members_root` can forge
//! membership at any unused slot by presenting `leaf = [0;32]` and an all-zero
//! sibling chain — the same byte values that the tree uses internally to
//! represent "no leaf here." See `crypto/tests/red_team.rs` FINDING-1 for the
//! exploit and the regression that locks the fix in place.
//!
//! `hash_pair` remains exposed as an undomained utility — it must NOT be used
//! by the Merkle tree, which is required to call `hash_leaf` and `hash_node`.

use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

pub const DOMAIN_LEAF: u8 = 0x00;
pub const DOMAIN_NODE: u8 = 0x01;

pub trait Hasher {
    const NAME: &'static str;

    fn hash(input: &[u8]) -> Hash;

    fn hash_pair(left: &Hash, right: &Hash) -> Hash {
        let mut buf = [0u8; 2 * HASH_LEN];
        buf[..HASH_LEN].copy_from_slice(left);
        buf[HASH_LEN..].copy_from_slice(right);
        Self::hash(&buf)
    }

    /// Domain-separated leaf hashing: `H(DOMAIN_LEAF ‖ leaf)`. Used by
    /// `MerkleTree` so that a leaf input can never be confused with an internal
    /// node hash, and so that the empty-leaf marker is structurally distinct
    /// from any real commitment that a member could produce.
    fn hash_leaf(leaf: &Hash) -> Hash {
        let mut buf = [0u8; 1 + HASH_LEN];
        buf[0] = DOMAIN_LEAF;
        buf[1..].copy_from_slice(leaf);
        Self::hash(&buf)
    }

    /// Domain-separated internal-node hashing: `H(DOMAIN_NODE ‖ left ‖ right)`.
    /// Used by `MerkleTree` for every non-leaf level. Distinct domain byte
    /// from `hash_leaf` ensures a leaf-position hash cannot stand in for an
    /// internal-node hash even if their byte values coincidentally collide.
    fn hash_node(left: &Hash, right: &Hash) -> Hash {
        let mut buf = [0u8; 1 + 2 * HASH_LEN];
        buf[0] = DOMAIN_NODE;
        buf[1..1 + HASH_LEN].copy_from_slice(left);
        buf[1 + HASH_LEN..].copy_from_slice(right);
        Self::hash(&buf)
    }
}

pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    const NAME: &'static str = "sha256";

    fn hash(input: &[u8]) -> Hash {
        let mut h = Sha256::new();
        h.update(input);
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let a = Sha256Hasher::hash(b"hello");
        let b = Sha256Hasher::hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_distinct_inputs_distinct_outputs() {
        let a = Sha256Hasher::hash(b"hello");
        let b = Sha256Hasher::hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_pair_is_order_sensitive() {
        let l = [1u8; HASH_LEN];
        let r = [2u8; HASH_LEN];
        let ab = Sha256Hasher::hash_pair(&l, &r);
        let ba = Sha256Hasher::hash_pair(&r, &l);
        assert_ne!(ab, ba);
    }

    #[test]
    fn hash_pair_matches_concat() {
        let l = [3u8; HASH_LEN];
        let r = [7u8; HASH_LEN];
        let pair = Sha256Hasher::hash_pair(&l, &r);
        let mut concat = [0u8; 2 * HASH_LEN];
        concat[..HASH_LEN].copy_from_slice(&l);
        concat[HASH_LEN..].copy_from_slice(&r);
        assert_eq!(pair, Sha256Hasher::hash(&concat));
    }

    #[test]
    fn hash_leaf_prefixes_with_leaf_domain() {
        let leaf = [0xAAu8; HASH_LEN];
        let mut expected = [0u8; 1 + HASH_LEN];
        expected[0] = DOMAIN_LEAF;
        expected[1..].copy_from_slice(&leaf);
        assert_eq!(Sha256Hasher::hash_leaf(&leaf), Sha256Hasher::hash(&expected));
    }

    #[test]
    fn hash_node_prefixes_with_node_domain() {
        let l = [0xBBu8; HASH_LEN];
        let r = [0xCCu8; HASH_LEN];
        let mut expected = [0u8; 1 + 2 * HASH_LEN];
        expected[0] = DOMAIN_NODE;
        expected[1..1 + HASH_LEN].copy_from_slice(&l);
        expected[1 + HASH_LEN..].copy_from_slice(&r);
        assert_eq!(Sha256Hasher::hash_node(&l, &r), Sha256Hasher::hash(&expected));
    }

    #[test]
    fn hash_leaf_and_hash_node_use_different_domains() {
        // Even with identical underlying bytes the leaf-domain and node-domain
        // outputs must differ. This is what prevents the FINDING-1 forgery:
        // an attacker cannot present a leaf whose bytes collide with an
        // internal node hash.
        let bytes = [0u8; HASH_LEN];
        let l = Sha256Hasher::hash_leaf(&bytes);
        // hash_node of (bytes, bytes) is what the empty-subtree marker at
        // level 1 looks like — must NOT equal the level-0 empty-leaf marker.
        let n = Sha256Hasher::hash_node(&bytes, &bytes);
        assert_ne!(l, n);
    }

    #[test]
    fn empty_leaf_marker_is_not_all_zeros() {
        // The Merkle tree uses Sha256Hasher::hash_leaf(&[0;32]) as its
        // empty-leaf marker. For the FINDING-1 forgery to be hard, this
        // marker must NOT be the all-zero byte string an attacker can present
        // trivially — domain separation ensures it isn't.
        let marker = Sha256Hasher::hash_leaf(&[0u8; HASH_LEN]);
        assert_ne!(marker, [0u8; HASH_LEN]);
    }
}
