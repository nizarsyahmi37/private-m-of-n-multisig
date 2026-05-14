//! Hasher trait + SHA-256 implementation.
//!
//! `Hash` is fixed at 32 bytes — sized for both SHA-256 and Poseidon over BN254
//! so the trait can hold either implementation without changing call sites.

use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

pub trait Hasher {
    const NAME: &'static str;

    fn hash(input: &[u8]) -> Hash;

    fn hash_pair(left: &Hash, right: &Hash) -> Hash {
        let mut buf = [0u8; 2 * HASH_LEN];
        buf[..HASH_LEN].copy_from_slice(left);
        buf[HASH_LEN..].copy_from_slice(right);
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
}
