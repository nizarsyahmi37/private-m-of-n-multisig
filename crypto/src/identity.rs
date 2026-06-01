//! Member identity and its public commitment.
//!
//! `Identity { sk, salt }` is the secret material held only by the member. The
//! public commitment is `H(sk ‖ salt)` — what gets enrolled as a Merkle leaf.
//!
//! This crate keeps `sk` as raw bytes; the SDK is responsible for wrapping it
//! in `secrecy::Secret` with `Zeroize` on drop (per PLAN.md §SDK + THREAT_MODEL.md
//! T6.1 / T6.2). Keeping the crypto core dependency-free preserves portability
//! into the Risc0 guest, where `secrecy` adds avoidable weight.

use crate::hash::{Hash, Hasher, HASH_LEN};
use crate::nullifier;

pub const SK_LEN: usize = 32;
pub const SALT_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub sk: [u8; SK_LEN],
    pub salt: [u8; SALT_LEN],
}

impl Identity {
    pub fn new(sk: [u8; SK_LEN], salt: [u8; SALT_LEN]) -> Self {
        Self { sk, salt }
    }

    pub fn commitment<H: Hasher>(&self) -> IdentityCommitment {
        let mut buf = [0u8; SK_LEN + SALT_LEN];
        buf[..SK_LEN].copy_from_slice(&self.sk);
        buf[SK_LEN..].copy_from_slice(&self.salt);
        IdentityCommitment(H::hash(&buf))
    }

    /// Derive this identity's nullifier for `proposal_id`. Keeps `sk` inside
    /// `Identity` at the call site instead of forcing callers to pass
    /// `&identity.sk` directly — slightly easier to audit which call sites
    /// actually touch the secret.
    pub fn nullifier<H: Hasher>(&self, proposal_id: &Hash) -> Hash {
        nullifier::<H>(&self.sk, proposal_id)
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("sk", &"[REDACTED]")
            .field("salt", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityCommitment(pub Hash);

impl IdentityCommitment {
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for IdentityCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IdentityCommitment(0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256Hasher;

    #[test]
    fn commitment_is_deterministic() {
        let id = Identity::new([1u8; 32], [2u8; 32]);
        let c1 = id.commitment::<Sha256Hasher>();
        let c2 = id.commitment::<Sha256Hasher>();
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_salt_yields_different_commitment() {
        let id1 = Identity::new([1u8; 32], [2u8; 32]);
        let id2 = Identity::new([1u8; 32], [3u8; 32]);
        assert_ne!(
            id1.commitment::<Sha256Hasher>(),
            id2.commitment::<Sha256Hasher>()
        );
    }

    #[test]
    fn different_sk_yields_different_commitment() {
        let id1 = Identity::new([1u8; 32], [2u8; 32]);
        let id2 = Identity::new([9u8; 32], [2u8; 32]);
        assert_ne!(
            id1.commitment::<Sha256Hasher>(),
            id2.commitment::<Sha256Hasher>()
        );
    }

    #[test]
    fn debug_redacts_secret_material() {
        let id = Identity::new([0xAB; 32], [0xCD; 32]);
        let rendered = format!("{:?}", id);
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("ab"));
        assert!(!rendered.contains("cd"));
    }

    #[test]
    fn nullifier_helper_matches_free_function() {
        let id = Identity::new([0x11; 32], [0x22; 32]);
        let pid = [0x33; 32];
        assert_eq!(
            id.nullifier::<Sha256Hasher>(&pid),
            crate::nullifier::<Sha256Hasher>(&id.sk, &pid)
        );
    }
}
