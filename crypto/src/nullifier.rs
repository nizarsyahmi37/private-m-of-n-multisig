//! Nullifier derivation.
//!
//! `nullifier = H(sk ‖ proposal_id)`. Properties this implementation relies on
//! (see THREAT_MODEL.md T2.x):
//!
//! - Deterministic in (sk, proposal_id): the same member generates the same
//!   nullifier for the same proposal, so a double-vote attempt collides at the
//!   on-chain `NullifierEntry` PDA and `init` fails.
//! - Unlinkable across proposals: different `proposal_id` ⇒ different nullifier,
//!   indistinguishable from random under preimage resistance of H.
//!
//! `proposal_id` is computed elsewhere (in `private_multisig_core`) as
//! `H(chain_id ‖ state_pda ‖ index ‖ H(action_bytes) ‖ H(target_program))` —
//! that binding closes T2.3, T2.4, T2.5. This module only knows the final 32-byte
//! `proposal_id`.

use crate::hash::{Hash, Hasher, HASH_LEN};
use crate::identity::SK_LEN;

pub fn nullifier<H: Hasher>(sk: &[u8; SK_LEN], proposal_id: &Hash) -> Hash {
    let mut buf = [0u8; SK_LEN + HASH_LEN];
    buf[..SK_LEN].copy_from_slice(sk);
    buf[SK_LEN..].copy_from_slice(proposal_id);
    H::hash(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256Hasher;

    #[test]
    fn deterministic_in_inputs() {
        let sk = [1u8; SK_LEN];
        let pid = [2u8; HASH_LEN];
        assert_eq!(
            nullifier::<Sha256Hasher>(&sk, &pid),
            nullifier::<Sha256Hasher>(&sk, &pid)
        );
    }

    #[test]
    fn different_sk_yields_different_nullifier() {
        let pid = [2u8; HASH_LEN];
        let n1 = nullifier::<Sha256Hasher>(&[1u8; SK_LEN], &pid);
        let n2 = nullifier::<Sha256Hasher>(&[9u8; SK_LEN], &pid);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_proposal_yields_different_nullifier() {
        let sk = [1u8; SK_LEN];
        let n1 = nullifier::<Sha256Hasher>(&sk, &[2u8; HASH_LEN]);
        let n2 = nullifier::<Sha256Hasher>(&sk, &[3u8; HASH_LEN]);
        assert_ne!(n1, n2);
    }

    #[test]
    fn input_order_matters() {
        // Quick sanity check that we are not accidentally hashing
        // `proposal_id ‖ sk` somewhere — the on-chain verifier and the guest
        // must agree byte-for-byte (THREAT_MODEL.md T5.3).
        let a = [0x11u8; SK_LEN];
        let b = [0x22u8; HASH_LEN];
        let n_ab = nullifier::<Sha256Hasher>(&a, &b);

        // Manually swap order — should give a different nullifier.
        let mut swapped = [0u8; SK_LEN + HASH_LEN];
        swapped[..HASH_LEN].copy_from_slice(&b);
        swapped[HASH_LEN..].copy_from_slice(&a);
        let n_swapped = Sha256Hasher::hash(&swapped);

        assert_ne!(n_ab, n_swapped);
    }
}
