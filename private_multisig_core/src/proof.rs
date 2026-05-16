//! Proof-side types: `ApprovePublicInputs` and `proposal_id` derivation.
//!
//! The Risc0 approve circuit commits exactly three field values to its
//! receipt journal — `members_root`, `proposal_id`, `nullifier` — which the
//! verifier program reads back as fixed-layout bytes. Those three values
//! are the only public outputs of an approval proof; everything else
//! (`sk`, `salt`, Merkle path, indices) stays private inside the guest.
//!
//! The on-chain `proposal_id` is derived from public information only —
//! the multisig state PDA, the index, the action bytes, the target
//! program, and `chain_id`. The client, the circuit, and the verifier ALL
//! compute it the same way. Any byte-level drift here means proofs no
//! longer cross-verify.

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Hasher, Sha256Hasher};

use crate::pda::AccountId;

/// Canonical wire size of the public-inputs bundle:
/// `members_root (32) || proposal_id (32) || nullifier (32) = 96`.
pub const APPROVE_PUBLIC_INPUTS_LEN: usize = 96;

/// Public inputs committed by the Risc0 approve circuit to its journal.
///
/// The on-chain wire layout is the fixed concatenation:
///
/// ```text
/// [members_root: 32 bytes][proposal_id: 32 bytes][nullifier: 32 bytes]
/// ```
///
/// No length prefix, no version byte, no padding. Use [`Self::to_bytes`] /
/// [`Self::from_bytes`] to cross the FFI boundary. Borsh derives are
/// provided for consumers (the SDK packing instructions, the verifier
/// reading the journal) but a parity test asserts the Borsh encoding is
/// byte-identical to the explicit layout — if a future Borsh release
/// changes that, the parity test catches it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct ApprovePublicInputs {
    pub members_root: [u8; 32],
    pub proposal_id: [u8; 32],
    pub nullifier: [u8; 32],
}

impl ApprovePublicInputs {
    /// Pack into the canonical 96-byte layout.
    pub fn to_bytes(&self) -> [u8; APPROVE_PUBLIC_INPUTS_LEN] {
        let mut out = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        out[..32].copy_from_slice(&self.members_root);
        out[32..64].copy_from_slice(&self.proposal_id);
        out[64..96].copy_from_slice(&self.nullifier);
        out
    }

    /// Unpack from the canonical 96-byte layout. Cannot fail because the
    /// length is a const generic — a misshapen input simply doesn't type
    /// check at the call site.
    pub fn from_bytes(bytes: &[u8; APPROVE_PUBLIC_INPUTS_LEN]) -> Self {
        let mut members_root = [0u8; 32];
        let mut proposal_id = [0u8; 32];
        let mut nullifier = [0u8; 32];
        members_root.copy_from_slice(&bytes[..32]);
        proposal_id.copy_from_slice(&bytes[32..64]);
        nullifier.copy_from_slice(&bytes[64..96]);
        Self {
            members_root,
            proposal_id,
            nullifier,
        }
    }
}

/// Chain identifier that goes into the `proposal_id` preimage so an
/// approval generated on devnet cannot replay on testnet/mainnet. 32 bytes
/// for canonicity even if the underlying LEZ chain-id is shorter (it gets
/// padded by the constructor).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ChainId(pub [u8; 32]);

impl ChainId {
    /// Wrap a raw 32-byte chain identifier without lifting from a smaller
    /// numeric type. Use this when the chain id source already has a
    /// canonical 32-byte form (e.g. a SHA-256 of a domain string).
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lift an integer chain id (the most common LEZ encoding) into the
    /// canonical 32-byte form. Little-endian, right-padded with zeros.
    ///
    /// # Warning — zero aliasing
    ///
    /// `ChainId::from_u64(0) == ChainId::new([0; 32])`, so callers that treat
    /// the all-zero 32-byte value as an "uninitialized" sentinel will accept
    /// a real chain whose id is literally `0` as such. The LEZ chain-id
    /// allocations in scope for this prize do not use `0`, but if a
    /// downstream consumer needs an injective sentinel they should reserve
    /// a non-zero value (e.g. `ChainId::new([0xFF; 32])`) for "uninitialized"
    /// rather than relying on the all-zero pattern. Documented as
    /// THREAT_MODEL FINDING-3 (informational, accepted residual).
    pub fn from_u64(id: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&id.to_le_bytes());
        Self(bytes)
    }

    /// Borrow the underlying 32-byte chain-id payload for inclusion in the
    /// `proposal_id` preimage. The returned reference always has fixed
    /// length 32; callers do not need to validate.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonical `proposal_id` derivation. EVERY consumer — client SDK, Risc0
/// guest, on-chain verifier — calls THIS function (or reimplements its
/// byte-exact equivalent). The formula is from PLAN.md step 2:
///
/// ```text
/// proposal_id = SHA-256( chain_id
///                     ‖ multisig_state_pda
///                     ‖ index.to_le_bytes()
///                     ‖ SHA-256(action_bytes)
///                     ‖ SHA-256(target_program) )
/// ```
///
/// Inputs in this order, little-endian for the integer. `chain_id` blocks
/// cross-chain replay; `H(action_bytes)` and `H(target_program)` bind the
/// approval to *what* is being approved so mutating either after `propose`
/// invalidates existing approvals (THREAT_MODEL T2.4, T2.5).
pub fn derive_proposal_id(
    chain_id: &ChainId,
    multisig_state_pda: &AccountId,
    index: u64,
    action_bytes: &[u8],
    target_program: &AccountId,
) -> [u8; 32] {
    let action_hash = Sha256Hasher::hash(action_bytes);
    let target_hash = Sha256Hasher::hash(target_program);
    let index_bytes = index.to_le_bytes();

    // Preimage size is fixed: 32 + 32 + 8 + 32 + 32 = 136 bytes. Stack-only.
    let mut buf = [0u8; 32 + 32 + 8 + 32 + 32];
    buf[0..32].copy_from_slice(chain_id.as_bytes());
    buf[32..64].copy_from_slice(multisig_state_pda);
    buf[64..72].copy_from_slice(&index_bytes);
    buf[72..104].copy_from_slice(&action_hash);
    buf[104..136].copy_from_slice(&target_hash);

    Sha256Hasher::hash(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::to_vec;

    fn sample_inputs() -> ApprovePublicInputs {
        ApprovePublicInputs {
            members_root: [0x11; 32],
            proposal_id: [0x22; 32],
            nullifier: [0x33; 32],
        }
    }

    #[test]
    fn canonical_length_matches_constant() {
        let bundle = sample_inputs().to_bytes();
        assert_eq!(bundle.len(), APPROVE_PUBLIC_INPUTS_LEN);
        assert_eq!(APPROVE_PUBLIC_INPUTS_LEN, 96);
    }

    #[test]
    fn to_bytes_layout_is_root_then_pid_then_nullifier() {
        let bundle = sample_inputs().to_bytes();
        assert_eq!(&bundle[..32], &[0x11; 32]);
        assert_eq!(&bundle[32..64], &[0x22; 32]);
        assert_eq!(&bundle[64..96], &[0x33; 32]);
    }

    #[test]
    fn to_bytes_from_bytes_round_trips() {
        let original = sample_inputs();
        let bytes = original.to_bytes();
        let recovered = ApprovePublicInputs::from_bytes(&bytes);
        assert_eq!(original, recovered);
    }

    #[test]
    fn borsh_encoding_matches_explicit_layout() {
        // Parity invariant — protects against Borsh ever adding a length
        // prefix or version tag to `[u8; 32]`-only structs.
        let bundle = sample_inputs();
        let via_explicit = bundle.to_bytes();
        let via_borsh = to_vec(&bundle).unwrap();
        assert_eq!(via_borsh.len(), APPROVE_PUBLIC_INPUTS_LEN);
        assert_eq!(via_borsh.as_slice(), via_explicit.as_slice());
    }

    const TEST_STATE_PDA: AccountId = [0xAA; 32];
    const TEST_TARGET: AccountId = [0xBB; 32];

    #[test]
    fn proposal_id_is_deterministic() {
        let cid = ChainId::from_u64(1);
        let a = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"action", &TEST_TARGET);
        let b = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"action", &TEST_TARGET);
        assert_eq!(a, b);
    }

    #[test]
    fn proposal_id_changes_with_chain_id() {
        let a = derive_proposal_id(&ChainId::from_u64(1), &TEST_STATE_PDA, 0, b"x", &TEST_TARGET);
        let b = derive_proposal_id(&ChainId::from_u64(2), &TEST_STATE_PDA, 0, b"x", &TEST_TARGET);
        assert_ne!(a, b);
    }

    #[test]
    fn proposal_id_changes_with_state_pda() {
        let cid = ChainId::from_u64(1);
        let a = derive_proposal_id(&cid, &[0x01; 32], 0, b"x", &TEST_TARGET);
        let b = derive_proposal_id(&cid, &[0x02; 32], 0, b"x", &TEST_TARGET);
        assert_ne!(a, b);
    }

    #[test]
    fn proposal_id_changes_with_index() {
        let cid = ChainId::from_u64(1);
        let a = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"x", &TEST_TARGET);
        let b = derive_proposal_id(&cid, &TEST_STATE_PDA, 1, b"x", &TEST_TARGET);
        assert_ne!(a, b);
    }

    #[test]
    fn proposal_id_changes_with_action_bytes() {
        let cid = ChainId::from_u64(1);
        let a = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"x", &TEST_TARGET);
        let b = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"y", &TEST_TARGET);
        assert_ne!(a, b);
    }

    #[test]
    fn proposal_id_changes_with_target_program() {
        let cid = ChainId::from_u64(1);
        let a = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"x", &[0x01; 32]);
        let b = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"x", &[0x02; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn proposal_id_handles_empty_action_bytes() {
        let cid = ChainId::from_u64(1);
        // Must not panic; result must be deterministic; result must differ
        // from any non-empty action_bytes.
        let empty = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"", &TEST_TARGET);
        let one = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, b"\x00", &TEST_TARGET);
        assert_ne!(empty, one);
    }

    #[test]
    fn proposal_id_handles_large_action_bytes() {
        let cid = ChainId::from_u64(1);
        // 4 KiB at the MAX_ACTION_BYTES_LEN ceiling. Must not panic.
        let big = vec![0xCDu8; 4096];
        let id = derive_proposal_id(&cid, &TEST_STATE_PDA, 0, &big, &TEST_TARGET);
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn chain_id_from_u64_pads_with_zero() {
        let cid = ChainId::from_u64(0x0102_0304_0506_0708);
        let bytes = cid.as_bytes();
        // Little-endian: least-significant byte first.
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[1], 0x07);
        assert_eq!(bytes[7], 0x01);
        for b in &bytes[8..] {
            assert_eq!(*b, 0u8);
        }
    }

    #[test]
    fn chain_id_construction_is_distinct_per_value() {
        let a = ChainId::from_u64(1);
        let b = ChainId::from_u64(2);
        let c = ChainId::new([0u8; 32]);
        let d = ChainId::new([1u8; 32]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(c, d);
    }
}
