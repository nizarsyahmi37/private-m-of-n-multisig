//! PDA seed constants and derivation helpers.
//!
//! Every LEZ account this protocol creates has its address derived
//! deterministically from `(program_id, seed_constant, varying_inputs)`.
//! Clients and the verifier program both call the same derivation function
//! so an address never has to round-trip through state.
//!
//! # Algorithm
//!
//! Byte-identical to `spel_framework::pda::compute_pda` +
//! `nssa_core::AccountId::for_public_pda` so an SDK-derived `AccountId`
//! exactly matches what the SPEL macro's `#[account(pda = [...])]` check
//! recomputes on chain. Two steps:
//!
//! 1. **Combine**: each input seed is normalized to a 32-byte value (literals
//!    zero-padded to 32 from the right; `[u8; 32]` values are identity;
//!    `u64` is little-endian + zero-padded to 32 from the right). If there
//!    is exactly one seed, `combined = seed_0`. Otherwise
//!    `combined = SHA-256(seed_0_32B ‖ seed_1_32B ‖ …)`.
//! 2. **Apply NSSA public-PDA prefix**: `account_id = SHA-256(NSSA_PUBLIC_PDA_PREFIX(32) ‖ program_id(32) ‖ combined(32))`.
//!
//! The 32-byte prefix `b"/NSSA/v0.2/AccountId/PDA/\0\0\0\0\0\0\0"` domain-
//! separates public PDAs from private PDAs (which use a different prefix)
//! and from arbitrary preimages.
//!
//! # Round-5 fix
//!
//! Earlier versions of this module used `SHA-256(program_id ‖ seed_13B ‖ extras…)`
//! which did NOT match SPEL's derivation. Every SDK-derived address would
//! have failed the verifier's PDA enforcement with `PdaMismatch`. The
//! cross-check unit tests in `private_multisig_program/tests/`
//! (`vault_pda_seed_parity.rs` and the catalog tests) pin the new
//! algorithm against SPEL's own primitives.

use crypto::{Hasher, Sha256Hasher};

use crate::{AccountId, CreateKey, ProgramId};

extern crate alloc;

/// Domain-separation prefix used by `nssa_core::AccountId::for_public_pda`.
/// 32 bytes (the literal text plus 7 trailing NULs to round it to 32).
const NSSA_PUBLIC_PDA_PREFIX: &[u8; 32] =
    b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00";

/// Seed for the per-multisig `MultisigState` account.
pub const SEED_MULTISIG_STATE: &[u8; 13] = b"pmsig_state__";
/// Seed for the per-(multisig, index) `Proposal` account.
pub const SEED_PROPOSAL: &[u8; 13] = b"pmsig_prop___";
/// Seed for the per-multisig `Vault` account that holds funds the
/// threshold-gated `execute` instruction can disburse.
pub const SEED_VAULT: &[u8; 13] = b"pmsig_vault__";
/// Seed for the per-(proposal, nullifier) `NullifierEntry` PDA. Init-fails-if-
/// exists at this address is the on-chain double-vote check.
pub const SEED_NULLIFIER: &[u8; 13] = b"pmsig_nulli__";

/// Right-zero-pad an input shorter than 32 bytes into a 32-byte seed.
/// Mirrors `spel_framework::pda::seed_from_str` (which pads string seeds)
/// and `<u64 as ToSeed>::to_seed` (which pads numeric seeds the same way).
#[inline]
fn pad_seed_32(input: &[u8]) -> [u8; 32] {
    assert!(input.len() <= 32, "seed exceeds 32 bytes");
    let mut out = [0u8; 32];
    out[..input.len()].copy_from_slice(input);
    out
}

/// SPEL-compatible PDA derivation primitive. Takes already-32-byte seeds
/// (use [`pad_seed_32`] to normalize a shorter literal first) and combines
/// them per the algorithm in the module docs.
///
/// # Panics
///
/// Panics if `seeds` is empty (matches `spel_framework::pda::compute_pda`'s
/// behavior — there is no defensible "PDA with no seeds").
pub fn derive_pda(program_id: &ProgramId, seeds: &[&[u8; 32]]) -> AccountId {
    assert!(!seeds.is_empty(), "PDA requires at least one seed");

    // Step 1: combine the seeds. Single seed pass-through; multiple seeds
    // SHA-256 over the concatenation (NOT XOR — see PoC ambiguity note in
    // the previous revision).
    let combined: [u8; 32] = if seeds.len() == 1 {
        *seeds[0]
    } else {
        let mut buf = alloc::vec::Vec::with_capacity(32 * seeds.len());
        for seed in seeds {
            buf.extend_from_slice(*seed);
        }
        Sha256Hasher::hash(&buf)
    };

    // Step 2: apply the NSSA public-PDA prefix domain separator.
    let mut preimage = [0u8; 96];
    preimage[0..32].copy_from_slice(NSSA_PUBLIC_PDA_PREFIX);
    preimage[32..64].copy_from_slice(program_id);
    preimage[64..96].copy_from_slice(&combined);
    Sha256Hasher::hash(&preimage)
}

/// `MultisigState` PDA. Seeds: `[pad(SEED_MULTISIG_STATE), create_key]`.
pub fn derive_multisig_state_pda(program_id: &ProgramId, create_key: &CreateKey) -> AccountId {
    let lit = pad_seed_32(SEED_MULTISIG_STATE);
    derive_pda(program_id, &[&lit, create_key])
}

/// `Proposal` PDA for a given multisig instance and index. Seeds:
/// `[pad(SEED_PROPOSAL), create_key, pad(index.to_le_bytes())]`.
pub fn derive_proposal_pda(
    program_id: &ProgramId,
    create_key: &CreateKey,
    index: u64,
) -> AccountId {
    let lit = pad_seed_32(SEED_PROPOSAL);
    let index_seed = pad_seed_32(&index.to_le_bytes());
    derive_pda(program_id, &[&lit, create_key, &index_seed])
}

/// `Vault` PDA. Seeds: `[pad(SEED_VAULT), create_key]`.
pub fn derive_vault_pda(program_id: &ProgramId, create_key: &CreateKey) -> AccountId {
    let lit = pad_seed_32(SEED_VAULT);
    derive_pda(program_id, &[&lit, create_key])
}

/// `NullifierEntry` PDA. Seeds: `[pad(SEED_NULLIFIER), proposal_pda, nullifier]`.
/// Init-fails-if-exists at this address is what enforces single-vote-per-
/// (member, proposal): a second approval from the same member targets the
/// same address and the `init` step fails.
pub fn derive_nullifier_entry_pda(
    program_id: &ProgramId,
    proposal_pda: &AccountId,
    nullifier: &[u8; 32],
) -> AccountId {
    let lit = pad_seed_32(SEED_NULLIFIER);
    derive_pda(program_id, &[&lit, proposal_pda, nullifier])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PROGRAM_ID: ProgramId = [0xA1; 32];
    const TEST_CREATE_KEY: CreateKey = [0xB2; 32];

    #[test]
    fn seed_constants_are_13_bytes_and_pmsig_prefixed() {
        for seed in [
            SEED_MULTISIG_STATE,
            SEED_PROPOSAL,
            SEED_VAULT,
            SEED_NULLIFIER,
        ] {
            assert_eq!(seed.len(), 13, "seed must be 13 bytes");
            assert!(
                seed.starts_with(b"pmsig_"),
                "seed must start with pmsig_: {seed:?}"
            );
        }
    }

    #[test]
    fn seed_constants_are_all_distinct() {
        let seeds = [
            *SEED_MULTISIG_STATE,
            *SEED_PROPOSAL,
            *SEED_VAULT,
            *SEED_NULLIFIER,
        ];
        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert_ne!(
                    seeds[i], seeds[j],
                    "seeds[{i}] collides with seeds[{j}]"
                );
            }
        }
    }

    #[test]
    fn nssa_public_pda_prefix_is_pinned() {
        // The prefix bytes are part of the on-chain ABI — if SPEL ever
        // changes its prefix, this test catches it before the next deploy.
        assert_eq!(NSSA_PUBLIC_PDA_PREFIX.len(), 32);
        assert_eq!(&NSSA_PUBLIC_PDA_PREFIX[..25], b"/NSSA/v0.2/AccountId/PDA/");
        assert_eq!(&NSSA_PUBLIC_PDA_PREFIX[25..], &[0u8; 7]);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_multisig_state_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY);
        let b = derive_multisig_state_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY);
        assert_eq!(a, b);
    }

    #[test]
    fn different_create_keys_yield_different_pdas() {
        let a = derive_multisig_state_pda(&TEST_PROGRAM_ID, &[0x01; 32]);
        let b = derive_multisig_state_pda(&TEST_PROGRAM_ID, &[0x02; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn different_program_ids_yield_different_pdas() {
        let a = derive_multisig_state_pda(&[0x01; 32], &TEST_CREATE_KEY);
        let b = derive_multisig_state_pda(&[0x02; 32], &TEST_CREATE_KEY);
        assert_ne!(a, b);
    }

    #[test]
    fn state_proposal_vault_pdas_are_distinct() {
        let s = derive_multisig_state_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY);
        let p = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, 0);
        let v = derive_vault_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY);
        assert_ne!(s, p);
        assert_ne!(s, v);
        assert_ne!(p, v);
    }

    #[test]
    fn proposal_index_is_part_of_address() {
        let p0 = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, 0);
        let p1 = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, 1);
        let p_max = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, u64::MAX);
        assert_ne!(p0, p1);
        assert_ne!(p0, p_max);
        assert_ne!(p1, p_max);
    }

    #[test]
    fn nullifier_entry_pda_binds_to_proposal_and_nullifier() {
        let proposal = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, 0);
        let other_proposal = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, 1);
        let n1 = [0x11; 32];
        let n2 = [0x22; 32];

        let entry_same_proposal = derive_nullifier_entry_pda(&TEST_PROGRAM_ID, &proposal, &n1);
        let entry_diff_nullifier = derive_nullifier_entry_pda(&TEST_PROGRAM_ID, &proposal, &n2);
        let entry_diff_proposal =
            derive_nullifier_entry_pda(&TEST_PROGRAM_ID, &other_proposal, &n1);

        assert_ne!(entry_same_proposal, entry_diff_nullifier);
        assert_ne!(entry_same_proposal, entry_diff_proposal);
        assert_ne!(entry_diff_nullifier, entry_diff_proposal);
    }

    #[test]
    fn derived_pdas_are_not_all_zeros() {
        // Sanity guard: under no input combination should derive_pda hash
        // down to [0;32] (it would, only if SHA-256 had a known preimage
        // for that value). Pin the negative.
        for ix in 0..8u64 {
            let p = derive_proposal_pda(&TEST_PROGRAM_ID, &TEST_CREATE_KEY, ix);
            assert_ne!(p, [0u8; 32]);
        }
    }

    #[test]
    fn single_seed_passes_through_without_combine_hash() {
        // Single-seed PDAs use the seed directly (no inner SHA-256 of the
        // seed list). Verify by constructing a PDA that's morally
        // equivalent to "one seed of all 0xAB" — its inner combined seed
        // must literally be all 0xAB, not SHA-256 of all 0xAB.
        let seed = [0xAB_u8; 32];
        let mut preimage = [0u8; 96];
        preimage[0..32].copy_from_slice(NSSA_PUBLIC_PDA_PREFIX);
        preimage[32..64].copy_from_slice(&TEST_PROGRAM_ID);
        preimage[64..96].copy_from_slice(&seed); // identity, not SHA-256
        let expected = Sha256Hasher::hash(&preimage);

        let got = derive_pda(&TEST_PROGRAM_ID, &[&seed]);
        assert_eq!(got, expected);
    }
}
