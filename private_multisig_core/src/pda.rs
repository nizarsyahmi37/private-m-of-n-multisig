//! PDA seed constants and derivation helpers.
//!
//! Every LEZ account this protocol creates has its address derived
//! deterministically from `(program_id, seed_constant, varying_inputs)`.
//! Clients and the verifier program both call the same derivation function
//! so an address never has to round-trip through state.
//!
//! ## Seed convention
//!
//! Each seed constant is exactly 13 bytes, matching lez-multisig's
//! `pmsig_<role>__` shape so the two programs can be told apart at a glance
//! in chain explorers. (PLAN.md describes them as "14 bytes each" but the
//! literals it quotes — `pmsig_state__` etc. — are 13 bytes; we follow the
//! literal byte values, not the byte-count annotation.)
//!
//! ```text
//! pda = SHA-256( program_id ‖ seed_constant ‖ extra₀ ‖ extra₁ ‖ ... )
//! ```
//!
//! `VERIFY:` lez-multisig's PoC notes mention an "XOR with create_key"
//! pattern alongside a SHA-256-of-concat note. The two are mutually
//! exclusive and PLAN.md flagged the contradiction. This crate implements
//! the SHA-256-of-concat form (more common, easier to audit, no ambiguity
//! around fixed-length XOR). If a future cross-check against the real
//! lez-multisig source shows otherwise, only `derive_pda` needs to change —
//! every public helper is layered on top.

use crypto::Sha256Hasher;

/// 32-byte LEZ program identifier. Mirrors the runtime's program-id type.
pub type ProgramId = [u8; 32];
/// 32-byte LEZ account address — the value returned by every PDA derivation
/// helper in this module.
pub type AccountId = [u8; 32];
/// 32-byte caller-chosen salt that distinguishes a multisig instance from
/// every other `(program_id, create_key)` pair. Stored in `MultisigState`
/// and threaded through every child PDA derivation.
pub type CreateKey = [u8; 32];

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

/// `SHA-256(program_id ‖ seed ‖ extras…)`. Single source of truth for the
/// derivation, layered helpers below specialize it for each account class.
pub fn derive_pda(program_id: &ProgramId, seed: &[u8; 13], extras: &[&[u8]]) -> AccountId {
    // Sum of all input lengths so the buffer is allocated exactly once.
    let mut total = program_id.len() + seed.len();
    for e in extras {
        total += e.len();
    }
    let mut buf = alloc::vec::Vec::with_capacity(total);
    buf.extend_from_slice(program_id);
    buf.extend_from_slice(seed);
    for e in extras {
        buf.extend_from_slice(e);
    }
    <Sha256Hasher as crypto::Hasher>::hash(&buf)
}

/// `MultisigState` lives at `H(program_id ‖ pmsig_state__ ‖ create_key)`.
pub fn derive_multisig_state_pda(program_id: &ProgramId, create_key: &CreateKey) -> AccountId {
    derive_pda(program_id, SEED_MULTISIG_STATE, &[create_key])
}

/// `Proposal` for `index` of a given multisig lives at
/// `H(program_id ‖ pmsig_prop___ ‖ create_key ‖ index.to_le_bytes())`.
pub fn derive_proposal_pda(
    program_id: &ProgramId,
    create_key: &CreateKey,
    index: u64,
) -> AccountId {
    let index_bytes = index.to_le_bytes();
    derive_pda(program_id, SEED_PROPOSAL, &[create_key, &index_bytes])
}

/// `Vault` lives at `H(program_id ‖ pmsig_vault__ ‖ create_key)`.
pub fn derive_vault_pda(program_id: &ProgramId, create_key: &CreateKey) -> AccountId {
    derive_pda(program_id, SEED_VAULT, &[create_key])
}

/// `NullifierEntry` lives at `H(program_id ‖ pmsig_nulli__ ‖ proposal_pda ‖ nullifier)`.
/// Init-fails-if-exists at this address is what enforces single-vote-per-
/// (member, proposal): a second approval from the same member targets the
/// same address and the `init` step fails.
pub fn derive_nullifier_entry_pda(
    program_id: &ProgramId,
    proposal_pda: &AccountId,
    nullifier: &[u8; 32],
) -> AccountId {
    derive_pda(program_id, SEED_NULLIFIER, &[proposal_pda, nullifier])
}

// `derive_pda` uses `alloc::vec::Vec`. The crate is currently linked as
// `std` so the `alloc` crate is automatically reachable, but pulling it in
// explicitly keeps the import path correct when step 3 switches to no_std.
extern crate alloc;

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
}
