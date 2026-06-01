//! Parity tests for the remaining three PDA helpers (state, proposal,
//! nullifier) against SPEL's `compute_pda` primitive.
//!
//! `vault_pda_seed_parity.rs` already pins the vault path. This file
//! covers the other three so a SPEL change to `seed_from_str` or
//! `ToSeed` is caught for ANY namespace, not just the vault.
//!
//! Round 6 PDA-parity-verifier gap (blue team report): without these
//! tests, state/proposal/nullifier addresses are validated only against
//! an independently-re-derived SHA-256 — algorithmic equivalence with
//! SPEL is asserted but the live SPEL function is never called for
//! these paths.

use nssa_core::account::AccountId;
use nssa_core::program::ProgramId;
use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_pda,
};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use spel_framework::pda::{compute_pda, seed_from_str, ToSeed};

fn spel_state_account_id(self_program_id: &ProgramId, create_key: &[u8; 32]) -> AccountId {
    let lit = seed_from_str("pmsig_state__");
    compute_pda(self_program_id, &[&lit, &create_key.to_seed()])
}

fn spel_proposal_account_id(
    self_program_id: &ProgramId,
    create_key: &[u8; 32],
    index: u64,
) -> AccountId {
    let lit = seed_from_str("pmsig_prop___");
    compute_pda(
        self_program_id,
        &[&lit, &create_key.to_seed(), &index.to_seed()],
    )
}

fn spel_nullifier_entry_account_id(
    self_program_id: &ProgramId,
    proposal_pda: &[u8; 32],
    nullifier: &[u8; 32],
) -> AccountId {
    let lit = seed_from_str("pmsig_nulli__");
    compute_pda(
        self_program_id,
        &[&lit, &proposal_pda.to_seed(), &nullifier.to_seed()],
    )
}

/// On a little-endian host (the only target SPEL/RISC0 supports), a
/// `[u32; 8]` ProgramId byte-cast equals the 32-byte form core uses.
/// All three core helpers accept `&[u8; 32]`; SPEL's `compute_pda` takes
/// `&[u32; 8]`. We pick `[0x1234_5678; 8]` so the non-uniform LE
/// representation `[0x78, 0x56, 0x34, 0x12, ...]` catches any
/// endianness drift.
const TEST_PROGRAM_BYTES: [u8; 32] = [
    0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
    0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
];
const TEST_PROGRAM_WORDS: ProgramId = [0x1234_5678; 8];

#[test]
fn state_pda_matches_spel_compute_pda() {
    let create_key = [0xAB_u8; 32];
    let from_core = derive_multisig_state_pda(&TEST_PROGRAM_BYTES, &create_key);
    let from_spel = spel_state_account_id(&TEST_PROGRAM_WORDS, &create_key);
    assert_eq!(
        from_core,
        *from_spel.value(),
        "derive_multisig_state_pda drifted from SPEL's compute_pda. \
         A handler with `#[account(pda = [literal(\"pmsig_state__\"), arg(\"create_key\")])]` \
         will reject every SDK-derived account_id with PdaMismatch.",
    );
}

#[test]
fn state_pda_matches_spel_over_random_inputs() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    for _ in 0..64 {
        let create_key: [u8; 32] = rng.random();
        let mut program_words = [0u32; 8];
        for w in &mut program_words {
            *w = rng.random();
        }
        let mut program_bytes = [0u8; 32];
        for (i, w) in program_words.iter().enumerate() {
            program_bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }

        let from_core = derive_multisig_state_pda(&program_bytes, &create_key);
        let from_spel = spel_state_account_id(&program_words, &create_key);
        assert_eq!(
            from_core,
            *from_spel.value(),
            "drift on randomized state PDA (create_key={:?}, program={:?})",
            create_key,
            program_words,
        );
    }
}

#[test]
fn proposal_pda_matches_spel_compute_pda() {
    let create_key = [0xCD_u8; 32];
    for &index in &[0u64, 1, 7, u64::MAX] {
        let from_core = derive_proposal_pda(&TEST_PROGRAM_BYTES, &create_key, index);
        let from_spel = spel_proposal_account_id(&TEST_PROGRAM_WORDS, &create_key, index);
        assert_eq!(
            from_core,
            *from_spel.value(),
            "derive_proposal_pda drifted from SPEL's compute_pda at index={}",
            index,
        );
    }
}

#[test]
fn proposal_pda_matches_spel_over_random_inputs() {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    for _ in 0..64 {
        let create_key: [u8; 32] = rng.random();
        let index: u64 = rng.random();
        let mut program_words = [0u32; 8];
        for w in &mut program_words {
            *w = rng.random();
        }
        let mut program_bytes = [0u8; 32];
        for (i, w) in program_words.iter().enumerate() {
            program_bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }

        let from_core = derive_proposal_pda(&program_bytes, &create_key, index);
        let from_spel = spel_proposal_account_id(&program_words, &create_key, index);
        assert_eq!(
            from_core,
            *from_spel.value(),
            "drift on randomized proposal PDA",
        );
    }
}

#[test]
fn nullifier_entry_pda_matches_spel_compute_pda() {
    let proposal_pda = [0xEF_u8; 32];
    let nullifier = [0x12_u8; 32];
    let from_core = derive_nullifier_entry_pda(&TEST_PROGRAM_BYTES, &proposal_pda, &nullifier);
    let from_spel = spel_nullifier_entry_account_id(&TEST_PROGRAM_WORDS, &proposal_pda, &nullifier);
    assert_eq!(
        from_core,
        *from_spel.value(),
        "derive_nullifier_entry_pda drifted from SPEL's compute_pda",
    );
}

#[test]
fn nullifier_entry_pda_matches_spel_over_random_inputs() {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE);
    for _ in 0..64 {
        let proposal_pda: [u8; 32] = rng.random();
        let nullifier: [u8; 32] = rng.random();
        let mut program_words = [0u32; 8];
        for w in &mut program_words {
            *w = rng.random();
        }
        let mut program_bytes = [0u8; 32];
        for (i, w) in program_words.iter().enumerate() {
            program_bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }

        let from_core = derive_nullifier_entry_pda(&program_bytes, &proposal_pda, &nullifier);
        let from_spel = spel_nullifier_entry_account_id(&program_words, &proposal_pda, &nullifier);
        assert_eq!(
            from_core,
            *from_spel.value(),
            "drift on randomized nullifier_entry PDA",
        );
    }
}

#[test]
fn literal_seed_shapes_pinned() {
    // Confirm SPEL's `seed_from_str` produces the byte sequence each
    // core helper assumes when it pads `SEED_*` to 32 bytes. If SPEL
    // ever changes padding semantics, this fails immediately.
    let cases = [
        ("pmsig_state__", b"pmsig_state__"),
        ("pmsig_prop___", b"pmsig_prop___"),
        ("pmsig_nulli__", b"pmsig_nulli__"),
    ];
    for (s, prefix) in cases {
        let seed = seed_from_str(s);
        let mut expected = [0u8; 32];
        expected[..13].copy_from_slice(prefix);
        assert_eq!(seed, expected, "seed shape drift for '{}'", s);
    }
}
