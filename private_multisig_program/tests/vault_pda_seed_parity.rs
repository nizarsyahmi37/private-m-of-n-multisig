//! Drift detector: the verifier's manual vault-PDA-seed reconstruction
//! MUST stay byte-identical to SPEL's own `compute_pda` derivation, or
//! every `execute` call will fail at the runtime's
//! `compute_public_authorized_pdas` check with `InconsistentAccountAuthorization`.
//!
//! `methods/guest/src/bin/private_multisig.rs::execute` constructs the
//! vault's `PdaSeed` as:
//!
//! ```text
//! sha256( seed_from_str("pmsig_vault__") || create_key )
//! ```
//!
//! and passes it in `ChainedCall.pda_seeds`. The runtime later derives the
//! authorized AccountId via `for_public_pda(self_program_id, pda_seed)`
//! and compares it against the vault's `account_id` in the chained call's
//! `pre_states`. Both sides must agree on the seed bytes.
//!
//! These tests assert that agreement directly against
//! `spel_framework::pda::compute_pda` — the same primitive the SPEL macro
//! generates a check against on the verifier side. If SPEL changes its
//! seed-combiner (e.g. adds a domain prefix, switches to a different
//! hash), the parity test fails immediately rather than at deploy time.

use crypto::{Hasher, Sha256Hasher};
use nssa_core::account::AccountId;
use nssa_core::program::{PdaSeed, ProgramId};
use spel_framework::pda::{compute_pda, seed_from_str, ToSeed};

/// Reconstruct the vault PDA seed the verifier emits.
///
/// Mirrors `methods/guest/src/bin/private_multisig.rs:447-451` byte-for-byte.
fn manual_vault_pda_seed(create_key: [u8; 32]) -> PdaSeed {
    let vault_literal_seed = seed_from_str("pmsig_vault__");
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&vault_literal_seed);
    combined[32..].copy_from_slice(&create_key);
    PdaSeed::new(Sha256Hasher::hash(&combined))
}

/// Derive the vault's expected `AccountId` the way the SPEL macro
/// (`#[account(pda = [literal("pmsig_vault__"), arg("create_key")])]`) does
/// internally: `compute_pda(self_program_id, [&literal_seed, &create_key])`.
fn spel_vault_account_id(self_program_id: &ProgramId, create_key: &[u8; 32]) -> AccountId {
    let lit = seed_from_str("pmsig_vault__");
    let arg = create_key.to_seed();
    compute_pda(self_program_id, &[&lit, &arg])
}

/// Apply `for_public_pda(self_program_id, manual_pda_seed)` and confirm it
/// equals `compute_pda(...)`. This is the load-bearing equality the
/// runtime checks: when the chained call's `pda_seeds` contain
/// `manual_pda_seed` and the vault's `account_id` was derived by the SPEL
/// macro check, both sides must produce the same `AccountId`.
#[test]
fn manual_vault_seed_matches_spel_compute_pda() {
    let create_key = [0xAB_u8; 32];
    let self_program_id: ProgramId = [0x1234_5678u32; 8];

    let manual_seed = manual_vault_pda_seed(create_key);
    let from_manual = AccountId::for_public_pda(&self_program_id, &manual_seed);
    let from_spel = spel_vault_account_id(&self_program_id, &create_key);

    assert_eq!(
        from_manual, from_spel,
        "vault PDA seed reconstruction drifted from SPEL's compute_pda. \
         The verifier's `execute` handler will emit a ChainedCall.pda_seeds \
         value the runtime rejects with InconsistentAccountAuthorization. \
         See methods/guest/src/bin/private_multisig.rs:447-451 and update \
         BOTH the manual reconstruction AND this test together.",
    );
}

/// The previous test covers one (create_key, program_id) pair. A
/// commutativity / determinism sweep over multiple values catches the
/// rare case where two different inputs happen to collide on one pair but
/// not on another (e.g. a bug that XORs instead of concats would pass
/// the all-0xAB test by accident if the program_id is also all-0x12 in
/// the right pattern).
#[test]
fn manual_vault_seed_matches_spel_compute_pda_over_random_inputs() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    for _ in 0..64 {
        let create_key: [u8; 32] = rng.gen();
        let mut program_words = [0u32; 8];
        for w in &mut program_words {
            *w = rng.gen();
        }
        let self_program_id: ProgramId = program_words;

        let manual_seed = manual_vault_pda_seed(create_key);
        let from_manual = AccountId::for_public_pda(&self_program_id, &manual_seed);
        let from_spel = spel_vault_account_id(&self_program_id, &create_key);
        assert_eq!(
            from_manual, from_spel,
            "drift on randomized input (create_key={:?}, program_id={:?})",
            create_key, self_program_id,
        );
    }
}

/// Pin the literal seed `b"pmsig_vault__"` after `seed_from_str` zero-pads
/// it to 32 bytes. If anyone shortens or extends the literal in either
/// the verifier OR the manual reconstruction without updating the
/// derivation tests, this fails loudly.
#[test]
fn vault_literal_seed_is_pmsig_vault_zero_padded() {
    let seed = seed_from_str("pmsig_vault__");
    let mut expected = [0u8; 32];
    expected[..13].copy_from_slice(b"pmsig_vault__");
    assert_eq!(seed, expected, "vault literal seed shape drifted");
}
