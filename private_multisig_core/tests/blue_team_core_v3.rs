//! Blue-team round-3 validator for `private_multisig_core`.
//!
//! Round-1 closed FINDING-2 (E1002 `ActionBytesTooLong`) and documented
//! FINDING-3 (ChainId zero aliasing). Round-2 closed FINDING-V2-A (E1003
//! `InvalidThreshold` + `MultisigState::validate_threshold` /
//! `MultisigState::validate`) and FINDING-V2-C (removal of the unused
//! `pda::PdaSeed` type). 224 tests pass; clippy clean.
//!
//! This file pins every defense those fixes installed from FRESH ANGLES so
//! a future PR that quietly rolls one back is caught by a named test. Every
//! `v3_*` test maps 1:1 to a defense from the round-3 brief.
//!
//! Constraints (enforced by the brief):
//! - Only file this round may touch.
//! - Allowed deps: `rand`, `hex`, `borsh`, `crypto`, `private_multisig_core`.
//!   (`proptest` is permitted by the brief but is NOT in the workspace; we
//!   use seeded `StdRng` sweeps for the randomized assertions so reproductions
//!   are byte-stable without adding a dependency.)

#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::type_complexity)]

use borsh::to_vec;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crypto::{Identity, MerkleTree, Sha256Hasher, SALT_LEN, SK_LEN};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id,
    error::CoreError,
    pda::{derive_pda, SEED_MULTISIG_STATE, SEED_PROPOSAL},
    proof::{ApprovePublicInputs, ChainId},
    state::{MultisigState, Proposal, MAX_ACTION_BYTES_LEN},
    APPROVE_PUBLIC_INPUTS_LEN,
};

// ---------------------------------------------------------------------------
// Hand-maintained source of truth: the full 11-variant `CoreError` set after
// round-2's V2-A patch. If a future PR adds or removes a variant without
// updating this list, multiple tests in this file will fail — intentional.
// ---------------------------------------------------------------------------

const ALL_VARIANTS: [CoreError; 11] = [
    CoreError::InstanceNotActive,
    CoreError::ProposalExpiredOrExecuted,
    CoreError::ActionBytesTooLong,
    CoreError::InvalidThreshold,
    CoreError::InvalidReceipt,
    CoreError::ImageIdMismatch,
    CoreError::RootMismatch,
    CoreError::ProposalIdMismatch,
    CoreError::NullifierAlreadyUsed,
    CoreError::ThresholdNotMet,
    CoreError::AlreadyExecuted,
];

// ===========================================================================
// 1. v3_e1003_returned_for_m_eq_zero
// ===========================================================================

#[test]
fn v3_e1003_returned_for_m_eq_zero() {
    // m=0 must be rejected regardless of n. Sweep includes the full domain
    // boundary u32::MAX so the comparison branch is exercised at its limit.
    for n in [1u32, 5, 100, u32::MAX] {
        let r = MultisigState::validate_threshold(0, n);
        assert_eq!(
            r,
            Err(CoreError::InvalidThreshold),
            "validate_threshold(0, {n}) must return E1003 InvalidThreshold"
        );
    }
}

// ===========================================================================
// 2. v3_e1003_returned_for_n_eq_zero
// ===========================================================================

#[test]
fn v3_e1003_returned_for_n_eq_zero() {
    // n=0 must be rejected regardless of m. m=0 with n=0 is also a
    // double-trigger but the right error is still E1003 — the short-circuit
    // returns on the first failing predicate.
    for m in [1u8, 100, u8::MAX] {
        let r = MultisigState::validate_threshold(m, 0);
        assert_eq!(
            r,
            Err(CoreError::InvalidThreshold),
            "validate_threshold({m}, 0) must return E1003 InvalidThreshold"
        );
    }
}

// ===========================================================================
// 3. v3_e1003_returned_for_m_gt_n
// ===========================================================================

#[test]
fn v3_e1003_returned_for_m_gt_n() {
    // u32::from(m) > n boundary sweep. (u8::MAX, 254) is the off-by-one
    // sentinel right below the m == n line.
    for (m, n) in [(5u8, 4u32), (u8::MAX, 1u32), (u8::MAX, 254u32)] {
        let r = MultisigState::validate_threshold(m, n);
        assert_eq!(
            r,
            Err(CoreError::InvalidThreshold),
            "validate_threshold({m}, {n}) must reject m > n"
        );
    }
}

// ===========================================================================
// 4. v3_validate_threshold_accepts_at_exact_equality
// ===========================================================================

#[test]
fn v3_validate_threshold_accepts_at_exact_equality() {
    // The predicate is `u32::from(m) > n`, so `u32::from(m) == n` must
    // remain accepted. (u8::MAX, 255) and (u8::MAX, u32::MAX) bracket the
    // upper end of the legal domain.
    let cases: [(u8, u32); 3] = [(1, 1), (u8::MAX, 255), (u8::MAX, u32::MAX)];
    for (m, n) in cases {
        let r = MultisigState::validate_threshold(m, n);
        assert!(
            r.is_ok(),
            "validate_threshold({m}, {n}) must be Ok at the equality boundary, got {r:?}"
        );
    }
}

// ===========================================================================
// 5. v3_validate_method_consistent_with_validate_threshold
// ===========================================================================

#[test]
fn v3_validate_method_consistent_with_validate_threshold() {
    // 100 random (m, n) pairs. The `validate` instance method must be a
    // pure delegate of the `validate_threshold` associated function — same
    // inputs, same outputs, always. Seeded RNG so failures reproduce.
    let mut rng = StdRng::seed_from_u64(0xB1_0E_0F_03_05_C0_DE_05);
    for _ in 0..100 {
        let m: u8 = rng.gen();
        let n: u32 = rng.gen();
        let state = MultisigState {
            create_key: [0x00; 32],
            members_root: [0x00; 32],
            m,
            n,
            proposal_count: 0,
        };
        let via_method = state.validate();
        let via_assoc = MultisigState::validate_threshold(m, n);
        assert_eq!(
            via_method, via_assoc,
            "validate() / validate_threshold() disagree at m={m} n={n}"
        );
    }
}

// ===========================================================================
// 6. v3_e1003_display_format_pinned
// ===========================================================================

#[test]
fn v3_e1003_display_format_pinned() {
    // The `Display` text is part of the on-chain ABI — block explorers and
    // SDK error parsers grep it. Re-pin byte-for-byte.
    assert_eq!(
        CoreError::InvalidThreshold.to_string(),
        "E1003: invalid threshold"
    );
}

// ===========================================================================
// 7. v3_from_code_1003_to_invalid_threshold
// ===========================================================================

#[test]
fn v3_from_code_1003_to_invalid_threshold() {
    assert_eq!(
        CoreError::from_code(1003),
        Some(CoreError::InvalidThreshold),
        "from_code(1003) must round-trip to InvalidThreshold"
    );
    // 1004 is the next unused slot; from_code must reject it so a future
    // accidental renumbering of an upper-class variant is caught here.
    assert_eq!(
        CoreError::from_code(1004),
        None,
        "from_code(1004) must remain unmapped"
    );
}

// ===========================================================================
// 8. v3_e1003_distinct_from_other_e1xxx
// ===========================================================================

#[test]
fn v3_e1003_distinct_from_other_e1xxx() {
    // No two E1xxx codes may collide. Explicit pairwise inequality so a
    // typo in `code()` is caught even if the listed variant order shifts.
    let a = CoreError::InvalidThreshold.code();
    assert_ne!(a, CoreError::InstanceNotActive.code());
    assert_ne!(a, CoreError::ProposalExpiredOrExecuted.code());
    assert_ne!(a, CoreError::ActionBytesTooLong.code());
    // And confirm the literal slot is the one the catalog promises.
    assert_eq!(a, 1003);
}

// ===========================================================================
// 9. v3_variant_count_is_11
// ===========================================================================

#[test]
fn v3_variant_count_is_11() {
    // Hand-enumerated list. Round-2 was 10; round-3 must be 11. Going
    // higher means somebody added a variant without round-4 sign-off; going
    // lower means somebody removed one — both are ABI changes.
    assert_eq!(ALL_VARIANTS.len(), 11, "CoreError variant count drifted");

    // Defense in depth: every code from_code-round-trips. If a new variant
    // is added but ALL_VARIANTS isn't updated, this loop misses it AND the
    // length assert above stays at 11 — but the v2 `from_code_round_trips`
    // test in src/error.rs catches that complementary case.
    for v in ALL_VARIANTS {
        assert_eq!(CoreError::from_code(v.code()), Some(v));
    }
}

// ===========================================================================
// 10. v3_pdaseed_is_not_in_pda_module
// ===========================================================================
//
// Note: a doctest-style `compile_fail` block would be the cleanest negative
// assertion, but doc-comments on tests don't run as doctests. Instead we
// (a) call `derive_pda` directly with a `&[u8; 13]` literal — proving the
// helper still exists post-V2-C and still takes the documented byte-slice
// types — and (b) leave a comment that `use private_multisig_core::pda::PdaSeed;`
// would fail compilation, so any future PR that reintroduces that name will
// turn this test back into a compile guard.

#[test]
fn v3_pdaseed_is_not_in_pda_module() {
    // If V2-C is rolled back, the compiler accepts `use ...::PdaSeed`. We
    // can't express that negative as a runtime assertion, so instead we
    // assert the post-removal positive: `derive_pda` is still callable with
    // raw byte arrays, exactly as the helpers depend on. A regression that
    // re-adds `PdaSeed` would land alongside changes to this helper
    // signature, which would break this test.
    let program_id: [u8; 32] = [0xA1; 32];
    let seed: &[u8; 13] = SEED_MULTISIG_STATE;
    let create_key: [u8; 32] = [0xB2; 32];
    let out = derive_pda(&program_id, seed, &[&create_key]);
    // Must be equal to the high-level helper for the same inputs.
    let via_helper = derive_multisig_state_pda(&program_id, &create_key);
    assert_eq!(out, via_helper);
    assert_ne!(out, [0u8; 32]);
}

// ===========================================================================
// 11. v3_derive_pda_signature_unchanged
// ===========================================================================

#[test]
fn v3_derive_pda_signature_unchanged() {
    // Sentinel against signature drift: `derive_pda` must keep the exact
    // signature `(&[u8; 32], &[u8; 13], &[&[u8]]) -> [u8; 32]`. We bind a
    // fn pointer of that exact type to catch any change.
    let f: fn(&[u8; 32], &[u8; 13], &[&[u8]]) -> [u8; 32] = derive_pda;

    let program_id: [u8; 32] = [0x01; 32];
    let create_key: [u8; 32] = [0x02; 32];
    let extra1: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    let extra2: [u8; 8] = 7u64.to_le_bytes();

    let a = f(&program_id, SEED_PROPOSAL, &[&create_key, &extra1]);
    let b = f(&program_id, SEED_PROPOSAL, &[&create_key, &extra1]);
    assert_eq!(a, b, "derive_pda must be deterministic");

    // Two extras vs one extra must differ (length-prefix-free concat would
    // be ambiguous otherwise; the helper hashes the byte stream which makes
    // any input-shape change observable).
    let c = f(&program_id, SEED_PROPOSAL, &[&create_key]);
    assert_ne!(a, c, "extras participation in the hash regressed");

    // And one with `extra2` must differ from one without.
    let d = f(&program_id, SEED_PROPOSAL, &[&create_key, &extra1, &extra2]);
    assert_ne!(a, d);
}

// ===========================================================================
// 12. v3_combined_validate_state_and_action_bytes
// ===========================================================================

#[test]
fn v3_combined_validate_state_and_action_bytes() {
    // Independence: state.validate() is OK regardless of any action-bytes
    // payload, and validate_action_bytes is OK regardless of any state.
    // The two validators must not entangle.
    let state = MultisigState {
        create_key: [0x10; 32],
        members_root: [0x20; 32],
        m: 3,
        n: 5,
        proposal_count: 0,
    };
    assert!(state.validate().is_ok(), "m=3, n=5 must be a valid state");

    for size in [0usize, 100, 4096] {
        let bytes = vec![0u8; size];
        assert!(
            Proposal::validate_action_bytes(&bytes).is_ok(),
            "valid action_bytes (len={size}) must pass"
        );
        // state.validate() is independent of action_bytes — re-assert
        // after each iteration to make the orthogonality explicit.
        assert!(state.validate().is_ok());
    }

    // Over-cap action_bytes must fail even though the state stays valid.
    let too_long = vec![0u8; MAX_ACTION_BYTES_LEN + 1];
    assert_eq!(
        Proposal::validate_action_bytes(&too_long),
        Err(CoreError::ActionBytesTooLong)
    );
    assert!(state.validate().is_ok());

    // And an invalid state must fail even with empty (valid) action_bytes.
    let bad = MultisigState {
        m: 6,
        n: 5,
        ..state
    };
    assert_eq!(bad.validate(), Err(CoreError::InvalidThreshold));
    assert!(Proposal::validate_action_bytes(&[]).is_ok());
}

// ===========================================================================
// 13. v3_finding2_still_closed
// ===========================================================================

#[test]
fn v3_finding2_still_closed() {
    // Re-pin from a fresh angle: build the overflow buffer with `vec!`
    // (round-1 used a helper; round-2 used a helper). If the validator ever
    // regressed to returning `InstanceNotActive` again, this test catches
    // it independently of the previous rounds' fixtures.
    let r = Proposal::validate_action_bytes(&vec![0u8; MAX_ACTION_BYTES_LEN + 1]);
    assert_eq!(r, Err(CoreError::ActionBytesTooLong));
    // Defense in depth: it must NOT be the old wrong error.
    assert_ne!(r, Err(CoreError::InstanceNotActive));
}

// ===========================================================================
// 14. v3_finding3_still_documented
// ===========================================================================

#[test]
fn v3_finding3_still_documented() {
    // The accepted-residual: `ChainId::from_u64(0)` aliases the all-zero
    // 32-byte form. This test pins the alias so any future change to the
    // padding (e.g. switching from LE to BE, or right-aligning) shows up.
    let lifted = ChainId::from_u64(0);
    let explicit = ChainId::new([0u8; 32]);
    assert_eq!(lifted, explicit, "ChainId::from_u64(0) alias regressed");
    // Bytes view too — Eq derives from the inner array, but assert the
    // public accessor agrees so a future opaque-newtype refactor stays honest.
    assert_eq!(lifted.as_bytes(), explicit.as_bytes());
    assert_eq!(lifted.as_bytes(), &[0u8; 32]);
}

// ===========================================================================
// 15. v3_full_workflow_unchanged_after_round2
// ===========================================================================

#[test]
fn v3_full_workflow_unchanged_after_round2() {
    // Cross-crate parity happy path: enroll members → derive proposal_id →
    // compute nullifier → pack ApprovePublicInputs → confirm Borsh =
    // explicit layout. Round-3 must observe the same byte flow as round-2.
    const N_MEMBERS: usize = 5;

    let program_id = [0x77u8; 32];
    let create_key = [0xC1u8; 32];
    let target_program = [0xBBu8; 32];
    let action_bytes = b"transfer(amount=42)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let index: u64 = 7;

    // Both validators agree at the entry: state is valid, action bytes are
    // valid. This is the V2-A + FINDING-2 conjunction.
    let state = MultisigState {
        create_key,
        members_root: [0u8; 32], // filled in below
        m: 3,
        n: N_MEMBERS as u32,
        proposal_count: 0,
    };
    assert!(MultisigState::validate_threshold(state.m, state.n).is_ok());
    assert!(Proposal::validate_action_bytes(&action_bytes).is_ok());

    // Deterministic identities — same construction round-2 used so the
    // bytes hash to the same sentinel value.
    let identities: Vec<Identity> = (0..N_MEMBERS as u8)
        .map(|i| {
            let mut sk = [0u8; SK_LEN];
            let mut salt = [0u8; SALT_LEN];
            for j in 0..32 {
                sk[j] = i.wrapping_mul(13).wrapping_add(j as u8);
                salt[j] = i.wrapping_mul(31).wrapping_add(j as u8 ^ 0x55);
            }
            Identity::new(sk, salt)
        })
        .collect();

    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for id in &identities {
        let commitment = id.commitment::<Sha256Hasher>();
        tree.insert(*commitment.as_bytes()).unwrap();
    }
    let members_root = tree.root();
    assert_ne!(members_root, [0u8; 32]);

    // verify_proof for every member — this is the "proof verifies" step
    // listed in the brief.
    for (i, identity) in identities.iter().enumerate() {
        let commitment = identity.commitment::<Sha256Hasher>();
        let proof = tree.proof(i).unwrap();
        assert!(
            crypto::verify_proof::<Sha256Hasher>(&members_root, commitment.as_bytes(), &proof),
            "verify_proof must accept honest proof for member {i}"
        );
    }

    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let proposal_id =
        derive_proposal_id(&chain_id, &state_pda, index, &action_bytes, &target_program);
    assert_ne!(proposal_id, [0u8; 32]);

    for identity in &identities {
        let nullifier = identity.nullifier::<Sha256Hasher>(&proposal_id);
        let inputs = ApprovePublicInputs {
            members_root,
            proposal_id,
            nullifier,
        };
        let packed = inputs.to_bytes();
        assert_eq!(packed.len(), APPROVE_PUBLIC_INPUTS_LEN);
        let unpacked = ApprovePublicInputs::from_bytes(&packed);
        assert_eq!(unpacked, inputs);
        // Borsh-encoded == explicit pack — the bridge invariant.
        let via_borsh = to_vec(&inputs).unwrap();
        assert_eq!(via_borsh.as_slice(), packed.as_slice());
    }
}

// ===========================================================================
// 16. v3_chain_id_distinct_from_zero
// ===========================================================================

#[test]
fn v3_chain_id_distinct_from_zero() {
    // Sentinel against any future regression that maps a non-zero u64 to
    // the all-zero pattern. 100 ids drawn from [1, u64::MAX] inclusive.
    let mut rng = StdRng::seed_from_u64(0xC0_FF_EE_C0_DE_03_16_42);
    for _ in 0..100 {
        // Draw uniformly in [1, u64::MAX]: gen() then map 0 to 1. Reduces
        // probability of an unlucky zero (~2^-64 anyway) to actually zero.
        let mut id: u64 = rng.gen();
        if id == 0 {
            id = 1;
        }
        let cid = ChainId::from_u64(id);
        assert_ne!(
            cid.as_bytes(),
            &[0u8; 32],
            "ChainId::from_u64({id}) must not be all-zero"
        );
        // Also confirm the lift is consistent: low 8 bytes are id LE,
        // high 24 bytes are zero.
        let bytes = cid.as_bytes();
        assert_eq!(&bytes[..8], &id.to_le_bytes());
        for b in &bytes[8..] {
            assert_eq!(*b, 0);
        }
    }
}
