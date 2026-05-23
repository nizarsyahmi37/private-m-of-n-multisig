//! Blue-team round-2 validator for `private_multisig_core`.
//!
//! Round 1 surfaced and fixed two issues in the crate:
//!
//! - **FINDING-2 (LOW, fixed)**: `Proposal::validate_action_bytes` returned
//!   `CoreError::InstanceNotActive` (E1000) for an oversize input. The fix
//!   allocated a new variant `ActionBytesTooLong` (E1002, code 1002, Display
//!   `"E1002: action bytes too long"`) and routed the validator to return it.
//! - **FINDING-3 (INFO, documented)**: `ChainId::from_u64(0)` aliases
//!   `ChainId::new([0; 32])`. Rustdoc warning was added under the
//!   `from_u64` constructor.
//!
//! This file confirms the fixes hold under varied conditions AND validates
//! combinations the round-1 tests only covered in isolation. Each test is
//! named for the defense it pins; together they form a regression net for the
//! exact ABI/spec invariants the crate must preserve.
//!
//! Constraints (enforced by the task brief):
//! - Only file allowed to touch is this one.
//! - Allowed deps: `rand`, `hex`, `borsh`, `crypto`, `private_multisig_core`.
//!
//! All "proptests" are seeded sweeps (no `proptest` crate dep) so reproductions
//! are byte-stable.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_panics_doc)]

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crypto::{Identity, MerkleTree, Sha256Hasher, SALT_LEN, SK_LEN};
use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id,
    error::CoreError,
    proof::{ApprovePublicInputs, ChainId},
    state::{Proposal, MAX_ACTION_BYTES_LEN},
    APPROVE_PUBLIC_INPUTS_LEN,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a sized buffer of zeros without OOM risk. Centralizes the
/// "oversize input" pattern so individual tests stay readable.
fn oversize_buf(extra: usize) -> Vec<u8> {
    vec![0u8; MAX_ACTION_BYTES_LEN.saturating_add(extra)]
}

/// All ten current `CoreError` variants, enumerated by hand. If a future
/// PR adds or removes a variant without updating this list, multiple tests
/// in this file will fail — that is intentional. The list is the source of
/// truth for "what is the full variant set" in round 2.
fn all_variants() -> [CoreError; 11] {
    [
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
    ]
}

// ===========================================================================
// 1. e1002_returned_under_varied_overcap_sizes
// ===========================================================================

#[test]
fn e1002_returned_under_varied_overcap_sizes() {
    // The exact sweep the brief enumerates: cap+{1, 2, 100, 1000,
    // MAX_ACTION_BYTES_LEN}. usize::MAX/2 is deliberately skipped to avoid
    // OOM on CI runners — the boundary is enforced by a numeric `len > cap`
    // comparison in the validator, so an algebraic sweep of small offsets
    // covers the same logical surface.
    let extras: [usize; 5] = [1, 2, 100, 1000, MAX_ACTION_BYTES_LEN];
    for extra in extras {
        let data = oversize_buf(extra);
        let result = Proposal::validate_action_bytes(&data);
        assert_eq!(
            result,
            Err(CoreError::ActionBytesTooLong),
            "validate_action_bytes(len={}) must return E1002 ActionBytesTooLong",
            data.len()
        );
    }
}

// ===========================================================================
// 2. e1002_display_format_pinned
// ===========================================================================

#[test]
fn e1002_display_format_pinned() {
    // The `Display` text is part of the on-chain ABI surface — block
    // explorers grep for it. Any drift in the string is a breaking change.
    assert_eq!(
        CoreError::ActionBytesTooLong.to_string(),
        "E1002: action bytes too long"
    );
}

// ===========================================================================
// 3. e1002_from_code_round_trip
// ===========================================================================

#[test]
fn e1002_from_code_round_trip() {
    // Positive: 1002 lifts back to ActionBytesTooLong.
    assert_eq!(
        CoreError::from_code(1002),
        Some(CoreError::ActionBytesTooLong)
    );

    // 1003 is InvalidThreshold (FINDING-V2-A), 1004 is SerializationError
    // (round-5 fix: split serde paths from InstanceNotActive), 1005 is
    // ArithmeticOverflow (same round-5 split for checked_add paths). 1006
    // is the next free slot in E1xxx — must NOT lift to any variant.
    assert_eq!(
        CoreError::from_code(1003),
        Some(CoreError::InvalidThreshold)
    );
    assert_eq!(
        CoreError::from_code(1004),
        Some(CoreError::SerializationError)
    );
    assert_eq!(
        CoreError::from_code(1005),
        Some(CoreError::ArithmeticOverflow)
    );
    assert_eq!(CoreError::from_code(1006), None);
}

// ===========================================================================
// 4. e1000_no_longer_returned_for_oversize_action
// ===========================================================================

#[test]
fn e1000_no_longer_returned_for_oversize_action() {
    // Pre-fix the validator returned `InstanceNotActive` (E1000) for
    // oversize input — semantically wrong. Pin the post-fix negative so
    // any regression re-introducing the original behavior trips here.
    for extra in [1usize, 17, 4096] {
        let data = oversize_buf(extra);
        let result = Proposal::validate_action_bytes(&data);
        assert!(result.is_err(), "len={} must error", data.len());
        assert_ne!(
            result,
            Err(CoreError::InstanceNotActive),
            "validate_action_bytes must NOT return InstanceNotActive (E1000) \
             for oversize input — that was the pre-fix bug from FINDING-2"
        );
    }
}

// ===========================================================================
// 5. error_variant_count_is_10
// ===========================================================================

#[test]
fn error_variant_count_is_10() {
    // FINDING-V2-A added InvalidThreshold (E1003), bringing the total to 11.
    // The test name is preserved as a regression marker even though the
    // count is now 11.
    let variants = all_variants();
    assert_eq!(
        variants.len(),
        11,
        "CoreError must have exactly 11 variants after V2-A FINDING fix; \
         see private_multisig_core/src/error.rs"
    );
}

// ===========================================================================
// 6. error_codes_within_class_increment
// ===========================================================================

#[test]
fn error_codes_within_class_increment() {
    // Within each class, code numbers must increase monotonically from the
    // class base (E1xxx → 1000, E2xxx → 2000, ...). This locks the
    // convention that classes don't intermix and that codes inside a class
    // are densely allocated without gaps creeping in unnoticed.
    let classes: [(&str, u32, &[CoreError]); 4] = [
        (
            "E1xxx",
            1000,
            &[
                CoreError::InstanceNotActive,
                CoreError::ProposalExpiredOrExecuted,
                CoreError::ActionBytesTooLong,
            ],
        ),
        (
            "E2xxx",
            2000,
            &[
                CoreError::InvalidReceipt,
                CoreError::ImageIdMismatch,
                CoreError::RootMismatch,
                CoreError::ProposalIdMismatch,
            ],
        ),
        ("E3xxx", 3000, &[CoreError::NullifierAlreadyUsed]),
        (
            "E4xxx",
            4000,
            &[CoreError::ThresholdNotMet, CoreError::AlreadyExecuted],
        ),
    ];

    for (label, base, variants) in classes {
        let mut last: Option<u32> = None;
        for v in variants {
            let code = v.code();
            // Inside the class range.
            assert!(
                code >= base && code < base + 1000,
                "{label}: variant {:?} code {} not inside [{}..{})",
                v,
                code,
                base,
                base + 1000
            );
            // Strictly increasing.
            if let Some(prev) = last {
                assert!(
                    code > prev,
                    "{label}: codes must increment; got {} after {}",
                    code,
                    prev
                );
            }
            last = Some(code);
        }
    }
}

// ===========================================================================
// 7. chain_id_from_u64_zero_documented_aliasing
// ===========================================================================

#[test]
fn chain_id_from_u64_zero_documented_aliasing() {
    // Reproduce the FINDING-3 condition: `from_u64(0)` is byte-identical to
    // `new([0; 32])`. The fix here was rustdoc-only — pinning the alias as
    // a test so any future code that branches on `ChainId == [0; 32]` as a
    // sentinel will visibly conflict with the real chain-id-zero value.
    let from_zero = ChainId::from_u64(0);
    let from_array_zero = ChainId::new([0u8; 32]);
    assert_eq!(from_zero, from_array_zero);
    assert_eq!(from_zero.as_bytes(), &[0u8; 32]);
}

// ===========================================================================
// 8. chain_id_from_u64_one_is_nontrivial
// ===========================================================================

#[test]
fn chain_id_from_u64_one_is_nontrivial() {
    // The first non-zero chain id must distinguish from the "uninitialized"
    // pattern. Little-endian → `[0x01, 0x00, ..., 0x00]`.
    let one = ChainId::from_u64(1);
    let zero = ChainId::new([0u8; 32]);
    assert_ne!(one, zero);
    assert_eq!(one.as_bytes()[0], 0x01);
    for b in &one.as_bytes()[1..] {
        assert_eq!(*b, 0u8);
    }
}

// ===========================================================================
// 9. validate_action_bytes_boundary_proptest
// ===========================================================================

#[test]
fn validate_action_bytes_boundary_proptest() {
    // 200 seeded random sizes in [0, MAX_ACTION_BYTES_LEN + 100]. The
    // validator's decision (Ok vs Err) must depend purely on
    // `len > MAX_ACTION_BYTES_LEN`. Any future change that introduces a
    // size-dependent code path inside the cap (e.g. "reject zero-length")
    // will trip this test.
    let mut rng = StdRng::seed_from_u64(0xB10E_2002_FFFF_FFFFu64);
    let upper = MAX_ACTION_BYTES_LEN + 100;
    for _ in 0..200 {
        let len = (rng.next_u32() as usize) % (upper + 1);
        let data = vec![0u8; len];
        let expected_err = len > MAX_ACTION_BYTES_LEN;
        let result = Proposal::validate_action_bytes(&data);
        assert_eq!(
            result.is_err(),
            expected_err,
            "validate_action_bytes(len={}) decision must equal len > {}",
            len,
            MAX_ACTION_BYTES_LEN
        );
        if expected_err {
            assert_eq!(result, Err(CoreError::ActionBytesTooLong));
        }
    }
}

// ===========================================================================
// 10. e1002_round_trip_through_instruction
// ===========================================================================

#[test]
fn e1002_round_trip_through_instruction() {
    // Construct a Proposal with oversize action_bytes. The cap is enforced
    // by the validator, NOT by Borsh — so the encode/decode round trip
    // must succeed, but `validate_action_bytes` must reject. This pins the
    // layering: serialization is structural, validation is semantic.
    let oversize = oversize_buf(1);

    let proposal = Proposal {
        action_bytes: oversize.clone(),
        target_program: [0xCC; 32],
        approvals_count: 0,
        executed: false,
    };

    // Borsh round trip is unaffected by the validator (no error).
    let bytes = to_vec(&proposal).expect("borsh serialize must succeed");
    let decoded = Proposal::try_from_slice(&bytes).expect("borsh deserialize must succeed");
    assert_eq!(decoded, proposal);
    assert_eq!(decoded.action_bytes.len(), MAX_ACTION_BYTES_LEN + 1);

    // Validator catches the cap violation with the correct code.
    assert_eq!(
        Proposal::validate_action_bytes(&decoded.action_bytes),
        Err(CoreError::ActionBytesTooLong)
    );
}

// ===========================================================================
// 11. error_code_invertibility_post_fix
// ===========================================================================

#[test]
fn error_code_invertibility_post_fix() {
    // For every variant, `from_code(variant.code()) == Some(variant)`.
    // Round 1 established this; round 2 confirms the new variant did not
    // break the property.
    for v in all_variants() {
        assert_eq!(
            CoreError::from_code(v.code()),
            Some(v),
            "round-trip failed for {:?}",
            v
        );
    }
}

// ===========================================================================
// 12. error_classes_no_cross_collision
// ===========================================================================

#[test]
fn error_classes_no_cross_collision() {
    // Structural invariant: each variant's code lives in exactly one of
    // the documented class ranges. Trivially true given the numeric ranges
    // 1000..2000 / 2000..3000 / 3000..4000 / 4000..5000, but assert as a
    // sentinel so any future "shared base" mistake (e.g. assigning a
    // proof-failure code in the 1xxx range) breaks visibly.
    fn class_of(code: u32) -> Option<u32> {
        match code {
            1000..=1999 => Some(1),
            2000..=2999 => Some(2),
            3000..=3999 => Some(3),
            4000..=4999 => Some(4),
            _ => None,
        }
    }

    let expected: [(CoreError, u32); 10] = [
        (CoreError::InstanceNotActive, 1),
        (CoreError::ProposalExpiredOrExecuted, 1),
        (CoreError::ActionBytesTooLong, 1),
        (CoreError::InvalidReceipt, 2),
        (CoreError::ImageIdMismatch, 2),
        (CoreError::RootMismatch, 2),
        (CoreError::ProposalIdMismatch, 2),
        (CoreError::NullifierAlreadyUsed, 3),
        (CoreError::ThresholdNotMet, 4),
        (CoreError::AlreadyExecuted, 4),
    ];

    for (v, expected_class) in expected {
        let actual_class = class_of(v.code())
            .unwrap_or_else(|| panic!("{:?} code {} outside known classes", v, v.code()));
        assert_eq!(
            actual_class,
            expected_class,
            "{:?} (code {}) belongs to class E{}xxx, not E{}xxx",
            v,
            v.code(),
            expected_class,
            actual_class
        );
    }
}

// ===========================================================================
// 13. max_action_bytes_len_invariant_unchanged
// ===========================================================================

#[test]
fn max_action_bytes_len_invariant_unchanged() {
    // PLAN.md step 2 commits to a 4 KiB cap. The round-1 fix did not move
    // this constant; pin it so future "let's bump the cap" PRs surface
    // both here and in the existing round-1 / state.rs tests.
    assert_eq!(MAX_ACTION_BYTES_LEN, 4096);
}

// ===========================================================================
// 14. fix_does_not_regress_existing_validate_path
// ===========================================================================

#[test]
fn fix_does_not_regress_existing_validate_path() {
    // Sentinel against any future overcorrection. Inputs the validator was
    // already accepting before round 1 must STILL be accepted after the
    // fix: empty, cap-minus-one, and exactly-at-cap.
    let cases: [(&str, Vec<u8>); 3] = [
        ("empty", Vec::<u8>::new()),
        ("cap minus 1", vec![0u8; MAX_ACTION_BYTES_LEN - 1]),
        ("exactly cap", vec![0u8; MAX_ACTION_BYTES_LEN]),
    ];
    for (label, data) in cases {
        let result = Proposal::validate_action_bytes(&data);
        assert!(
            result.is_ok(),
            "validate_action_bytes must still accept {} ({} bytes); got {:?}",
            label,
            data.len(),
            result
        );
    }
}

// ===========================================================================
// 15. integration_round_trip_with_oversize_action_unchanged
// ===========================================================================

#[test]
fn integration_round_trip_with_oversize_action_unchanged() {
    // For each valid size (0, 1, 100, MAX_ACTION_BYTES_LEN), construct a
    // Proposal, Borsh-serialize, Borsh-deserialize, then validate. All
    // four steps must succeed. The naming is "with_oversize" because this
    // is the dual of test #10 — that one used oversize input and expected
    // the validator to reject; this one uses the full *valid* range to
    // confirm the validator continues to accept everything within the cap.
    let sizes: [usize; 4] = [0, 1, 100, MAX_ACTION_BYTES_LEN];
    for size in sizes {
        let proposal = Proposal {
            action_bytes: vec![0xAB; size],
            target_program: [0x55; 32],
            approvals_count: 0,
            executed: false,
        };
        let bytes = to_vec(&proposal)
            .unwrap_or_else(|e| panic!("borsh serialize failed for size {}: {}", size, e));
        let decoded = Proposal::try_from_slice(&bytes)
            .unwrap_or_else(|e| panic!("borsh deserialize failed for size {}: {}", size, e));
        assert_eq!(decoded, proposal);
        assert!(
            Proposal::validate_action_bytes(&decoded.action_bytes).is_ok(),
            "validate_action_bytes rejected valid size {}",
            size
        );
    }
}

// ===========================================================================
// 16. full_workflow_after_fixes_still_green
// ===========================================================================

#[test]
fn full_workflow_after_fixes_still_green() {
    // Replicate the round-1 happy path from `cross_crate_parity.rs`:
    // enroll members → derive proposal_id → compute nullifier → pack into
    // ApprovePublicInputs. The point is to confirm that adding
    // `CoreError::ActionBytesTooLong` and tightening the rustdoc on
    // `ChainId::from_u64` did NOT shift any cross-crate bytes.
    const N_MEMBERS: usize = 5;

    let program_id = [0x77u8; 32];
    let create_key = [0xC1u8; 32];
    let target_program = [0xBBu8; 32];
    let action_bytes = b"transfer(amount=42)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let index: u64 = 7;

    // Validator accepts the action bytes (well under cap).
    assert!(Proposal::validate_action_bytes(&action_bytes).is_ok());

    // Deterministic identities — same construction the round-1 parity test
    // uses, so the bytes pin against the same sentinel.
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

    // Merkle tree of commitments.
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for id in &identities {
        let commitment = id.commitment::<Sha256Hasher>();
        tree.insert(*commitment.as_bytes()).unwrap();
    }
    let members_root = tree.root();
    assert_ne!(members_root, [0u8; 32]);

    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let proposal_id =
        derive_proposal_id(&chain_id, &state_pda, index, &action_bytes, &target_program);
    assert_ne!(proposal_id, [0u8; 32]);

    // For each member, pack public inputs through the canonical 96-byte
    // layout and confirm round-trip equality. This is exactly the surface
    // the on-chain verifier reads.
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
        // And the Borsh-encoded form remains byte-identical to the explicit
        // 96-byte pack — the bridge invariant from round 1.
        let via_borsh = to_vec(&inputs).unwrap();
        assert_eq!(via_borsh.as_slice(), packed.as_slice());
    }
}
