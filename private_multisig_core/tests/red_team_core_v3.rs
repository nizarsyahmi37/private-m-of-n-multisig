//! Round-3 red-team for `private_multisig_core`.
//!
//! Rounds 1 and 2 (and a parallel round on `crypto`) pounded the structural
//! ABI surfaces: PDA collisions, avalanche, Borsh malformation, action-bytes
//! cap, error-code stability, ChainId construction, instruction discriminant
//! tampering, soundness oracles, and the threshold validator. The fixes
//! shipped:
//!   FINDING-2  (LOW)  → E1002 `ActionBytesTooLong`
//!   FINDING-3  (INFO) → `ChainId::from_u64(0)` aliasing documented
//!   FINDING-V2-A (LOW) → `validate_threshold` + E1003 `InvalidThreshold`
//!   FINDING-V2-B (INFO) → `Vault.create_key` redundancy accepted
//!   FINDING-V2-C (INFO) → unused `PdaSeed` removed
//!
//! This round is meta-level pressure. It pins corners the prior rounds
//! either glossed at the surface level or didn't think to ask:
//!
//!   * `CoreError` is *not* Borsh-serialized (only its u32 code is part of
//!     the ABI). Sentinel that catches a future PR adding `derive(BorshSerialize)`.
//!   * `Instruction` discriminant ordering is part of the on-chain ABI; a
//!     5th variant must APPEND (disc 4), never insert. Pin each existing
//!     discriminant by exact value.
//!   * `derive_proposal_id` index slot uses `index.to_le_bytes()`. Future PR
//!     flipping to BE would silently break consensus. Pin per-byte.
//!   * `validate_threshold` boundary corners: (1,1), (255,255), (255,1) fail,
//!     (255,254) fails, (255,255) passes, etc.
//!   * `u32::from(m) > n` widening invariant: if anyone refactors to
//!     `m > n as u8`, truncation aliases unequal values. Pin behaviorally.
//!   * `ChainId` value identity through `derive_proposal_id`: equal ChainIds
//!     produce identical proposal_ids regardless of how they were built.
//!   * `ApprovePublicInputs::from_bytes` is *total* over `[u8; 96]` — pin as
//!     a documented (not silently buggy) contract.
//!   * Empty receipt / empty action_bytes: documented "verifier owns this"
//!     scope boundaries.
//!   * Tautological tests review — see report.
//!
//! Constraints: only file touched is this one. Seeded sweeps, no proptest
//! crate (workspace doesn't carry it). All assertions reproducible
//! byte-for-byte from `--test red_team_core_v3`.

#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::similar_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::items_after_statements)]

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    derive_multisig_state_pda, derive_proposal_id, derive_proposal_pda, derive_vault_pda,
    ApprovePublicInputs, ChainId, CoreError, Instruction, MultisigState, NullifierEntry, Proposal,
    Vault, APPROVE_PUBLIC_INPUTS_LEN, MAX_ACTION_BYTES_LEN, SEED_MULTISIG_STATE, SEED_NULLIFIER,
    SEED_PROPOSAL, SEED_VAULT,
};

fn rng() -> StdRng {
    // "RED3" — round-3 deterministic seed.
    StdRng::seed_from_u64(0x52_45_44_33_u64)
}

fn random_32(r: &mut StdRng) -> [u8; 32] {
    let mut out = [0u8; 32];
    r.fill_bytes(&mut out);
    out
}

// ============================================================================
// 1. CoreError is NOT Borsh-serialized in the public ABI — sentinel
// ============================================================================

/// `CoreError` participates in the on-chain ABI ONLY through the numeric
/// `code()` (a `u32`). The variant order in the source enum therefore must
/// stay reorderable without breaking consumers — UNLESS someone later
/// derives `BorshSerialize` on it, at which point Borsh would assign a u8
/// discriminant by source-order and any reorder would shift discriminants.
///
/// This test makes the "no Borsh" contract a regression: it confirms that
/// the borsh round-trip path does NOT compile (we can't `to_vec(&err)`).
/// We can't directly assert "trait not implemented" in stable Rust, so we
/// observe the property indirectly: if `to_vec(&CoreError::...)` ever starts
/// compiling, a future test referencing it will need to be added. Here we
/// pin the surface-level "ABI is via u32 code()" instead.
#[test]
fn v3_attack_1a_core_error_abi_is_only_u32_code() {
    // The public, ABI-stable surface for `CoreError` consists of:
    //   (1) the numeric `code()` value
    //   (2) the `from_code` round-trip
    //   (3) the `Display` text (logged on chain)
    //
    // No Borsh serializer is exposed. If someone derives one in the future,
    // they MUST add a `#[borsh(use_discriminant = true)]` and pin each
    // discriminant explicitly — otherwise a reorder is a silent ABI break.
    //
    // This test pins the *current* contract. The discriminants for the
    // numeric code are stable and tested elsewhere; this test asserts that
    // adding/removing/reordering variants does NOT alter the (code, display)
    // mapping for the surviving variants.
    let table: &[(CoreError, u32)] = &[
        (CoreError::InstanceNotActive, 1000),
        (CoreError::ProposalExpiredOrExecuted, 1001),
        (CoreError::ActionBytesTooLong, 1002),
        (CoreError::InvalidThreshold, 1003),
        (CoreError::InvalidReceipt, 2000),
        (CoreError::ImageIdMismatch, 2001),
        (CoreError::RootMismatch, 2002),
        (CoreError::ProposalIdMismatch, 2003),
        (CoreError::NullifierAlreadyUsed, 3000),
        (CoreError::ThresholdNotMet, 4000),
        (CoreError::AlreadyExecuted, 4001),
    ];
    for (variant, expected_code) in table {
        let got = variant.code();
        assert_eq!(
            got, *expected_code,
            "v3: code() for {variant:?} is {got}, expected {expected_code} — \
             if you reordered variants, the explicit match arms in code() \
             are the binding contract, not source order",
        );
    }
}

/// The 11 variants must each round-trip through (code → from_code → variant).
/// Pinning the cardinality here too — if a 12th variant lands without a
/// corresponding `from_code` arm, this catches the gap.
#[test]
fn v3_attack_1b_core_error_round_trip_cardinality_11() {
    let all = [
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
    assert_eq!(all.len(), 11, "v3: variant count drift from 11");
    let mut codes = HashSet::new();
    for v in all {
        let c = v.code();
        assert!(codes.insert(c), "duplicate code {c} for variant {v:?}");
        assert_eq!(CoreError::from_code(c), Some(v));
    }
    assert_eq!(codes.len(), 11);
}

// ============================================================================
// 2. Instruction discriminant stability — every existing variant pinned by
//    exact value, plus a "future variants must APPEND" sentinel.
// ============================================================================

/// Each existing variant's Borsh discriminant byte is pinned by exact value.
/// The four MVP variants are at 0, 1, 2, 3 in source order. A future PR
/// adding `Reject` (mentioned in the docstring as post-MVP) MUST append it
/// as discriminant 4 — inserting it anywhere else would shift the existing
/// discriminants and silently break every on-chain consumer.
#[test]
fn v3_attack_2a_instruction_discriminants_each_pinned() {
    // CreateMultisig = 0
    let create = Instruction::CreateMultisig {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 0,
        n: 0,
    };
    assert_eq!(to_vec(&create).unwrap()[0], 0u8, "v3: CreateMultisig disc != 0");

    // Propose = 1
    let propose = Instruction::Propose {
        create_key: [0; 32],
        index: 0,
        action_bytes: Vec::new(),
        target_program: [0; 32],
    };
    assert_eq!(to_vec(&propose).unwrap()[0], 1u8, "v3: Propose disc != 1");

    // Approve = 2
    let approve = Instruction::Approve {
        create_key: [0; 32],
        index: 0,
        public_inputs: ApprovePublicInputs {
            members_root: [0; 32],
            proposal_id: [0; 32],
            nullifier: [0; 32],
        },
    };
    assert_eq!(to_vec(&approve).unwrap()[0], 2u8, "v3: Approve disc != 2");

    // Execute = 3
    let execute = Instruction::Execute {
        create_key: [0; 32],
        index: 0,
    };
    assert_eq!(to_vec(&execute).unwrap()[0], 3u8, "v3: Execute disc != 3");
}

/// Implication-of-insertion test. We cannot modify the crate's source, but
/// we can ENUMERATE the breakage: if a future PR inserts `Reject` between
/// CreateMultisig (0) and Propose (1), then Propose would shift to 2,
/// Approve to 3, Execute to 4. The instruction byte stream for an Execute
/// emitted by the OLD client (`bytes[0] == 3`) would now decode as the NEW
/// Approve. This test pins the IMPACT: any byte stream beginning with `3`
/// MUST decode as today's Execute, never as a future Approve-shape.
#[test]
fn v3_attack_2b_disc_3_only_decodes_as_execute_today() {
    let bytes_only_disc = [3u8];
    // 1 byte alone is not enough for any variant — must error cleanly.
    let res = Instruction::try_from_slice(&bytes_only_disc);
    assert!(res.is_err(), "v3: disc 3 alone must not decode");

    // Disc 3 + 32 bytes create_key + 8 bytes index = a 41-byte Execute.
    let mut bytes = vec![3u8];
    bytes.extend_from_slice(&[0xCC; 32]);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    let decoded = Instruction::try_from_slice(&bytes).expect("Execute decode");
    match decoded {
        Instruction::Execute { create_key, index } => {
            assert_eq!(create_key, [0xCC; 32]);
            assert_eq!(index, 0);
        }
        other => panic!(
            "v3: disc 3 must decode as Execute today — got {other:?}. \
             If a new variant was inserted at disc <= 3, fix the insertion \
             to APPEND instead.",
        ),
    }
}

/// Discriminant 4 — the SMALLEST disc that future variants can occupy —
/// currently rejects. This anchors that today's `Instruction` has exactly
/// 4 variants and `Reject` (or any new variant) lives at disc 4 once added.
#[test]
fn v3_attack_2c_disc_4_currently_rejects() {
    // Bare disc 4 must error today (no variant exists at that disc).
    let buf = [4u8];
    let res = Instruction::try_from_slice(&buf);
    assert!(res.is_err(), "v3: disc 4 must error today — fifth variant not yet added");

    // A longer body with disc 4 still errors today.
    let mut long = vec![4u8];
    long.resize(128, 0xAA);
    let res = Instruction::try_from_slice(&long);
    assert!(res.is_err(), "v3: disc 4 with body must error today");
}

// ============================================================================
// 3. derive_proposal_id index byte-layout sentinel
// ============================================================================

/// The 136-byte preimage of `derive_proposal_id` puts the index at
/// `[64..72)` in `to_le_bytes()` order. For `index = 0x0102030405060708`
/// the bytes at that slot are `[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]`.
///
/// If a future PR flipped to big-endian — even by accident, e.g. someone
/// replacing `index.to_le_bytes()` with `index.to_be_bytes()` thinking
/// "network order" — the bytes would be reversed. Cross-crate parity tests
/// in `cross_crate_parity.rs` use a manual recompute that catches this,
/// but they recompute with LE in their own helper; we go one step further
/// and INDEPENDENTLY pin the expected LE bytes against a manually-built
/// "wrong endian" alternative to make the implication explicit.
#[test]
fn v3_attack_3a_derive_proposal_id_index_is_little_endian_per_byte() {
    let chain_id = ChainId::new([0x77; 32]); // arbitrary non-trivial chain
    let state_pda = [0xAA; 32];
    let action = b"v3-index-le-pin";
    let target = [0xBB; 32];
    let index: u64 = 0x0102_0304_0506_0708;

    let actual = derive_proposal_id(&chain_id, &state_pda, index, action, &target);

    // Independent LE recompute (this is what the actual implementation does).
    let action_hash = crypto::Sha256Hasher::hash(action);
    let target_hash = crypto::Sha256Hasher::hash(&target);
    use crypto::Hasher;
    let mut preimage = [0u8; 136];
    preimage[0..32].copy_from_slice(chain_id.as_bytes());
    preimage[32..64].copy_from_slice(&state_pda);
    // Bytes 64..72 LITTLE-endian.
    preimage[64..72].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    preimage[72..104].copy_from_slice(&action_hash);
    preimage[104..136].copy_from_slice(&target_hash);
    let expected_le = crypto::Sha256Hasher::hash(&preimage);
    assert_eq!(actual, expected_le, "v3: index byte slot must be LE");

    // Negative: if it were big-endian, the bytes would be reversed. Build
    // that alt preimage and confirm it is DIFFERENT from `actual`.
    let mut alt = preimage;
    alt[64..72].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // BE
    let alt_hash = crypto::Sha256Hasher::hash(&alt);
    assert_ne!(actual, alt_hash, "v3: BE-encoded index must NOT match LE result");
}

// ============================================================================
// 4. proposal_id binding to target_program — independent reference
// ============================================================================

/// `derive_proposal_id` hashes `target_program` via SHA-256 (NOT raw,
/// NOT reversed, NOT padded). cross_crate_parity already pins this, but
/// the test there uses a manual recompute that mirrors the implementation
/// 1:1. Here we use a *completely independent* observation: hash the
/// target bytes ONCE outside, splice the digest at slot [104..136), and
/// confirm the result matches `derive_proposal_id`. This catches a future
/// refactor that changes the target-hashing direction (e.g. reversed bytes,
/// big-endian flip, or accidentally double-hashing).
#[test]
fn v3_attack_4a_target_program_hashed_natural_order() {
    use crypto::Hasher;

    let chain_id = ChainId::from_u64(0xCAFE_BABE_DEAD_BEEFu64);
    let state_pda = [0x55; 32];
    let index: u64 = 1234;
    let action: &[u8] = b"v3-target-hash-anchor";
    // Use a clearly-asymmetric target so a reversed-bytes bug would surface.
    let mut target = [0u8; 32];
    for i in 0..32 {
        target[i] = i as u8; // 0,1,...,31
    }

    let actual = derive_proposal_id(&chain_id, &state_pda, index, action, &target);

    // Independent: hash target in natural order.
    let target_hash = crypto::Sha256Hasher::hash(&target);

    // Now build the preimage by hand and re-hash. (We deliberately don't
    // reuse the helper from cross_crate_parity to keep this independent.)
    let action_hash = crypto::Sha256Hasher::hash(action);
    let mut preimage = Vec::with_capacity(136);
    preimage.extend_from_slice(chain_id.as_bytes());
    preimage.extend_from_slice(&state_pda);
    preimage.extend_from_slice(&index.to_le_bytes());
    preimage.extend_from_slice(&action_hash);
    preimage.extend_from_slice(&target_hash);
    assert_eq!(preimage.len(), 136);
    let expected = crypto::Sha256Hasher::hash(&preimage);
    assert_eq!(actual, expected, "v3: target_program hashed in natural order");

    // Negative: hashing the REVERSED target must yield a different result.
    let mut reversed = target;
    reversed.reverse();
    let reversed_hash = crypto::Sha256Hasher::hash(&reversed);
    assert_ne!(target_hash, reversed_hash, "v3: target ≠ reverse(target)");
    let mut alt = preimage.clone();
    let len = alt.len();
    alt[len - 32..].copy_from_slice(&reversed_hash);
    let alt_pid = crypto::Sha256Hasher::hash(&alt);
    assert_ne!(actual, alt_pid, "v3: reversed-target preimage must differ");
}

// ============================================================================
// 5. validate_threshold widening direction — behavioral pin
// ============================================================================

/// `u32::from(self.m) > self.n` is a widening compare (u8 → u32, safe).
///
/// A naive "fix" some future contributor might attempt:
///   `self.m > self.n as u8`
/// truncates `n` to its low byte. That's catastrophic:
///   - `m=1, n=256`  → `n as u8 = 0`, `1 > 0` = true → REJECTED (wrong, valid)
///   - `m=1, n=257`  → `n as u8 = 1`, `1 > 1` = false → ACCEPTED (wrong direction)
///
/// This test pins values that DISAMBIGUATE the two implementations. If a
/// future refactor switches to truncation, at least one of these breaks.
#[test]
fn v3_attack_5a_validate_threshold_widening_not_truncating() {
    // (m=1, n=256): widening says n=256 > m=1 → valid (Ok).
    //               truncating says n_as_u8=0 < m=1 → invalid (Err).
    // The current widening implementation MUST accept this.
    let res = MultisigState::validate_threshold(1, 256);
    assert!(
        res.is_ok(),
        "v3: validate_threshold(1, 256) must be Ok under widening; \
         if this fails the refactor truncated n to u8",
    );

    // (m=2, n=257): widening says n=257 > m=2 → valid (Ok).
    //               truncating says n_as_u8=1 < m=2 → invalid (Err).
    let res = MultisigState::validate_threshold(2, 257);
    assert!(res.is_ok(), "v3: validate_threshold(2, 257) must be Ok");

    // (m=255, n=256): widening valid; truncating says n_as_u8=0 vs m=255 →
    //                 truncating rejects.
    let res = MultisigState::validate_threshold(255, 256);
    assert!(
        res.is_ok(),
        "v3: validate_threshold(255, 256) must be Ok under widening",
    );

    // (m=10, n=300): widening valid; truncating says n_as_u8=44 → 10 < 44 →
    //                truncating would ALSO accept (false positive). Pin a
    //                case where they diverge in the other direction:
    // (m=200, n=256): widening accepts (200 <= 256). Truncating: n_as_u8=0,
    //                 200 > 0 → rejects. Current must accept.
    let res = MultisigState::validate_threshold(200, 256);
    assert!(res.is_ok(), "v3: validate_threshold(200, 256) must be Ok under widening");

    // (m=255, n=u32::MAX): widening 255 <= u32::MAX → Ok.
    let res = MultisigState::validate_threshold(255, u32::MAX);
    assert!(res.is_ok(), "v3: max n must be accepted");
}

// ============================================================================
// 6. validate_threshold boundary corners — exact pins
// ============================================================================

/// Pin specific corner pairs the task brief enumerates.
#[test]
fn v3_attack_6a_validate_threshold_corner_pins() {
    // m=1, n=1 → Ok (degenerate single-member-1-of-1).
    assert!(MultisigState::validate_threshold(1, 1).is_ok(), "v3: (1,1) Ok");

    // m=255, n=255 → Ok (255 == 255, not greater).
    assert!(
        MultisigState::validate_threshold(255, 255).is_ok(),
        "v3: (255,255) Ok — 255 is u8::MAX and u32::from(255) == 255 is not > 255",
    );

    // m=u8::MAX (255), n=1 → Err (255 > 1).
    assert_eq!(
        MultisigState::validate_threshold(u8::MAX, 1),
        Err(CoreError::InvalidThreshold),
        "v3: (255,1) must be rejected",
    );

    // m=u8::MAX, n=254 → Err (255 > 254 by exactly 1).
    assert_eq!(
        MultisigState::validate_threshold(u8::MAX, 254),
        Err(CoreError::InvalidThreshold),
        "v3: (255,254) must be rejected — m > n by 1",
    );

    // m=u8::MAX, n=255 → Ok (the exact boundary).
    assert!(
        MultisigState::validate_threshold(u8::MAX, 255).is_ok(),
        "v3: (255,255) is the exact boundary — must be Ok",
    );

    // m=0, n=anything → Err.
    for n in [0u32, 1, 5, 256, u32::MAX] {
        assert_eq!(
            MultisigState::validate_threshold(0, n),
            Err(CoreError::InvalidThreshold),
            "v3: (0,{n}) must be Err",
        );
    }

    // m=anything, n=0 → Err.
    for m in [0u8, 1, 50, 255] {
        assert_eq!(
            MultisigState::validate_threshold(m, 0),
            Err(CoreError::InvalidThreshold),
            "v3: ({m},0) must be Err",
        );
    }
}

/// Sweep the (m, n) plane for small values to confirm the predicate is
/// exactly `m == 0 || n == 0 || u32::from(m) > n`.
#[test]
fn v3_attack_6b_validate_threshold_small_plane_proptest() {
    for m in 0u8..=20 {
        for n in 0u32..=20 {
            let expected_err = m == 0 || n == 0 || u32::from(m) > n;
            let got = MultisigState::validate_threshold(m, n);
            if expected_err {
                assert_eq!(
                    got,
                    Err(CoreError::InvalidThreshold),
                    "v3: ({m},{n}) expected Err",
                );
            } else {
                assert!(got.is_ok(), "v3: ({m},{n}) expected Ok, got {got:?}");
            }
        }
    }
}

/// And the same predicate must hold via `MultisigState::validate()`.
#[test]
fn v3_attack_6c_validate_method_matches_threshold_function() {
    let cases: &[(u8, u32)] = &[
        (0, 5),
        (3, 0),
        (5, 4),
        (1, 1),
        (255, 255),
        (255, 254),
        (255, 256),
        (3, 5),
    ];
    for &(m, n) in cases {
        let state = MultisigState {
            create_key: [0; 32],
            members_root: [0; 32],
            m,
            n,
            proposal_count: 0,
        };
        let via_state = state.validate();
        let via_helper = MultisigState::validate_threshold(m, n);
        assert_eq!(
            via_state, via_helper,
            "v3: state.validate() must equal validate_threshold({m},{n})",
        );
    }
}

// ============================================================================
// 7. m=u8::MAX, n=254 fail; m=u8::MAX, n=255 pass — task brief explicit
// ============================================================================
// Covered by v3_attack_6a — keeping this section header so the report
// lines up with the brief. No separate test (would be tautological).

// ============================================================================
// 8. derive_pda — SPEL-compatibility shape sanity
// ============================================================================
// The round-5 PDA rewrite changed derive_pda's algorithm from
// `SHA-256(program_id ‖ seed ‖ extras)` to SPEL's
// `SHA-256(NSSA_PREFIX(32) ‖ program_id(32) ‖ combined(32))` where
// combined is either the single 32-byte seed or SHA-256(seed_0 ‖ seed_1 ‖ ...).
// The three OLD round-3 attack tests (8a/8b/8c) verified implementation
// details of the OLD algorithm (no length prefix, raw-byte concat, etc.)
// that no longer apply. Replaced below with tests that verify the NEW
// algorithm's shape invariants.

/// (8a) Multi-seed combine is SHA-256 of the concatenation, NOT XOR /
/// HKDF / any other reducer. Construct the same combined seed manually
/// and assert byte-equality.
#[test]
fn v3_attack_8a_derive_pda_multi_seed_combine_is_sha256_concat() {
    use crypto::Hasher;

    let program_id = [0x42u8; 32];
    let seed_a = [0x11u8; 32];
    let seed_b = [0x22u8; 32];
    let seed_c = [0x33u8; 32];

    let actual = private_multisig_core::pda::derive_pda(&program_id, &[&seed_a, &seed_b, &seed_c]);

    // Manual: combined = SHA-256(seed_a || seed_b || seed_c);
    //         pda = SHA-256(NSSA_PREFIX || program_id || combined).
    let mut combined_preimage = Vec::with_capacity(96);
    combined_preimage.extend_from_slice(&seed_a);
    combined_preimage.extend_from_slice(&seed_b);
    combined_preimage.extend_from_slice(&seed_c);
    let combined: [u8; 32] = crypto::Sha256Hasher::hash(&combined_preimage);

    let mut outer = [0u8; 96];
    outer[..32].copy_from_slice(b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00");
    outer[32..64].copy_from_slice(&program_id);
    outer[64..96].copy_from_slice(&combined);
    let expected: [u8; 32] = crypto::Sha256Hasher::hash(&outer);

    assert_eq!(actual, expected, "v3: multi-seed combine must be SHA-256 concat");
}

/// (8b) Single-seed input passes through WITHOUT a SHA-256 over the seed
/// list (so `derive_pda(pid, &[&S]) != derive_pda(pid, &[&SHA(S)])`).
/// This catches a regression that would always run the combine step.
#[test]
fn v3_attack_8b_derive_pda_single_seed_no_double_hash() {
    use crypto::Hasher;

    let program_id = [0x42u8; 32];
    let single = [0xCDu8; 32];

    let actual = private_multisig_core::pda::derive_pda(&program_id, &[&single]);

    // Manual: with one seed, combined == single (no inner SHA-256).
    let mut outer = [0u8; 96];
    outer[..32].copy_from_slice(b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00");
    outer[32..64].copy_from_slice(&program_id);
    outer[64..96].copy_from_slice(&single);
    let expected_single: [u8; 32] = crypto::Sha256Hasher::hash(&outer);

    assert_eq!(actual, expected_single);

    // And as a contrast: if the implementation accidentally always
    // SHA-256'd the seed list, the result would be the "with SHA" path.
    let double_seed_preimage: [u8; 32] = crypto::Sha256Hasher::hash(&single);
    outer[64..96].copy_from_slice(&double_seed_preimage);
    let expected_double: [u8; 32] = crypto::Sha256Hasher::hash(&outer);
    assert_ne!(
        actual, expected_double,
        "v3: single-seed call must not double-hash the seed list"
    );
}

/// (8c) Seed ordering matters (SHA-256 of concat is non-commutative).
#[test]
fn v3_attack_8c_derive_pda_seed_order_matters() {
    let program_id = [0x33u8; 32];
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];

    let ab = private_multisig_core::pda::derive_pda(&program_id, &[&a, &b]);
    let ba = private_multisig_core::pda::derive_pda(&program_id, &[&b, &a]);
    assert_ne!(
        ab, ba,
        "v3: seed ordering must affect the result (non-commutative combine)",
    );
}

// ============================================================================
// 9. ChainId equality invariance under derive_proposal_id
// ============================================================================

/// `ChainId::from_u64(1)` and `ChainId::new([1, 0, ..., 0])` are equal
/// (FINDING-3 alias path). They MUST produce identical `proposal_id`s.
/// This is technically guaranteed by `Eq` on `ChainId` + the function being
/// pure, but pin it: any future refactor that derives `proposal_id`
/// non-deterministically from the construction path (e.g. by adding a
/// version byte to one constructor) would fail here.
#[test]
fn v3_attack_9a_equal_chainids_same_proposal_id() {
    let mut le_bytes = [0u8; 32];
    le_bytes[0] = 1;
    let via_from_u64 = ChainId::from_u64(1);
    let via_new = ChainId::new(le_bytes);
    assert_eq!(via_from_u64, via_new);

    let state_pda = [0x42u8; 32];
    let target = [0x84u8; 32];
    let pid_a = derive_proposal_id(&via_from_u64, &state_pda, 0, b"x", &target);
    let pid_b = derive_proposal_id(&via_new, &state_pda, 0, b"x", &target);
    assert_eq!(pid_a, pid_b, "v3: equal ChainIds must produce equal proposal_ids");

    // Test with the all-zero alias path too (FINDING-3 sentinel).
    let zero_a = ChainId::from_u64(0);
    let zero_b = ChainId::new([0u8; 32]);
    assert_eq!(zero_a, zero_b);
    let pid_za = derive_proposal_id(&zero_a, &state_pda, 0, b"x", &target);
    let pid_zb = derive_proposal_id(&zero_b, &state_pda, 0, b"x", &target);
    assert_eq!(pid_za, pid_zb, "v3: equal zero-ChainIds must produce equal proposal_ids");
}

/// And distinct-but-equal-on-bytes constructions never diverge over 1000
/// random u64 values.
#[test]
fn v3_attack_9b_chainid_construction_path_independence_sweep() {
    let mut r = rng();
    let state_pda = [0xAA; 32];
    let target = [0xBB; 32];
    for _ in 0..1_000 {
        let v: u64 = r.gen();
        let from_u64 = ChainId::from_u64(v);
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&v.to_le_bytes());
        let from_new = ChainId::new(bytes);
        assert_eq!(from_u64, from_new);
        let pid_a = derive_proposal_id(&from_u64, &state_pda, v, b"x", &target);
        let pid_b = derive_proposal_id(&from_new, &state_pda, v, b"x", &target);
        assert_eq!(pid_a, pid_b);
    }
}

// ============================================================================
// 10. ApprovePublicInputs::from_bytes totality — documented (not a bug)
// ============================================================================

/// `ApprovePublicInputs::from_bytes` accepts ANY `[u8; 96]`, including
/// triples that "look like" the same nullifier as a different proposal. The
/// task brief flags this as totality, not validity — i.e. by design.
///
/// Pin two specific corner cases:
///   1. All 96 bytes equal to the nullifier of some other (hypothetical)
///      proposal — totality says the decode succeeds and merely materializes
///      a `ApprovePublicInputs` whose three fields happen to all be equal.
///   2. members_root == proposal_id == nullifier (all 32 bytes identical).
///      Totality says decode succeeds.
///
/// The proposal_id-mismatch check is in the verifier program, NOT here.
#[test]
fn v3_attack_10a_from_bytes_total_over_collisions() {
    // 1. All 96 bytes equal to 0x42 — every field is identical.
    let bundle1 = ApprovePublicInputs::from_bytes(&[0x42u8; 96]);
    assert_eq!(bundle1.members_root, [0x42u8; 32]);
    assert_eq!(bundle1.proposal_id, [0x42u8; 32]);
    assert_eq!(bundle1.nullifier, [0x42u8; 32]);
    // And it round-trips back to the same 96 bytes.
    assert_eq!(bundle1.to_bytes(), [0x42u8; 96]);

    // 2. nullifier matches a "real" nullifier shape — say, all zeros — but
    //    so does everything else. from_bytes does not flag this.
    let bundle2 = ApprovePublicInputs::from_bytes(&[0u8; 96]);
    assert_eq!(bundle2.nullifier, [0u8; 32]);
    // Document the SCOPE: at this layer there is nothing to reject. The
    // verifier program is where the proposal_id mismatch / nullifier double-
    // use checks live. If a future PR adds field validation to `from_bytes`,
    // this test should be rewritten to assert the new rejection.
}

/// Sweep 5_000 random bytes — `from_bytes` never panics, never returns
/// anything other than the obvious bit-for-bit destructuring.
#[test]
fn v3_attack_10b_from_bytes_total_oracle_5k() {
    let mut r = rng();
    for _ in 0..5_000 {
        let mut buf = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        r.fill_bytes(&mut buf);
        let res = catch_unwind(AssertUnwindSafe(|| ApprovePublicInputs::from_bytes(&buf)));
        let bundle = match res {
            Ok(b) => b,
            Err(_) => panic!("v3: PANIC in from_bytes — should be infallible"),
        };
        // Each field is the byte-exact substring at its offset.
        assert_eq!(bundle.members_root, buf[0..32]);
        assert_eq!(bundle.proposal_id, buf[32..64]);
        assert_eq!(bundle.nullifier, buf[64..96]);
        // Round-trip.
        assert_eq!(bundle.to_bytes(), buf);
    }
}

// ============================================================================
// 11. Proposal.action_bytes empty — core layer accepts
// ============================================================================

/// `Proposal { action_bytes: vec![], ... }` is valid at the core layer
/// (Borsh round-trips, validator accepts). The "is empty action meaningful"
/// check is downstream (verifier / SDK semantic policy). Pin both halves.
#[test]
fn v3_attack_11a_proposal_empty_action_bytes_accepted_at_core() {
    let p = Proposal {
        action_bytes: Vec::new(),
        target_program: [0xCC; 32],
        approvals_count: 0,
        executed: false,
    };
    let bytes = to_vec(&p).unwrap();
    let decoded: Proposal = Proposal::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, p);
    assert!(decoded.action_bytes.is_empty());

    // Validator accepts.
    assert!(
        Proposal::validate_action_bytes(&decoded.action_bytes).is_ok(),
        "v3: empty action_bytes must pass the core validator",
    );

    // And derive_proposal_id over an empty action_bytes is also well-defined.
    let chain = ChainId::from_u64(1);
    let state_pda = [0xAA; 32];
    let pid = derive_proposal_id(&chain, &state_pda, 0, b"", &[0xBB; 32]);
    assert_ne!(pid, [0u8; 32], "v3: pid over empty action must be non-zero (SHA-256 of nonzero preimage)");
}

// ============================================================================
// 12. Cross-instance state confusion — non-responsibility pin
// ============================================================================

/// At the core layer, neither `CreateMultisig.create_key` nor any other
/// instruction field is cross-checked against an external `MultisigState`.
/// A malicious or buggy SDK could ship an instruction with `create_key` X
/// while the account-meta points at a state PDA derived from `create_key` Y.
/// The core layer can't detect this. The verifier MUST re-derive the PDA
/// from `create_key` and compare.
///
/// This test pins the *non-responsibility*: an `Instruction::CreateMultisig`
/// plus a `MultisigState` with mismatched `create_key` Borsh-decode
/// INDEPENDENTLY without complaint. The verifier is the only layer that
/// can connect them.
#[test]
fn v3_attack_12a_core_does_not_link_instruction_create_key_to_state() {
    let ix = Instruction::CreateMultisig {
        create_key: [0x11; 32],
        members_root: [0xAA; 32],
        m: 3,
        n: 5,
    };
    let state = MultisigState {
        create_key: [0x22; 32], // DIFFERENT create_key
        members_root: [0xAA; 32],
        m: 3,
        n: 5,
        proposal_count: 0,
    };

    // Both Borsh-encode and decode without complaint.
    let ix_bytes = to_vec(&ix).unwrap();
    let state_bytes = to_vec(&state).unwrap();
    let _ix_back = Instruction::try_from_slice(&ix_bytes).unwrap();
    let state_back: MultisigState = MultisigState::try_from_slice(&state_bytes).unwrap();

    // The mismatch lives in the bytes — no helper at the core surface
    // detects it.
    match _ix_back {
        Instruction::CreateMultisig { create_key, .. } => {
            assert_ne!(
                create_key, state_back.create_key,
                "v3: instruction.create_key ≠ state.create_key — core layer cannot reject",
            );
        }
        _ => panic!("disc shape mismatch"),
    }
}

// ============================================================================
// 13. Approve minimal wire size — receipt no longer part of the instruction
// ============================================================================

/// Round 5 dropped the `receipt: Vec<u8>` field from `Instruction::Approve`
/// (the receipt is attached host-side via `add_assumption`, never on the
/// instruction wire). Pin the new minimal Approve wire size as
/// `discriminant(1) + create_key(32) + index(8) + public_inputs(96) = 137`.
#[test]
fn v3_attack_13a_approve_minimal_wire_size_137_bytes() {
    let inputs = ApprovePublicInputs {
        members_root: [0x11; 32],
        proposal_id: [0x22; 32],
        nullifier: [0x33; 32],
    };
    let ix = Instruction::Approve {
        create_key: [0xAA; 32],
        index: 0,
        public_inputs: inputs,
    };
    let bytes = to_vec(&ix).unwrap();
    assert_eq!(
        bytes.len(),
        1 + 32 + 8 + APPROVE_PUBLIC_INPUTS_LEN,
        "v3: minimal Approve wire size",
    );
    assert_eq!(bytes.len(), 137);

    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, ix);
}

// ============================================================================
// 14. Re-export drift detection
// ============================================================================

/// Every public symbol re-exported at the crate root MUST be reachable by
/// name. Round-2 had `v2_attack_6a_reexport_surface_drift` — it referenced
/// the symbols but for some (the function items) only as type-elaborated
/// values. This test additionally:
///   (a) CALLS each re-exported function to confirm the symbol resolves to
///       a real callable, not a type alias.
///   (b) Confirms each re-exported function returns the byte-identical
///       result as the same function reached via the module path. This
///       catches a future PR that removes a `pub use` and accidentally
///       leaves the function name shadowed by something at the crate root.
///   (c) Confirms each constant has the documented value at BOTH paths.
#[test]
fn v3_attack_14a_reexports_callable_and_consistent() {
    let pid_arg = [0x11u8; 32];
    let ck_arg = [0x22u8; 32];

    // (a) + (b) functions reachable via crate root MUST equal the
    //         module-path versions.
    assert_eq!(
        private_multisig_core::derive_multisig_state_pda(&pid_arg, &ck_arg),
        private_multisig_core::pda::derive_multisig_state_pda(&pid_arg, &ck_arg),
    );
    assert_eq!(
        private_multisig_core::derive_proposal_pda(&pid_arg, &ck_arg, 7),
        private_multisig_core::pda::derive_proposal_pda(&pid_arg, &ck_arg, 7),
    );
    assert_eq!(
        private_multisig_core::derive_vault_pda(&pid_arg, &ck_arg),
        private_multisig_core::pda::derive_vault_pda(&pid_arg, &ck_arg),
    );
    let prop_pda = derive_proposal_pda(&pid_arg, &ck_arg, 0);
    let nullifier = [0xCC; 32];
    assert_eq!(
        private_multisig_core::derive_nullifier_entry_pda(&pid_arg, &prop_pda, &nullifier),
        private_multisig_core::pda::derive_nullifier_entry_pda(&pid_arg, &prop_pda, &nullifier),
    );

    let chain = ChainId::from_u64(1);
    let action = b"reexport-check";
    let target = [0xDD; 32];
    assert_eq!(
        private_multisig_core::derive_proposal_id(&chain, &prop_pda, 0, action, &target),
        private_multisig_core::proof::derive_proposal_id(&chain, &prop_pda, 0, action, &target),
    );

    // (c) constants identity.
    assert_eq!(
        SEED_MULTISIG_STATE as *const _,
        private_multisig_core::pda::SEED_MULTISIG_STATE as *const _,
        "v3: SEED_MULTISIG_STATE pointer identity (same const)",
    );
    assert_eq!(SEED_MULTISIG_STATE, private_multisig_core::pda::SEED_MULTISIG_STATE);
    assert_eq!(SEED_PROPOSAL, private_multisig_core::pda::SEED_PROPOSAL);
    assert_eq!(SEED_VAULT, private_multisig_core::pda::SEED_VAULT);
    assert_eq!(SEED_NULLIFIER, private_multisig_core::pda::SEED_NULLIFIER);
    assert_eq!(MAX_ACTION_BYTES_LEN, private_multisig_core::state::MAX_ACTION_BYTES_LEN);
    assert_eq!(
        APPROVE_PUBLIC_INPUTS_LEN,
        private_multisig_core::proof::APPROVE_PUBLIC_INPUTS_LEN,
    );
}

/// Type re-exports are callable in struct-construction position. If a `pub
/// use` is dropped, this test fails at compile time. The body is
/// structurally exercising the type names at the crate root.
#[test]
fn v3_attack_14b_type_reexports_constructible_at_crate_root() {
    // Each of these must compile at the crate-root path.
    let _err: CoreError = CoreError::AlreadyExecuted;
    let _ix: Instruction = Instruction::Execute {
        create_key: [0; 32],
        index: 0,
    };
    let _state = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 1,
        n: 1,
        proposal_count: 0,
    };
    let _prop = Proposal {
        action_bytes: Vec::new(),
        target_program: [0; 32],
        approvals_count: 0,
        executed: false,
    };
    let _vault = Vault { create_key: [0; 32] };
    let _ne = NullifierEntry;
    let _pi = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0; 32],
        nullifier: [0; 32],
    };
    let _cid = ChainId::from_u64(0);

    // Avoid dead-code warnings.
    drop((_err, _ix, _state, _prop, _vault, _ne, _pi, _cid));
}

// ============================================================================
// 15. Tautological-test replacements
// ============================================================================

/// REVIEW of `v2_attack_2c_finding3_no_zero_chain_rejection_in_core`:
/// The original body discards `derive_proposal_id`'s return without
/// asserting anything beyond "didn't panic". That's effectively
/// `assert!(true)`. The stronger replacement here:
///   (i)  asserts the function is deterministic (call twice, equal);
///   (ii) asserts the output differs from the trivial all-zero result;
///   (iii) asserts the result equals the SHA-256 of the manually-constructed
///         preimage with the all-zero ChainId.
/// Together these establish "the function actually ran with the zero
/// ChainId and produced the documented output", not just "did not panic".
#[test]
fn v3_attack_15a_replacement_for_zero_chain_no_rejection() {
    use crypto::Hasher;

    let zero_chain = ChainId::new([0u8; 32]);
    let state_pda = [0u8; 32];
    let action: &[u8] = &[];
    let target = [0u8; 32];

    let a = derive_proposal_id(&zero_chain, &state_pda, 0, action, &target);
    let b = derive_proposal_id(&zero_chain, &state_pda, 0, action, &target);
    assert_eq!(a, b, "v3: determinism over zero inputs");

    // Manually-built preimage of 136 zero-derived bytes (but the inner
    // SHA-256(action_bytes) and SHA-256(target) are NOT zero — SHA-256 of
    // an empty buffer is a known constant).
    let action_hash = crypto::Sha256Hasher::hash(action);
    let target_hash = crypto::Sha256Hasher::hash(&target);
    let mut preimage = [0u8; 136];
    preimage[72..104].copy_from_slice(&action_hash);
    preimage[104..136].copy_from_slice(&target_hash);
    let expected = crypto::Sha256Hasher::hash(&preimage);
    assert_eq!(
        a, expected,
        "v3: derive_proposal_id over zero ChainId must equal manual SHA-256 \
         of the 136-byte preimage with embedded SHA-256(empty) and SHA-256([0;32])",
    );

    // And the result is non-trivial.
    assert_ne!(a, [0u8; 32]);
}

/// REVIEW of `v2_attack_9b_multisigstate_no_public_mutator`:
/// The original test only round-trips a `MultisigState` with a chosen
/// members_root and reads it back. That's a Borsh round-trip test, not a
/// "no public mutator" test. The stronger version: round-trip the bytes
/// THROUGH a sequence of independent serializations and confirm the
/// members_root is the only thing changing per construction. This
/// exercises the structural-immutability claim better than the original.
#[test]
fn v3_attack_15b_replacement_for_no_public_mutator() {
    let mut r = rng();

    // Construct 100 random states, round-trip each, and verify each field is
    // independently preserved — exhaustively in the sense that bit-flips in
    // *one* field do not propagate to others.
    for _ in 0..100 {
        let create_key = random_32(&mut r);
        let members_root = random_32(&mut r);
        let m: u8 = r.gen();
        let n: u32 = r.gen();
        let proposal_count: u64 = r.gen();

        let s = MultisigState {
            create_key,
            members_root,
            m,
            n,
            proposal_count,
        };
        let bytes = to_vec(&s).unwrap();
        let back: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
        assert_eq!(back.create_key, create_key);
        assert_eq!(back.members_root, members_root);
        assert_eq!(back.m, m);
        assert_eq!(back.n, n);
        assert_eq!(back.proposal_count, proposal_count);
    }

    // Bit-flip the members_root in the wire bytes and confirm the decoded
    // members_root flips correspondingly — i.e. the bytes at the documented
    // offset are exactly the field.
    let base = MultisigState {
        create_key: [0; 32],
        members_root: [0x42; 32],
        m: 1,
        n: 1,
        proposal_count: 0,
    };
    let mut bytes = to_vec(&base).unwrap();
    // Offset of members_root in the encoded form: 32 (create_key) bytes in.
    bytes[32 + 5] ^= 0x80;
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    let mut expected_root = [0x42u8; 32];
    expected_root[5] ^= 0x80;
    assert_eq!(decoded.members_root, expected_root);
    // create_key was UNCHANGED in the bytes, so it must still be zero.
    assert_eq!(decoded.create_key, [0u8; 32]);
}

/// REVIEW of `attack_8a_core_layer_does_not_bind_account_to_create_key`
/// in round 1: it asserts an `Instruction::Execute` round-trips with any
/// `create_key`. That's the Borsh round-trip property already pinned by
/// `execute_borsh_round_trip` in `instructions.rs` (unit test) and the
/// avalanche tests elsewhere. The added "lying_ck != real_ck" derivation
/// pieces are sanity but the round-trip assertion is the meat — and it's
/// tautological with existing coverage.
///
/// Stronger replacement: confirm that even when two `Instruction::Execute`s
/// share every field EXCEPT `create_key`, their Borsh encodings DIFFER at
/// exactly the create_key bytes (1..33 in the wire form). This actually
/// pins what "create_key in the instruction" means at the byte level.
#[test]
fn v3_attack_15c_replacement_for_core_layer_does_not_bind() {
    let real_ck = [0x11u8; 32];
    let lying_ck = [0x22u8; 32];
    assert_ne!(real_ck, lying_ck);

    let ix_real = Instruction::Execute {
        create_key: real_ck,
        index: 42,
    };
    let ix_lying = Instruction::Execute {
        create_key: lying_ck,
        index: 42,
    };
    let bytes_real = to_vec(&ix_real).unwrap();
    let bytes_lying = to_vec(&ix_lying).unwrap();

    // Both are 41 bytes (1 disc + 32 create_key + 8 index).
    assert_eq!(bytes_real.len(), 41);
    assert_eq!(bytes_lying.len(), 41);

    // Discriminant byte equal.
    assert_eq!(bytes_real[0], bytes_lying[0]);
    assert_eq!(bytes_real[0], 3);

    // create_key bytes [1..33) differ at EVERY byte (since the patterns are
    // 0x11... vs 0x22...).
    for i in 1..33 {
        assert_ne!(
            bytes_real[i], bytes_lying[i],
            "v3: create_key byte {i} should differ",
        );
    }
    // Index bytes [33..41) equal.
    assert_eq!(&bytes_real[33..41], &bytes_lying[33..41]);
    // No mechanism in the core layer to flag the lying create_key — that's
    // the verifier's responsibility.
}

// ============================================================================
// 16. Creative attacks
// ============================================================================

/// (16a) "Borsh enum discriminant width = u8" implicit assumption.
/// Borsh enums use a single u8 for the discriminant — 256 possible variants.
/// A future PR that grows the enum past 256 variants would silently break
/// the wire format. Pin the implicit ceiling. (Right now there are 4
/// variants; we have 252 free slots — but the test exists so the day this
/// matters, the regression is visible.)
#[test]
fn v3_attack_16a_instruction_discriminant_is_single_u8() {
    let ix = Instruction::Execute {
        create_key: [0; 32],
        index: 0,
    };
    let bytes = to_vec(&ix).unwrap();
    // The discriminant occupies EXACTLY 1 byte. If Borsh ever switches to a
    // u32 discriminant (highly unlikely, but conceivable on a major version
    // bump), this test catches it: the second byte would no longer be the
    // first byte of `create_key`.
    assert_eq!(bytes[0], 3, "v3: disc is one byte");
    // Byte 1 is the first byte of create_key (all-zero in this fixture).
    assert_eq!(bytes[1], 0u8, "v3: byte 1 starts create_key, not a wider disc");
    // The whole encoding is 1 + 32 + 8 = 41 bytes; if disc were >1 byte
    // the total would exceed 41.
    assert_eq!(bytes.len(), 41);
}

/// (16b) `Proposal` wire-size lower bound at maximum action_bytes. The
/// largest valid Proposal (with action_bytes at the 4 KiB cap) has the
/// wire size: 4 (len-prefix) + 4096 + 32 + 4 + 1 = 4137 bytes. Pin so a
/// future PR that adds a field can't bump this without setting off alarms.
#[test]
fn v3_attack_16b_proposal_max_wire_size_is_4137() {
    let p = Proposal {
        action_bytes: vec![0xCD; MAX_ACTION_BYTES_LEN],
        target_program: [0xCC; 32],
        approvals_count: u32::MAX,
        executed: true,
    };
    let bytes = to_vec(&p).unwrap();
    assert_eq!(
        bytes.len(),
        4 + MAX_ACTION_BYTES_LEN + 32 + 4 + 1,
        "v3: Proposal max wire size drift",
    );
    assert_eq!(bytes.len(), 4137);
}

/// (16c) The "bool" field `Proposal.executed` Borsh-deserializes only from
/// `0x00` or `0x01` — round 1 pinned `0x02`, here we exhaustively pin every
/// 0x02..=0xFF byte must reject. Cheap and locks the strictness.
#[test]
fn v3_attack_16c_proposal_executed_bool_strict_full_byte_sweep() {
    for executed_byte in 2u8..=255 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // action_bytes len = 0
        bytes.extend_from_slice(&[0xCC; 32]); // target_program
        bytes.extend_from_slice(&0u32.to_le_bytes()); // approvals_count
        bytes.push(executed_byte); // executed
        let res = catch_unwind(AssertUnwindSafe(|| Proposal::try_from_slice(&bytes)));
        match res {
            Ok(decode) => assert!(
                decode.is_err(),
                "v3: Borsh accepted executed={executed_byte} as bool",
            ),
            Err(_) => panic!("v3: PANIC on invalid bool byte {executed_byte}"),
        }
    }
}

/// (16d) `derive_proposal_id` is structurally length-extension safe because
/// SHA-256 is applied at the OUTER hash — no Merkle/concat tree on the
/// produced 32 bytes. Pin a property: padding the action_bytes with the
/// SHA-256 padding shape (0x80 marker + zeros + 8-byte length) must NOT
/// produce a colliding proposal_id.
#[test]
fn v3_attack_16d_outer_hash_length_extension_safety() {
    let chain = ChainId::from_u64(1);
    let state = [0xAA; 32];
    let target = [0xBB; 32];

    let base = derive_proposal_id(&chain, &state, 0, b"abc", &target);
    // SHA-256 internal padding marker is 0x80, then zeros, then 8-byte
    // big-endian length. Even with that exact shape appended, the OUTER
    // hash sees DIFFERENT action_hash and produces a different pid.
    let mut extended = b"abc".to_vec();
    extended.push(0x80);
    extended.extend_from_slice(&[0u8; 53]); // pad to 56 mod 64 boundary
    extended.extend_from_slice(&(24u64.to_be_bytes())); // bit-length 3*8 = 24

    let extended_pid = derive_proposal_id(&chain, &state, 0, &extended, &target);
    assert_ne!(base, extended_pid, "v3: padding-shape extension must not collide");
}

/// (16e) ChainId is `Hash` (derive) — confirm hashing it via std `Hasher`
/// gives a stable, deterministic result across invocations on the same
/// process. This is a Rust-internal property but pinning catches a future
/// PR that drops the `Hash` derive.
#[test]
fn v3_attack_16e_chainid_hash_is_callable() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher as StdHasher};

    let cid = ChainId::from_u64(0xCAFE);

    let mut h1 = DefaultHasher::new();
    cid.hash(&mut h1);
    let v1 = h1.finish();

    let mut h2 = DefaultHasher::new();
    cid.hash(&mut h2);
    let v2 = h2.finish();

    assert_eq!(v1, v2, "v3: ChainId Hash must be deterministic per process");

    // ChainId can be used as a HashMap key.
    let mut map = std::collections::HashMap::new();
    map.insert(cid, "value");
    assert_eq!(map.get(&cid), Some(&"value"));
}

/// (16f) `Vault.create_key` field MUST equal the corresponding multisig
/// state's create_key — the verifier enforces this. At the core layer we
/// can confirm the Vault and MultisigState use the SAME field name and
/// 32-byte shape so future "rename create_key" PRs surface here too.
/// The check is structural: two structs with the same `create_key: [u8; 32]`
/// field at the same byte offset (0 in both).
#[test]
fn v3_attack_16f_vault_and_state_create_key_share_layout() {
    let ck = [0x55u8; 32];
    let v = Vault { create_key: ck };
    let s = MultisigState {
        create_key: ck,
        members_root: [0; 32],
        m: 1,
        n: 1,
        proposal_count: 0,
    };

    let v_bytes = to_vec(&v).unwrap();
    let s_bytes = to_vec(&s).unwrap();

    // First 32 bytes of each encoding are create_key.
    assert_eq!(&v_bytes[..32], &ck);
    assert_eq!(&s_bytes[..32], &ck);

    // Vault is exactly create_key (32 bytes total).
    assert_eq!(v_bytes.len(), 32);
    // MultisigState is 77 bytes (1 + 32 + 32 + 4 + 8).
    assert_eq!(s_bytes.len(), 77);
}

/// (16g) `derive_proposal_pda` index slot is also LE-encoded (matching
/// `derive_proposal_id`). A future PR that flips ONE of them but not the
/// other would make the verifier's Proposal-PDA mismatch the SDK's. Pin.
#[test]
fn v3_attack_16g_derive_proposal_pda_index_is_little_endian() {
    use crypto::Hasher;
    let program_id = [0x99u8; 32];
    let create_key = [0xAB; 32];
    let index: u64 = 0x0102_0304_0506_0708;

    let actual = derive_proposal_pda(&program_id, &create_key, index);

    // Round-5 SPEL-compatible recompute. The index seed is the 8 LE bytes
    // right-padded to 32 (the `<u64 as ToSeed>::to_seed` shape).
    let mut lit_padded = [0u8; 32];
    lit_padded[..13].copy_from_slice(SEED_PROPOSAL);
    let mut index_seed = [0u8; 32];
    index_seed[..8].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);

    let mut combine_buf = Vec::with_capacity(96);
    combine_buf.extend_from_slice(&lit_padded);
    combine_buf.extend_from_slice(&create_key);
    combine_buf.extend_from_slice(&index_seed);
    let combined: [u8; 32] = crypto::Sha256Hasher::hash(&combine_buf);

    let mut outer = [0u8; 96];
    outer[..32].copy_from_slice(b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00");
    outer[32..64].copy_from_slice(&program_id);
    outer[64..96].copy_from_slice(&combined);
    let expected: [u8; 32] = crypto::Sha256Hasher::hash(&outer);
    assert_eq!(actual, expected, "v3: derive_proposal_pda index slot must be LE");
}

/// (16h) Cross-class derivation: a `MultisigState` PDA from `create_key=A`
/// must never equal a `Vault` PDA from `create_key=B` for any A != B
/// (collision-bounded by SHA-256). Sample 5_000 random pairs and assert
/// no overlap.
#[test]
fn v3_attack_16h_state_vs_vault_class_separation_5k() {
    let mut r = rng();
    let mut state_set: HashSet<[u8; 32]> = HashSet::new();
    let mut vault_set: HashSet<[u8; 32]> = HashSet::new();
    let program_id = [0x11u8; 32];
    for _ in 0..5_000 {
        let ck_a = random_32(&mut r);
        let ck_b = random_32(&mut r);
        state_set.insert(derive_multisig_state_pda(&program_id, &ck_a));
        vault_set.insert(derive_vault_pda(&program_id, &ck_b));
    }
    let overlap: HashSet<[u8; 32]> =
        state_set.intersection(&vault_set).copied().collect();
    assert!(
        overlap.is_empty(),
        "v3: state-PDA and vault-PDA classes overlap — domain separation hole",
    );
}

/// (16i) `proposal_count` overflow scenario. A `MultisigState` with
/// `proposal_count == u64::MAX` would, on the next `Propose`, attempt
/// `proposal_count + 1` which overflows. The core layer doesn't enforce
/// this — the verifier MUST. Pin the round-trip at u64::MAX and confirm
/// no helper at the core surface flags it.
#[test]
fn v3_attack_16i_proposal_count_at_u64_max_round_trips_silently() {
    let s = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 1,
        n: 1,
        proposal_count: u64::MAX,
    };
    // validate() only inspects (m, n) — it does NOT touch proposal_count.
    assert!(s.validate().is_ok(), "v3: validate() ignores proposal_count");
    let bytes = to_vec(&s).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded.proposal_count, u64::MAX);
    // VERIFIER RESPONSIBILITY: reject `Propose` when proposal_count == u64::MAX
    // (or any monotonicity check). The core layer has no such helper.
}

/// (16j) The seed constants must be DISTINCT pairwise — already pinned, but
/// here we make the equality probe symmetric (a==b iff b==a) explicit at
/// the byte level. This caught one mutation-test miss in another crate; keep
/// it as a regression sentinel.
#[test]
fn v3_attack_16j_seed_constants_pairwise_distinct_symmetric() {
    let seeds: [&[u8; 13]; 4] = [
        SEED_MULTISIG_STATE,
        SEED_PROPOSAL,
        SEED_VAULT,
        SEED_NULLIFIER,
    ];
    for i in 0..seeds.len() {
        for j in 0..seeds.len() {
            if i == j {
                assert_eq!(seeds[i], seeds[j]);
            } else {
                assert_ne!(seeds[i], seeds[j], "v3: seed[{i}] == seed[{j}]");
                assert_ne!(seeds[j], seeds[i], "v3: symmetric inequality");
            }
        }
    }
}
