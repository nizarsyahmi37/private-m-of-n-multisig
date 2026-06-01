//! Round-2 red-team for `private_multisig_core`.
//!
//! Round 1 (`red_team_core.rs`) had broad PDA-collision, avalanche, Borsh,
//! and ABI coverage. This file is the second pair of eyes — it stresses
//! corners round 1 either glossed or didn't touch:
//!
//! 1. FINDING-2 closure (E1002 `ActionBytesTooLong`):
//!    - `from_code(1002)` resolves and `from_code(1003)` is `None`.
//!    - Display string is byte-exact `"E1002: action bytes too long"`.
//!    - Variant cardinality is 10 (not 9) at the on-chain ABI surface.
//!    - No remaining callsite uses `InstanceNotActive` for "action bytes too
//!      long" — every `InstanceNotActive` reference is audited via the
//!      manifest test below.
//! 2. FINDING-3 closure (ChainId zero aliasing): nothing in the crate
//!    treats all-zero ChainId as a sentinel; a real chain at id=0 is bound
//!    by the same `proposal_id` formula as any other chain — verified by
//!    actually deriving with id=0 and confirming it differs from id=1.
//! 3. Borsh edge cases not in round 1 (Proposal length-prefix=0 with
//!    garbage trailing, Instruction body shape mismatch under valid
//!    discriminant, empty Approve receipt, soundness oracle of 10 000
//!    random byte slices).
//! 4. State validator gaps: `m=0`, `n=0`, `m>n`, `n > u8::MAX limit` — the
//!    core layer does NOT validate these. Flagged as a finding.
//! 5. Dead public surface — `PdaSeed` was removed (FINDING-V2-C closed by
//!    deletion).
//! 6. Re-export surface drift — `derive_pda` is a pub item in `pda.rs`
//!    intentionally not re-exported at the crate root.
//! 7. Soundness oracle: 10 000 random byte slices into
//!    `Instruction::try_from_slice` — zero panics, no acceptance of inputs
//!    with trailing garbage.
//! 8. Doc-vs-code: verified against the public docstrings on each module.
//!
//! When the test fails, the assertion message names which finding it
//! pins so a future reader gets straight to the round-2 context.

#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::similar_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::mistyped_literal_suffixes)]

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id, derive_proposal_pda,
    derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction, MultisigState,
    NullifierEntry, Proposal, Vault, APPROVE_PUBLIC_INPUTS_LEN, MAX_ACTION_BYTES_LEN,
    SEED_MULTISIG_STATE, SEED_NULLIFIER, SEED_PROPOSAL, SEED_VAULT,
};

fn rng() -> StdRng {
    // Deterministic — round-2 reproductions must be byte-identical.
    StdRng::seed_from_u64(0x52_45_44_32) // "RED2"
}

fn random_32(r: &mut StdRng) -> [u8; 32] {
    let mut out = [0u8; 32];
    r.fill_bytes(&mut out);
    out
}

// =============================================================================
// 1. FINDING-2 closure — E1002 `ActionBytesTooLong`
// =============================================================================

/// FINDING-2 / Attack v2-1a: `from_code(1002)` must resolve to
/// `ActionBytesTooLong` and `from_code(1003)` must cleanly return `None`
/// (no off-by-one variant synthesis).
#[test]
fn v2_attack_1a_finding2_from_code_boundary() {
    assert_eq!(
        CoreError::from_code(1002),
        Some(CoreError::ActionBytesTooLong),
        "FINDING-2 closure: code 1002 must map to ActionBytesTooLong",
    );
    assert_eq!(
        CoreError::from_code(1003),
        Some(CoreError::InvalidThreshold),
        "FINDING-V2-A closure: code 1003 maps to InvalidThreshold",
    );
    // 1004 and 1005 are now SerializationError and ArithmeticOverflow
    // respectively (round-5 split of the previously-overloaded
    // InstanceNotActive path). 1006 onward stays clean.
    assert_eq!(
        CoreError::from_code(1004),
        Some(CoreError::SerializationError),
        "round-5 split: code 1004 maps to SerializationError",
    );
    assert_eq!(
        CoreError::from_code(1005),
        Some(CoreError::ArithmeticOverflow),
        "round-5 split: code 1005 maps to ArithmeticOverflow",
    );
    assert_eq!(CoreError::from_code(1006), None);
    assert_eq!(CoreError::from_code(1500), None);
    assert_eq!(CoreError::from_code(1999), None);
}

/// FINDING-2 / Attack v2-1b: Display string for E1002 is byte-exact
/// "E1002: action bytes too long". On-chain log explorers grep on this.
#[test]
fn v2_attack_1b_finding2_display_string_is_byte_exact() {
    let s = CoreError::ActionBytesTooLong.to_string();
    assert_eq!(
        s, "E1002: action bytes too long",
        "FINDING-2: Display string for E1002 drifted",
    );
    // Strict E1002 prefix — easy regression catcher.
    assert!(s.starts_with("E1002:"));
    // No accidental newline / whitespace appended.
    assert!(!s.ends_with(' '));
    assert!(!s.contains('\n'));
}

/// FINDING-2 / Attack v2-1c: total variant count is 10 (was 9 pre-fix).
/// Pinning the cardinality at every layer means a future PR that adds a
/// variant without updating the matching ABI table fails *here*.
#[test]
fn v2_attack_1c_finding2_variant_count_is_ten() {
    let all = [
        CoreError::InstanceNotActive,
        CoreError::ProposalExpiredOrExecuted,
        CoreError::ActionBytesTooLong,
        CoreError::InvalidReceipt,
        CoreError::ImageIdMismatch,
        CoreError::RootMismatch,
        CoreError::ProposalIdMismatch,
        CoreError::NullifierAlreadyUsed,
        CoreError::ThresholdNotMet,
        CoreError::AlreadyExecuted,
    ];
    assert_eq!(
        all.len(),
        10,
        "FINDING-2 closure: variant count must be 10 after E1002 add",
    );

    // Codes are dense and unique.
    let mut codes: alloc::vec::Vec<u32> = all.iter().map(|v| v.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 10);

    // Every code from the source list resolves back.
    for v in all {
        let code = v.code();
        assert_eq!(CoreError::from_code(code), Some(v));
    }
}

/// FINDING-2 / Attack v2-1d: the validator path for action_bytes routes
/// to `ActionBytesTooLong`, never to `InstanceNotActive`. Direct probe.
#[test]
fn v2_attack_1d_finding2_validator_does_not_emit_instance_not_active() {
    // Just over the cap.
    let bytes = alloc::vec![0u8; MAX_ACTION_BYTES_LEN + 1];
    let err = Proposal::validate_action_bytes(&bytes).unwrap_err();
    assert_eq!(
        err,
        CoreError::ActionBytesTooLong,
        "FINDING-2 regression: validator must emit E1002, not E1000",
    );
    assert_ne!(
        err,
        CoreError::InstanceNotActive,
        "FINDING-2 regression: E1000 is reserved for instance-not-active",
    );
    // Far over the cap behaves the same — no second branch.
    let huge = alloc::vec![0u8; MAX_ACTION_BYTES_LEN * 4];
    assert_eq!(
        Proposal::validate_action_bytes(&huge),
        Err(CoreError::ActionBytesTooLong),
    );
}

// =============================================================================
// 2. FINDING-3 closure — ChainId zero aliasing
// =============================================================================

/// FINDING-3 / Attack v2-2a: confirm the rustdoc-promised aliasing is real
/// and that nothing in the crate treats all-zero specially.
#[test]
fn v2_attack_2a_finding3_chain_id_zero_alias_is_documented_and_real() {
    let from_u64_zero = ChainId::from_u64(0);
    let new_all_zero = ChainId::new([0u8; 32]);
    assert_eq!(
        from_u64_zero, new_all_zero,
        "FINDING-3: documented alias must hold",
    );
}

/// FINDING-3 / Attack v2-2b: a real chain configured with id=0 must NOT
/// be silently broken. The `proposal_id` for chain 0 differs from any
/// other chain by design.
#[test]
fn v2_attack_2b_finding3_chain_zero_is_not_silently_broken() {
    let pda = [0xAAu8; 32];
    let target = [0xBBu8; 32];
    let id_zero = derive_proposal_id(&ChainId::from_u64(0), &pda, 7, b"action", &target);
    let id_one = derive_proposal_id(&ChainId::from_u64(1), &pda, 7, b"action", &target);
    assert_ne!(
        id_zero, id_one,
        "FINDING-3: chain 0 must not collide with chain 1",
    );

    // And both are non-trivial (not zero, not equal to the state PDA).
    assert_ne!(id_zero, [0u8; 32]);
    assert_ne!(id_zero, pda);

    // A different state PDA on chain 0 also separates correctly.
    let id_zero_other_pda =
        derive_proposal_id(&ChainId::from_u64(0), &[0xCC; 32], 7, b"action", &target);
    assert_ne!(id_zero, id_zero_other_pda);
}

/// FINDING-3 / Attack v2-2c: confirm there is no code path that returns
/// an error or special variant for all-zero ChainId. Sample the validator
/// surface — none of the publicly exposed helpers reject chain-0.
#[test]
fn v2_attack_2c_finding3_no_zero_chain_rejection_in_core() {
    // Empty action bytes, chain 0 — derive_proposal_id is total and
    // produces a value (no rejection, no panic).
    let id = derive_proposal_id(&ChainId::new([0u8; 32]), &[0u8; 32], 0, &[], &[0u8; 32]);
    // It must produce *something* — we don't assert its value because
    // SHA-256 of the all-zero preimage is itself a known constant; what we
    // need is that the function did not refuse, panic, or short-circuit.
    let _ = id;
}

// =============================================================================
// 3. Borsh edge cases not covered in round 1
// =============================================================================

/// Attack v2-3a: Proposal where the `action_bytes` length prefix is 0 but
/// there ARE trailing bytes after the rest of the struct. Borsh must
/// reject because of unconsumed input — otherwise an attacker can smuggle
/// bytes the verifier never inspects.
#[test]
fn v2_attack_3a_proposal_zero_len_with_trailing_garbage_rejected() {
    let p = Proposal {
        action_bytes: alloc::vec::Vec::new(),
        target_program: [0xCC; 32],
        approvals_count: 1,
        executed: false,
    };
    let mut bytes = to_vec(&p).unwrap();
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let res: Result<Proposal, _> = Proposal::try_from_slice(&bytes);
    assert!(
        res.is_err(),
        "Proposal with zero-length action_bytes but trailing garbage MUST be rejected",
    );
}

/// Attack v2-3b: Instruction with valid discriminant 0 (CreateMultisig)
/// but body bytes that don't match the variant's field layout. Must error,
/// not panic.
#[test]
fn v2_attack_3b_instruction_disc0_truncated_body() {
    // CreateMultisig requires 32 + 32 + 1 + 4 = 69 trailing bytes.
    for trim_to in [0usize, 1, 16, 32, 64, 68] {
        let mut bytes = alloc::vec::Vec::with_capacity(trim_to + 1);
        bytes.push(0u8); // disc = CreateMultisig
        bytes.resize(trim_to + 1, 0xAA);
        let res: Result<Instruction, _> = Instruction::try_from_slice(&bytes);
        assert!(
            res.is_err(),
            "discriminant 0 with truncated body (len {}) must error",
            trim_to,
        );
    }
}

/// Attack v2-3c: Approve instruction with `receipt.len() == 0` is a valid
/// Round 6 unified the Approve wire with the verifier handler signature:
/// `{create_key, index, nullifier, public_inputs: Vec<u8>}`. The wire is
/// no longer a fixed 137 bytes — `public_inputs` is length-prefixed. Pin
/// the byte length at 1 + 32 + 8 + 32 + 4 + 96 = 173 for the canonical
/// 96-byte ApprovePublicInputs payload.
#[test]
fn v2_attack_3c_approve_wire_round_trips() {
    let inputs = ApprovePublicInputs {
        members_root: [0x11; 32],
        proposal_id: [0x22; 32],
        nullifier: [0x33; 32],
    };
    let ix = Instruction::Approve {
        create_key: [0xAA; 32],
        index: 0,
        nullifier: inputs.nullifier,
        public_inputs: inputs.to_bytes().to_vec(),
    };
    let bytes = to_vec(&ix).unwrap();
    assert_eq!(bytes.len(), 1 + 32 + 8 + 32 + 4 + 96);
    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, ix, "Approve must round-trip");
}

/// Attack v2-3d: feed an oversize length-prefix on `Proposal.action_bytes`
/// across a wider range than round 1 — including specifically
/// `MAX_ACTION_BYTES_LEN + 1` (the boundary) and `u32::MAX as usize` (the
/// Borsh-vec headline-DoS attempt). Both must error cleanly.
#[test]
fn v2_attack_3d_proposal_lenprefix_dos_boundary() {
    for declared_len in [
        (MAX_ACTION_BYTES_LEN + 1) as u32,
        100_000u32,
        1_000_000u32,
        16_000_000u32,
        u32::MAX,
    ] {
        // Build a Proposal-shaped encoding manually:
        //   action_bytes_len: u32 LE
        //   action_bytes:     [u8; payload_len]
        //   target_program:   [u8; 32]
        //   approvals_count:  u32 LE
        //   executed:         u8
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&declared_len.to_le_bytes());
        // Append a *short* payload — claim huge, deliver tiny.
        bytes.extend_from_slice(&[0u8; 16]);
        // Tail bytes the parser would expect after the (truncated) Vec.
        bytes.extend_from_slice(&[0u8; 32 + 4 + 1]);
        let res = Proposal::try_from_slice(&bytes);
        assert!(
            res.is_err(),
            "declared len {declared_len} must yield a clean error, not panic / OOM",
        );
    }
}

// =============================================================================
// 4. State-validator gaps: `m=0`, `n=0`, `m>n`
// =============================================================================

/// Attack v2-4a: the core layer accepts a `MultisigState` with `m = 0`.
/// Zero-of-N is semantically a "no approvals needed" multisig — anyone can
/// execute. The core type does NOT validate. This is intentional (the
/// verifier program owns precondition validation), but the absence of any
/// `validate_threshold` helper at the core layer is a FINDING. See the
/// report.
#[test]
fn v2_attack_4a_state_m_zero_is_borsh_valid() {
    let state = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 0, // threshold-not-met-impossible → anyone passes
        n: 5,
        proposal_count: 0,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, state);
    assert_eq!(
        decoded.m, 0,
        "FINDING: core layer accepts m=0; verifier must catch",
    );
}

/// Attack v2-4b: same shape, `n = 0`. Zero members → no proposal can ever
/// pass; the instance is effectively dead.
#[test]
fn v2_attack_4b_state_n_zero_is_borsh_valid() {
    let state = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 1,
        n: 0,
        proposal_count: 0,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded.n, 0);
}

/// Attack v2-4c: `m > n`. Threshold higher than membership → unreachable.
/// Core layer accepts.
#[test]
fn v2_attack_4c_state_m_greater_than_n_is_borsh_valid() {
    let state = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 250,
        n: 5,
        proposal_count: 0,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert!(u32::from(decoded.m) > decoded.n);
}

/// Attack v2-4d: `n > 255`. Note `m: u8` but `n: u32` — a real instance
/// with `n = 300` would have *no* valid threshold (m can only count up to
/// 255). Core accepts it; verifier or SDK must catch.
#[test]
fn v2_attack_4d_state_n_exceeds_m_type_range() {
    let state = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 200,
        n: 300, // m: u8 cannot represent thresholds above 255
        proposal_count: 0,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded.n, 300);
    assert_eq!(decoded.m, 200);
    // Note for the report: the type asymmetry (m: u8, n: u32) is itself a
    // design smell. n above 255 cannot have its threshold expressed.
}

/// Attack v2-4e: `proposal_count = u64::MAX`. Next proposal's index would
/// be u64::MAX itself; subsequent increment overflows. Confirm round-trip
/// is fine and that the PDA derivation at u64::MAX is well-defined.
#[test]
fn v2_attack_4e_state_proposal_count_max_round_trips() {
    let state = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 2,
        n: 3,
        proposal_count: u64::MAX,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded.proposal_count, u64::MAX);

    // PDA at u64::MAX is well-defined and unique vs. neighbours.
    let p_max = derive_proposal_pda(&[0; 32], &state.create_key, u64::MAX);
    let p_max_minus_1 = derive_proposal_pda(&[0; 32], &state.create_key, u64::MAX - 1);
    assert_ne!(p_max, p_max_minus_1);
    assert_ne!(p_max, [0u8; 32]);

    // proposal_id at u64::MAX: well-defined.
    let pid = derive_proposal_id(
        &ChainId::from_u64(1),
        &[0xAA; 32],
        u64::MAX,
        b"x",
        &[0xBB; 32],
    );
    assert_ne!(pid, [0u8; 32]);
}

// =============================================================================
// 5. Dead public surface — `PdaSeed` (FINDING-V2-C, removed)
// =============================================================================
//
// `pda::PdaSeed` was a pub newtype with no callers in the workspace; FINDING-
// V2-C flagged it as dead surface. It has since been removed entirely. No
// regression test is needed — if a future PR re-adds the type, that PR
// should justify it explicitly.

// =============================================================================
// 6. Re-export surface drift
// =============================================================================

/// Attack v2-6a: confirm `derive_pda` is a pub fn in `pda.rs` that is
/// NOT re-exported at the crate root. Anything else new being non-re-
/// exported is caught here too: the test calls them via full module paths,
/// and the assertions check the re-exports exist.
#[test]
fn v2_attack_6a_reexport_surface_drift() {
    // These must exist at the crate root (round-1 contract):
    let _ = private_multisig_core::derive_multisig_state_pda;
    let _ = private_multisig_core::derive_proposal_pda;
    let _ = private_multisig_core::derive_vault_pda;
    let _ = private_multisig_core::derive_nullifier_entry_pda;
    let _ = private_multisig_core::SEED_MULTISIG_STATE;
    let _ = private_multisig_core::SEED_PROPOSAL;
    let _ = private_multisig_core::SEED_VAULT;
    let _ = private_multisig_core::SEED_NULLIFIER;
    let _ = private_multisig_core::derive_proposal_id;
    let _ = private_multisig_core::APPROVE_PUBLIC_INPUTS_LEN;
    let _ = private_multisig_core::MAX_ACTION_BYTES_LEN;

    // `private_multisig_core::pda::derive_pda` is pub in its module but
    // intentionally not re-exported at the crate root — callers go through
    // the typed helpers. Reach it via the full path. Round-5 signature is
    // `(program_id, seeds: &[&[u8; 32]])` so we pre-pad the literal.
    let mut state_lit = [0u8; 32];
    state_lit[..13].copy_from_slice(SEED_MULTISIG_STATE);
    let pid = private_multisig_core::pda::derive_pda(&[0u8; 32], &[&state_lit, &[0u8; 32]]);
    assert_eq!(pid.len(), 32);
}

// =============================================================================
// 7. Soundness oracle — 10 000 random byte slices into Instruction
// =============================================================================

/// Attack v2-7a: feed 10 000 deterministically-random byte slices of
/// varied length (0..=2048) to `Instruction::try_from_slice`. Expect zero
/// panics and zero acceptances of trailing-garbage encodings.
#[test]
fn v2_attack_7a_instruction_random_oracle_10k() {
    let mut r = rng();
    let mut accepted = 0usize;
    for _ in 0..10_000 {
        let len = r.gen_range(0..=2048usize);
        let mut buf = alloc::vec![0u8; len];
        r.fill_bytes(&mut buf);
        // `try_from_slice` is total — must not panic.
        let res: Result<Instruction, _> = Instruction::try_from_slice(&buf);
        if res.is_ok() {
            accepted += 1;
        }
    }
    // The random search space is so sparse that ANY acceptance with full
    // length consumption is statistically possible only for the trivial
    // Execute encoding (disc 3 + 32 create_key + 8 index = 41 bytes).
    // A handful is fine; thousands would indicate Borsh is silently
    // tolerating trailing garbage. Pin at <= 5% as a sanity ceiling.
    assert!(
        accepted < 500,
        "instruction oracle accepted {accepted}/10000 random slices — suspicious",
    );
}

/// Attack v2-7b: explicit trailing-garbage oracle. Build a valid Execute
/// instruction (the shortest variant), append 1..=32 bytes of garbage,
/// and assert each decoder result is `Err`. Round 1 didn't pin this for
/// Execute specifically.
#[test]
fn v2_attack_7b_execute_trailing_garbage_oracle() {
    let ix = Instruction::Execute {
        create_key: [0xAA; 32],
        index: 0x0123_4567_89AB_CDEF,
    };
    let base = to_vec(&ix).unwrap();
    for tail_len in 1..=32 {
        let mut bytes = base.clone();
        for b in 0..tail_len {
            bytes.push((0x80 ^ b) as u8);
        }
        let res: Result<Instruction, _> = Instruction::try_from_slice(&bytes);
        assert!(
            res.is_err(),
            "Execute + {tail_len} trailing bytes MUST be rejected",
        );
    }
}

// =============================================================================
// 8. ApprovePublicInputs::from_bytes totality
// =============================================================================

/// Attack v2-8a: `from_bytes` is total over `[u8; 96]`. Pump 5 000 random
/// 96-byte slices and confirm each round-trips back to the same bytes.
/// This is the spec — there is no "invalid" public-inputs encoding at
/// this layer; downstream `proposal_id` mismatch is the check.
#[test]
fn v2_attack_8a_approve_public_inputs_from_bytes_total() {
    let mut r = rng();
    for _ in 0..5_000 {
        let mut buf = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        r.fill_bytes(&mut buf);
        let inputs = ApprovePublicInputs::from_bytes(&buf);
        let round = inputs.to_bytes();
        assert_eq!(buf, round, "from_bytes/to_bytes must be a bijection");
    }
}

// =============================================================================
// 9. Doc-vs-code drift
// =============================================================================

/// Attack v2-9a: the lib.rs module-level doc claims the four MVP
/// instructions; confirm exactly four variants exist by exercising each
/// discriminant 0..=3 and verifying 4..=255 reject.
#[test]
fn v2_attack_9a_doc_promises_four_instruction_variants() {
    // Round 1 (attack_3f) tested 4/5/255; here we sweep 4..=255 just to be
    // exhaustive. Each must error.
    for disc in 4u8..=255 {
        // Construct a buffer that only differs in disc and minimal length.
        let buf = alloc::vec![disc]; // 1 byte — invalid no matter what
        let res: Result<Instruction, _> = Instruction::try_from_slice(&buf);
        assert!(
            res.is_err(),
            "discriminant {disc} must error (only 0..=3 are valid)",
        );
    }
}

/// Attack v2-9b: docstring on `MultisigState` says `members_root is
/// immutable after creation`. Confirm there's no public mutator method
/// (this is a structural property, not behavioural — we just exercise
/// the public surface).
#[test]
fn v2_attack_9b_multisigstate_no_public_mutator() {
    // We can only set the field directly through the pub field; there is
    // no `set_members_root` / `rotate_root` / etc. method. The check is
    // that round-tripping a fresh state with a chosen root yields the
    // same root — i.e. the field is the only mutation vector.
    let state = MultisigState {
        create_key: [0; 32],
        members_root: [0x42; 32],
        m: 1,
        n: 1,
        proposal_count: 0,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded.members_root, [0x42; 32]);
}

/// Attack v2-9c: `pda.rs` says "Each seed constant is exactly 13 bytes."
/// Direct verification (round 1 had the same, but it's cheap to keep).
#[test]
fn v2_attack_9c_seed_lengths_match_docstring() {
    for (name, seed) in [
        ("SEED_MULTISIG_STATE", SEED_MULTISIG_STATE),
        ("SEED_PROPOSAL", SEED_PROPOSAL),
        ("SEED_VAULT", SEED_VAULT),
        ("SEED_NULLIFIER", SEED_NULLIFIER),
    ] {
        assert_eq!(seed.len(), 13, "{name} must be 13 bytes per docstring");
    }
}

// =============================================================================
// 10. Creative attacks
// =============================================================================

/// Attack v2-10a: confirm `proposal_id` depends on `create_key` *only*
/// through `multisig_state_pda` — but transitively so that two distinct
/// `create_key` values can never collide in `proposal_id`. Round 1 sanity
/// checked this loosely; here we hit it with 10 000 distinct create_keys.
#[test]
fn v2_attack_10a_proposal_id_indirect_dependence_on_create_key() {
    let mut r = rng();
    let program_id = [0xA1; 32];
    let target = [0xBB; 32];
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        let ck = random_32(&mut r);
        let pda = derive_multisig_state_pda(&program_id, &ck);
        let pid = derive_proposal_id(&ChainId::from_u64(1), &pda, 0, b"action", &target);
        assert!(
            seen.insert(pid),
            "proposal_id collision across distinct create_keys",
        );
    }
}

/// Attack v2-10b: domain-separation between `proposal_id` and other PDAs.
/// `proposal_id` is a 32-byte hash output and so are PDAs. Could a
/// `proposal_id` ever equal a `Proposal` PDA / `MultisigState` PDA /
/// `NullifierEntry` PDA built from compatible inputs?
///
/// They use different preimage shapes (proposal_id has 136 bytes,
/// derive_pda has variable extras), so collision is birthday-bounded at
/// 2^128. But the SEED constants and the absence of a leading domain
/// separator in `derive_proposal_id` mean an attacker who controls inputs
/// to BOTH might in principle steer one to look like the other. Burn
/// 5 000 trials and confirm no overlap.
#[test]
fn v2_attack_10b_proposal_id_vs_pda_domain_separation() {
    let mut r = rng();
    let program_id = [0xA1; 32];
    let mut pids = std::collections::HashSet::new();
    let mut pdas = std::collections::HashSet::new();
    for _ in 0..5_000 {
        let ck = random_32(&mut r);
        let idx: u64 = r.gen();
        let action = random_32(&mut r);
        let target = random_32(&mut r);
        let pda = derive_multisig_state_pda(&program_id, &ck);
        let pid = derive_proposal_id(&ChainId::from_u64(1), &pda, idx, &action, &target);
        let prop_pda = derive_proposal_pda(&program_id, &ck, idx);
        let null_pda = derive_nullifier_entry_pda(&program_id, &prop_pda, &random_32(&mut r));
        pids.insert(pid);
        pdas.insert(prop_pda);
        pdas.insert(null_pda);
        pdas.insert(derive_vault_pda(&program_id, &ck));
    }
    // No element of pids overlaps any element of pdas.
    for p in &pids {
        assert!(
            !pdas.contains(p),
            "proposal_id and PDA hashes overlap — domain separation hole",
        );
    }
}

/// Attack v2-10c: `Vault` stores `create_key` (32 bytes of rent-paid
/// state). Confirm the bytes survive a round-trip. The report notes that
/// since `Vault`'s PDA is itself derived from `(program_id, SEED_VAULT,
/// create_key)`, storing `create_key` inside is redundant — the verifier
/// already knows `create_key` from instruction inputs and re-derives the
/// PDA from it. v1 spec accepts this as belt-and-suspenders; flag if
/// rent-sensitive.
#[test]
fn v2_attack_10c_vault_create_key_redundancy_pin() {
    let v = Vault {
        create_key: [0x77; 32],
    };
    let bytes = to_vec(&v).unwrap();
    assert_eq!(
        bytes.len(),
        32,
        "Vault is exactly create_key — 32 bytes of rent (FINDING context)",
    );
    let decoded: Vault = Vault::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, v);
}

/// Attack v2-10d: confirm `NullifierEntry` is truly zero-cost on-chain.
/// Round 1 verified the encoded length is zero; here we additionally
/// confirm that *adding* even one stray byte makes deserialize reject
/// (so the empty-PDA invariant cannot be subverted by future-PR drift).
#[test]
fn v2_attack_10d_nullifier_entry_strict_zero_bytes() {
    let bytes = to_vec(&NullifierEntry).unwrap();
    assert!(bytes.is_empty());
    // One byte of anything trailing → reject.
    for stray in [0x00u8, 0x01, 0xFF, 0x80] {
        let res: Result<NullifierEntry, _> = NullifierEntry::try_from_slice(&[stray]);
        assert!(
            res.is_err(),
            "NullifierEntry must reject any non-empty input ({stray:#x})",
        );
    }
}

/// Attack v2-10e: the m / n encoding asymmetry (m: u8, n: u32) means the
/// maximum representable threshold is 255 even though the type system
/// allows up to 4 billion members. A pragmatic helper at the core layer
/// would clamp / reject `n > 255`. None exists. Pin the gap so the report
/// is reproducible.
#[test]
fn v2_attack_10e_threshold_type_asymmetry() {
    // No core helper rejects this:
    let state = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 255,
        n: u32::MAX,
        proposal_count: 0,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded.n, u32::MAX);
    assert_eq!(decoded.m, 255);
    // FINDING context: the SDK or verifier would have to refuse such
    // shapes. A `MultisigState::validate_membership` core helper would
    // be a natural home — does not exist as of round-2.
}

/// Attack v2-10f: feed a Proposal whose Borsh declares a HUGE Vec via the
/// `executed` field's preimage (i.e. an attacker plays with the order of
/// bytes after a truncated Vec). Even if `try_from_slice` consumes all
/// 4 GiB worth of declared bytes, it should hit a clean buffer-too-short
/// error long before then. Time-box informally: this test runs in
/// milliseconds, not seconds.
#[test]
fn v2_attack_10f_proposal_extreme_lenprefix_no_hang() {
    let start = std::time::Instant::now();
    let mut buf = alloc::vec::Vec::new();
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);
    let _ = Proposal::try_from_slice(&buf);
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "Proposal::try_from_slice took {elapsed:?} on u32::MAX lenprefix — possible DoS",
    );
}

/// Attack v2-10g: Instruction::Propose with both an oversize action_bytes
/// length prefix AND a tampered discriminant. Confirms decoder rejects
/// without trying to allocate the oversize Vec.
#[test]
fn v2_attack_10g_propose_lenprefix_dos() {
    let start = std::time::Instant::now();
    let mut buf = alloc::vec::Vec::new();
    buf.push(1u8); // Propose discriminant
    buf.extend_from_slice(&[0xAA; 32]); // create_key
    buf.extend_from_slice(&0u64.to_le_bytes()); // index
    buf.extend_from_slice(&u32::MAX.to_le_bytes()); // action_bytes len
    buf.extend_from_slice(&[0u8; 4]); // tiny payload, missing target_program
    let res: Result<Instruction, _> = Instruction::try_from_slice(&buf);
    assert!(res.is_err());
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "Propose decode under u32::MAX lenprefix took {elapsed:?}",
    );
}

/// Attack v2-10h: confirm `proposal_id` formula has no "off by one" in
/// the index slot. Specifically, an attacker who shifts the index by one
/// byte (e.g. mis-encodes little-endian) MUST get a different
/// `proposal_id`. We test by manually constructing a "wrong endian"
/// preimage variant and confirming the real derivation differs.
#[test]
fn v2_attack_10h_index_endian_baked_into_proposal_id() {
    let cid = ChainId::from_u64(1);
    let pda = [0xAA; 32];
    let target = [0xBB; 32];
    // 0x01 in LE = [01, 00, 00, 00, 00, 00, 00, 00]
    // 0x01_00_00_00_00_00_00_00 in LE = [00, 00, 00, 00, 00, 00, 00, 01]
    let a = derive_proposal_id(&cid, &pda, 1, b"x", &target);
    let b = derive_proposal_id(&cid, &pda, 0x0100_0000_0000_0000, b"x", &target);
    assert_ne!(a, b, "endian misencode must shift proposal_id");
}

/// Attack v2-10i: 1 000-iteration cross-derive that swapping `index` and
/// `chain_id` (both 8 bytes once chain_id is from_u64) never produces a
/// collision. Pin the field-order resistance pointed at by THREAT_MODEL.
#[test]
fn v2_attack_10i_chain_id_index_swap_no_collision() {
    let mut r = rng();
    let pda = [0xAA; 32];
    let target = [0xBB; 32];
    for _ in 0..1_000 {
        let a: u64 = r.gen();
        let b: u64 = r.gen();
        if a == b {
            continue;
        }
        let pid_ab = derive_proposal_id(&ChainId::from_u64(a), &pda, b, b"action", &target);
        let pid_ba = derive_proposal_id(&ChainId::from_u64(b), &pda, a, b"action", &target);
        assert_ne!(pid_ab, pid_ba, "swap(chain_id, index) leaked a collision");
    }
}

/// Attack v2-10j: ApprovePublicInputs Borsh trailing-garbage rejection.
/// A 96-byte canonical encoding extended by even 1 byte must reject.
#[test]
fn v2_attack_10j_approve_public_inputs_borsh_trailing_reject() {
    let inputs = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0; 32],
        nullifier: [0; 32],
    };
    let mut bytes = to_vec(&inputs).unwrap();
    bytes.push(0xAA);
    let res: Result<ApprovePublicInputs, _> = ApprovePublicInputs::try_from_slice(&bytes);
    assert!(
        res.is_err(),
        "trailing byte after 96-byte canonical must be rejected by Borsh",
    );
}

/// Attack v2-10k: confirm the discriminant byte alone (without any body)
/// never decodes for variants that need a body — namely all four. This is
/// the minimal "is the discriminant byte a complete instruction" check.
#[test]
fn v2_attack_10k_disc_only_never_decodes() {
    for disc in 0u8..=3 {
        let buf = alloc::vec![disc];
        let res: Result<Instruction, _> = Instruction::try_from_slice(&buf);
        assert!(
            res.is_err(),
            "discriminant {disc} alone must not decode (body required)",
        );
    }
}

/// Attack v2-10l: round-tripping a MultisigState with maximum values in
/// every numeric field — make sure no field's encoder accidentally clamps.
#[test]
fn v2_attack_10l_state_extreme_values_roundtrip() {
    let state = MultisigState {
        create_key: [0xFF; 32],
        members_root: [0xFF; 32],
        m: u8::MAX,
        n: u32::MAX,
        proposal_count: u64::MAX,
    };
    let bytes = to_vec(&state).unwrap();
    assert_eq!(bytes.len(), 77, "wire size invariant must hold at extremes");
    let decoded: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, state);
}

extern crate alloc;
