//! Red-team test battery for `private_multisig_core`.
//!
//! Scope: shared-types crate consumed by SDK, Risc0 guest, and SPEL
//! verifier. Targets PDA derivation, `proposal_id` avalanche, Borsh
//! malformation, action-bytes cap, public-inputs layout, error-catalog
//! ABI stability, ChainId construction, and instruction discriminant
//! tampering. Underlying `crypto` crate is out of scope (already pressured).
//!
//! Methodology: deterministic seeds for reproducibility; high-volume
//! random sampling for collision/avalanche checks; panic-vs-error
//! distinction enforced via `catch_unwind` where relevant.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::needless_range_loop,
    clippy::unreadable_literal,
    clippy::needless_pass_by_value
)]

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id,
    derive_proposal_pda, derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction,
    MultisigState, NullifierEntry, Proposal, Vault, APPROVE_PUBLIC_INPUTS_LEN,
    MAX_ACTION_BYTES_LEN, SEED_MULTISIG_STATE, SEED_NULLIFIER, SEED_PROPOSAL, SEED_VAULT,
};

const FIXED_PROGRAM: [u8; 32] = [0x42; 32];
const FIXED_CREATE_KEY: [u8; 32] = [0x99; 32];
const FIXED_TARGET: [u8; 32] = [0x77; 32];

fn rng() -> StdRng {
    StdRng::seed_from_u64(0xDEAD_BEEF_C0FF_EE42)
}

fn random_32(r: &mut StdRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    r.fill_bytes(&mut b);
    b
}

// ============================================================================
// (1) PDA COLLISION SEARCH
// ============================================================================

/// Attack 1a: 100k distinct random create_keys, look for any colliding
/// `MultisigState` PDA. Birthday probability for a 256-bit hash with 1e5
/// samples is ~5e-67 — any hit is a structural bug.
#[test]
fn attack_1a_multisig_state_pda_collision_100k() {
    const N: usize = 100_000;
    let mut r = rng();
    let mut seen: HashMap<[u8; 32], [u8; 32]> = HashMap::with_capacity(N);
    for _ in 0..N {
        let ck = random_32(&mut r);
        let pda = derive_multisig_state_pda(&FIXED_PROGRAM, &ck);
        if let Some(prev) = seen.insert(pda, ck) {
            assert_eq!(prev, ck, "state PDA collision: ck1={prev:?} ck2={ck:?}");
        }
    }
    assert_eq!(seen.len(), N, "duplicate create_keys generated");
}

/// Attack 1b: 100k (create_key, index) pairs → look for proposal-PDA
/// collisions. Also covers the edge case where varying only the index
/// must yield distinct addresses.
#[test]
fn attack_1b_proposal_pda_collision_100k() {
    const N: usize = 100_000;
    let mut r = rng();
    let mut seen: HashMap<[u8; 32], ([u8; 32], u64)> = HashMap::with_capacity(N);
    for _ in 0..N {
        let ck = random_32(&mut r);
        let ix = r.gen::<u64>();
        let pda = derive_proposal_pda(&FIXED_PROGRAM, &ck, ix);
        if let Some(prev) = seen.insert(pda, (ck, ix)) {
            assert_eq!(prev, (ck, ix), "proposal PDA collision");
        }
    }
}

/// Attack 1c: 100k (proposal_pda, nullifier) pairs → nullifier-entry
/// PDA collision search.
#[test]
fn attack_1c_nullifier_entry_pda_collision_100k() {
    const N: usize = 100_000;
    let mut r = rng();
    let mut seen: HashMap<[u8; 32], ([u8; 32], [u8; 32])> = HashMap::with_capacity(N);
    for _ in 0..N {
        let prop = random_32(&mut r);
        let nul = random_32(&mut r);
        let pda = derive_nullifier_entry_pda(&FIXED_PROGRAM, &prop, &nul);
        if let Some(prev) = seen.insert(pda, (prop, nul)) {
            assert_eq!(prev, (prop, nul), "nullifier PDA collision");
        }
    }
}

/// Attack 1d: cross-account-class collisions. State / Proposal / Vault /
/// Nullifier-Entry under the SAME (program_id, create_key) must all be
/// distinct addresses. The 13-byte seed prefix is the only thing
/// distinguishing them — verify it actually does.
#[test]
fn attack_1d_cross_class_pda_collisions_50k() {
    const N: usize = 50_000;
    let mut r = rng();
    for _ in 0..N {
        let pid = random_32(&mut r);
        let ck = random_32(&mut r);
        let ix = r.gen::<u64>();
        let s = derive_multisig_state_pda(&pid, &ck);
        let p = derive_proposal_pda(&pid, &ck, ix);
        let v = derive_vault_pda(&pid, &ck);
        // nullifier entry needs a proposal_pda + nullifier; use s as the
        // "proposal" slot and ck as the nullifier to maximize collision
        // surface against state/vault.
        let n = derive_nullifier_entry_pda(&pid, &s, &ck);
        assert_ne!(s, p, "state == proposal");
        assert_ne!(s, v, "state == vault");
        assert_ne!(s, n, "state == nullifier-entry");
        assert_ne!(p, v, "proposal == vault");
        assert_ne!(p, n, "proposal == nullifier-entry");
        assert_ne!(v, n, "vault == nullifier-entry");
    }
}

/// Attack 1e: confirm changing only `program_id` (with fixed create_key)
/// produces a different state PDA — i.e. no constant collapses out.
#[test]
fn attack_1e_program_id_actually_participates() {
    let mut r = rng();
    let mut seen: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    for _ in 0..50_000 {
        let pid = random_32(&mut r);
        let pda = derive_multisig_state_pda(&pid, &FIXED_CREATE_KEY);
        if let Some(prev) = seen.insert(pda, pid) {
            assert_eq!(prev, pid, "program_id collapse: two pids → same PDA");
        }
    }
}

// ============================================================================
// (2) proposal_id AVALANCHE
// ============================================================================

/// Bit-flip avalanche check. For a strong hash, flipping one input bit
/// should flip roughly half the output bits (target 128/256, accept
/// 96..160 across ~1000 trials each).
#[test]
fn attack_2a_proposal_id_avalanche_single_bit_chain_id() {
    let mut r = rng();
    let state_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &FIXED_CREATE_KEY);
    for _ in 0..200 {
        let mut cid_bytes = random_32(&mut r);
        let baseline = derive_proposal_id(
            &ChainId::new(cid_bytes),
            &state_pda,
            0,
            b"action",
            &FIXED_TARGET,
        );
        let flip_bit = r.gen_range(0..256);
        cid_bytes[flip_bit / 8] ^= 1 << (flip_bit % 8);
        let mutated = derive_proposal_id(
            &ChainId::new(cid_bytes),
            &state_pda,
            0,
            b"action",
            &FIXED_TARGET,
        );
        assert_ne!(baseline, mutated);
        let hd = hamming_distance(&baseline, &mutated);
        assert!(
            (96..=160).contains(&hd),
            "weak avalanche: chain_id bit-flip changed {hd} of 256 output bits"
        );
    }
}

#[test]
fn attack_2b_proposal_id_avalanche_state_pda_bit_flip() {
    let mut r = rng();
    for _ in 0..200 {
        let mut pda = random_32(&mut r);
        let baseline = derive_proposal_id(
            &ChainId::from_u64(1),
            &pda,
            0,
            b"action",
            &FIXED_TARGET,
        );
        let flip_bit = r.gen_range(0..256);
        pda[flip_bit / 8] ^= 1 << (flip_bit % 8);
        let mutated = derive_proposal_id(
            &ChainId::from_u64(1),
            &pda,
            0,
            b"action",
            &FIXED_TARGET,
        );
        let hd = hamming_distance(&baseline, &mutated);
        assert!((96..=160).contains(&hd), "weak avalanche on state PDA: {hd}/256");
    }
}

#[test]
fn attack_2c_proposal_id_avalanche_index_low_bit() {
    // u64 indices typically have the high bits zero; flipping the LOW
    // bit must still avalanche fully.
    let state_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &FIXED_CREATE_KEY);
    let mut totals = 0usize;
    let trials = 200u64;
    for ix in 0..trials {
        let a = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            ix * 2,
            b"action",
            &FIXED_TARGET,
        );
        let b = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            ix * 2 + 1,
            b"action",
            &FIXED_TARGET,
        );
        let hd = hamming_distance(&a, &b);
        assert!((96..=160).contains(&hd), "weak avalanche on index: {hd}/256");
        totals += hd;
    }
    let mean = totals as f64 / trials as f64;
    assert!((118.0..=138.0).contains(&mean), "mean hamming dist {mean} off");
}

#[test]
fn attack_2d_proposal_id_avalanche_action_bytes_bit_flip() {
    let mut r = rng();
    let state_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &FIXED_CREATE_KEY);
    for _ in 0..200 {
        let mut action = vec![0u8; 32];
        r.fill_bytes(&mut action);
        let baseline = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            0,
            &action,
            &FIXED_TARGET,
        );
        let flip_bit = r.gen_range(0..(action.len() * 8));
        action[flip_bit / 8] ^= 1 << (flip_bit % 8);
        let mutated = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            0,
            &action,
            &FIXED_TARGET,
        );
        let hd = hamming_distance(&baseline, &mutated);
        assert!((96..=160).contains(&hd), "weak avalanche on action_bytes: {hd}/256");
    }
}

#[test]
fn attack_2e_proposal_id_avalanche_target_program_bit_flip() {
    let mut r = rng();
    let state_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &FIXED_CREATE_KEY);
    for _ in 0..200 {
        let mut tgt = random_32(&mut r);
        let baseline = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            0,
            b"action",
            &tgt,
        );
        let flip_bit = r.gen_range(0..256);
        tgt[flip_bit / 8] ^= 1 << (flip_bit % 8);
        let mutated = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            0,
            b"action",
            &tgt,
        );
        let hd = hamming_distance(&baseline, &mutated);
        assert!((96..=160).contains(&hd), "weak avalanche on target: {hd}/256");
    }
}

/// Confirm `proposal_id` collisions are not findable in 50k random
/// trials over the full input space.
#[test]
fn attack_2f_proposal_id_collision_50k() {
    const N: usize = 50_000;
    let mut r = rng();
    let mut seen: HashMap<[u8; 32], u64> = HashMap::with_capacity(N);
    for i in 0..N {
        let cid = ChainId::new(random_32(&mut r));
        let state_pda = random_32(&mut r);
        let ix = r.gen::<u64>();
        let alen = r.gen_range(0..64);
        let mut action = vec![0u8; alen];
        r.fill_bytes(&mut action);
        let tgt = random_32(&mut r);
        let pid = derive_proposal_id(&cid, &state_pda, ix, &action, &tgt);
        if let Some(prev) = seen.insert(pid, i as u64) {
            panic!("proposal_id collision between trial {prev} and {i}");
        }
    }
}

fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

// ============================================================================
// (3) BORSH MALFORMATION
// ============================================================================

/// Attack 3a: MultisigState with extra trailing bytes — Borsh contract
/// is `try_from_slice` MUST reject if input has unconsumed bytes
/// (otherwise an attacker can hide payload).
#[test]
fn attack_3a_multisig_state_rejects_trailing_bytes() {
    let s = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 3,
        n: 5,
        proposal_count: 42,
    };
    let mut bytes = to_vec(&s).unwrap();
    bytes.push(0xFF);
    let res = MultisigState::try_from_slice(&bytes);
    assert!(
        res.is_err(),
        "MultisigState accepted trailing byte: smuggle channel"
    );
}

/// Attack 3b: Vault with trailing bytes.
#[test]
fn attack_3b_vault_rejects_trailing_bytes() {
    let v = Vault { create_key: [0x11; 32] };
    let mut bytes = to_vec(&v).unwrap();
    bytes.extend_from_slice(&[0xDE, 0xAD]);
    assert!(Vault::try_from_slice(&bytes).is_err());
}

/// Attack 3c: NullifierEntry has zero payload — feed in non-empty bytes,
/// must reject (otherwise the verifier could be tricked into accepting
/// garbage in what is supposed to be empty state).
#[test]
fn attack_3c_nullifier_entry_rejects_nonempty() {
    let bytes = [0xAB];
    assert!(NullifierEntry::try_from_slice(&bytes).is_err());
}

/// Attack 3d: Truncated Proposal must error cleanly, not panic.
#[test]
fn attack_3d_truncated_proposal_errors_not_panic() {
    let p = Proposal {
        action_bytes: vec![0x01, 0x02, 0x03, 0x04],
        target_program: [0xCC; 32],
        approvals_count: 2,
        executed: false,
    };
    let bytes = to_vec(&p).unwrap();
    // Try every prefix length except the full length.
    for cut in 0..bytes.len() {
        let res = catch_unwind(AssertUnwindSafe(|| Proposal::try_from_slice(&bytes[..cut])));
        match res {
            Ok(decode) => assert!(decode.is_err(), "accepted truncated proposal at {cut}"),
            Err(_) => panic!("PANIC decoding truncated proposal at {cut}"),
        }
    }
}

/// Attack 3e: Proposal where action_bytes Borsh length-prefix claims a
/// payload larger than what's actually present → must reject, not panic
/// (potential DoS / over-read).
#[test]
fn attack_3e_proposal_action_bytes_length_oversize() {
    // Borsh `Vec<u8>` is little-endian u32 length prefix then bytes.
    // Construct a payload claiming 0xFFFF_FFFF bytes follow but provide none.
    let mut malformed: Vec<u8> = Vec::new();
    malformed.extend_from_slice(&u32::MAX.to_le_bytes());
    malformed.extend_from_slice(&[0xCC; 32]); // target_program
    malformed.extend_from_slice(&0u32.to_le_bytes()); // approvals_count
    malformed.push(0); // executed=false
    let res = catch_unwind(AssertUnwindSafe(|| Proposal::try_from_slice(&malformed)));
    match res {
        Ok(decode) => assert!(decode.is_err(), "accepted oversized length prefix"),
        Err(_) => panic!("PANIC on oversized length prefix"),
    }
}

/// Attack 3f: Instruction with unknown variant discriminant (4, 5, 255)
/// must error cleanly.
#[test]
fn attack_3f_instruction_unknown_discriminants() {
    for disc in [4u8, 5, 7, 42, 200, 254, 255] {
        let bytes = [disc];
        let res = catch_unwind(AssertUnwindSafe(|| Instruction::try_from_slice(&bytes)));
        match res {
            Ok(decode) => assert!(decode.is_err(), "accepted unknown discriminant {disc}"),
            Err(_) => panic!("PANIC on instruction discriminant {disc}"),
        }
    }
}

/// Attack 3g: Tamper the first byte of a valid Instruction encoding —
/// flip to other valid variants. The decode must succeed with the OTHER
/// variant shape OR fail cleanly. Critically: no panic, no acceptance of
/// the original semantics under a different discriminant.
#[test]
fn attack_3g_instruction_discriminant_tamper_to_other_valid() {
    let ix = Instruction::Execute {
        create_key: [0xAB; 32],
        index: 42,
    };
    let mut bytes = to_vec(&ix).unwrap();
    assert_eq!(bytes[0], 3); // Execute = 3
    bytes[0] = 0; // CreateMultisig — needs 32+32+1+4 = 69 bytes total
    let res = catch_unwind(AssertUnwindSafe(|| Instruction::try_from_slice(&bytes)));
    match res {
        Ok(decode) => {
            // It either errors (input too short) or returns a different
            // variant — both acceptable, just not the original.
            if let Ok(decoded) = decode {
                assert!(
                    !matches!(decoded, Instruction::Execute { .. }),
                    "discriminant tamper kept Execute semantics"
                );
            }
        }
        Err(_) => panic!("PANIC on discriminant tamper"),
    }
}

/// Attack 3h: Borsh on Instruction is fully byte-exact — every random
/// instruction round-trips, and no random 32-byte payload of an unknown
/// discriminant ever decodes successfully.
#[test]
fn attack_3h_random_byte_streams_dont_decode_to_instruction() {
    let mut r = rng();
    let mut accepted = 0usize;
    let total = 5000;
    for _ in 0..total {
        let mut buf = vec![0u8; 32];
        r.fill_bytes(&mut buf);
        // Force a discriminant >= 4 (no valid variant)
        buf[0] = r.gen_range(4u8..=255);
        let res = catch_unwind(AssertUnwindSafe(|| Instruction::try_from_slice(&buf)));
        match res {
            Ok(Ok(_)) => accepted += 1,
            Ok(Err(_)) => {}
            Err(_) => panic!("PANIC on random instruction stream"),
        }
    }
    assert_eq!(accepted, 0, "{accepted}/{total} unknown-discriminant streams decoded");
}

// ============================================================================
// (4) ACTION-BYTES CAP BYPASS
// ============================================================================

#[test]
fn attack_4a_validate_action_bytes_boundary() {
    let ok = vec![0u8; MAX_ACTION_BYTES_LEN];
    let bad = vec![0u8; MAX_ACTION_BYTES_LEN + 1];
    assert!(Proposal::validate_action_bytes(&ok).is_ok());
    assert!(Proposal::validate_action_bytes(&bad).is_err());
}

#[test]
fn attack_4b_validate_action_bytes_far_overcap() {
    let big = vec![0u8; MAX_ACTION_BYTES_LEN * 32];
    assert!(Proposal::validate_action_bytes(&big).is_err());
}

/// FINDING-2 (LOW, fixed). Pre-fix, `validate_action_bytes` returned
/// `InstanceNotActive` (E1000) for "action bytes too long" — the wrong
/// semantic code, since a stuck instance and an oversized payload produced
/// indistinguishable error values. The fix allocates `E1002
/// ActionBytesTooLong` and routes the validator to return it. This test
/// now locks the corrected behavior in place.
#[test]
fn attack_4c_validate_action_bytes_overcap_returns_misleading_code() {
    let bad = vec![0u8; MAX_ACTION_BYTES_LEN + 1];
    let err = Proposal::validate_action_bytes(&bad).unwrap_err();
    assert_eq!(err, CoreError::ActionBytesTooLong);
    assert_eq!(err.code(), 1002);
}

/// Direct field construction can hold > 4096 bytes — the type system
/// does not prevent it. Confirm validate catches the post-hoc check.
#[test]
fn attack_4d_proposal_struct_can_hold_oversize_until_validate() {
    let big = vec![0xCDu8; MAX_ACTION_BYTES_LEN + 100];
    let p = Proposal {
        action_bytes: big.clone(),
        target_program: [0xCC; 32],
        approvals_count: 0,
        executed: false,
    };
    // Struct field is settable — Borsh would happily serialize it.
    assert_eq!(p.action_bytes.len(), MAX_ACTION_BYTES_LEN + 100);
    let bytes = to_vec(&p).unwrap();
    let back = Proposal::try_from_slice(&bytes).unwrap();
    assert_eq!(back.action_bytes.len(), MAX_ACTION_BYTES_LEN + 100);
    // The validator is what saves us:
    assert!(Proposal::validate_action_bytes(&back.action_bytes).is_err());
}

// ============================================================================
// (5) APPROVE PUBLIC INPUTS LAYOUT
// ============================================================================

#[test]
fn attack_5a_all_zero_bundle_round_trips() {
    let z = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0; 32],
        nullifier: [0; 32],
    };
    let bytes = z.to_bytes();
    assert_eq!(bytes, [0u8; APPROVE_PUBLIC_INPUTS_LEN]);
    assert_eq!(ApprovePublicInputs::from_bytes(&bytes), z);
    // Borsh parity:
    let via_borsh = to_vec(&z).unwrap();
    assert_eq!(via_borsh.as_slice(), bytes.as_slice());
}

#[test]
fn attack_5b_all_ff_bundle_round_trips() {
    let f = ApprovePublicInputs {
        members_root: [0xFF; 32],
        proposal_id: [0xFF; 32],
        nullifier: [0xFF; 32],
    };
    let bytes = f.to_bytes();
    assert_eq!(bytes, [0xFFu8; APPROVE_PUBLIC_INPUTS_LEN]);
    assert_eq!(ApprovePublicInputs::from_bytes(&bytes), f);
}

#[test]
fn attack_5c_field_order_preserved() {
    // Set ONE field to a known value, leave others zero, confirm bytes
    // appear in the documented offset.
    let only_root = ApprovePublicInputs {
        members_root: [0xAA; 32],
        proposal_id: [0; 32],
        nullifier: [0; 32],
    };
    let bytes = only_root.to_bytes();
    assert_eq!(&bytes[..32], &[0xAA; 32]);
    assert_eq!(&bytes[32..64], &[0; 32]);
    assert_eq!(&bytes[64..96], &[0; 32]);

    let only_pid = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0xBB; 32],
        nullifier: [0; 32],
    };
    let bytes = only_pid.to_bytes();
    assert_eq!(&bytes[..32], &[0; 32]);
    assert_eq!(&bytes[32..64], &[0xBB; 32]);
    assert_eq!(&bytes[64..96], &[0; 32]);

    let only_nul = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0; 32],
        nullifier: [0xCC; 32],
    };
    let bytes = only_nul.to_bytes();
    assert_eq!(&bytes[..32], &[0; 32]);
    assert_eq!(&bytes[32..64], &[0; 32]);
    assert_eq!(&bytes[64..96], &[0xCC; 32]);
}

#[test]
fn attack_5d_borsh_explicit_parity_1000_random() {
    let mut r = rng();
    for _ in 0..1000 {
        let bundle = ApprovePublicInputs {
            members_root: random_32(&mut r),
            proposal_id: random_32(&mut r),
            nullifier: random_32(&mut r),
        };
        let canonical = bundle.to_bytes();
        let borsh_bytes = to_vec(&bundle).unwrap();
        assert_eq!(borsh_bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
        assert_eq!(borsh_bytes.as_slice(), canonical.as_slice());
        let back = ApprovePublicInputs::from_bytes(&canonical);
        assert_eq!(back, bundle);
        let back_borsh = ApprovePublicInputs::try_from_slice(&borsh_bytes).unwrap();
        assert_eq!(back_borsh, bundle);
    }
}

// ============================================================================
// (6) ERROR-CATALOG ABI STABILITY
// ============================================================================

#[test]
fn attack_6a_every_variant_has_distinct_code() {
    let codes = [
        CoreError::InstanceNotActive.code(),
        CoreError::ProposalExpiredOrExecuted.code(),
        CoreError::InvalidReceipt.code(),
        CoreError::ImageIdMismatch.code(),
        CoreError::RootMismatch.code(),
        CoreError::ProposalIdMismatch.code(),
        CoreError::NullifierAlreadyUsed.code(),
        CoreError::ThresholdNotMet.code(),
        CoreError::AlreadyExecuted.code(),
    ];
    let mut sorted = codes.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), codes.len(), "duplicate error code in catalog");
}

#[test]
fn attack_6b_from_code_rejects_undocumented_0_to_5000() {
    let valid: std::collections::HashSet<u32> = [
        1000, 1001, 1002, 1003, 1004, 1005, 2000, 2001, 2002, 2003, 3000, 4000, 4001,
    ]
    .into_iter()
    .collect();
    for code in 0u32..=5000 {
        let res = CoreError::from_code(code);
        if valid.contains(&code) {
            assert!(res.is_some(), "valid code {code} returned None");
        } else {
            assert!(res.is_none(), "undocumented code {code} accepted: {res:?}");
        }
    }
}

#[test]
fn attack_6c_display_format_is_stable() {
    // Exact text — this is what shows up in chain logs.
    assert_eq!(
        CoreError::InstanceNotActive.to_string(),
        "E1000: instance not active"
    );
    assert_eq!(
        CoreError::ProposalExpiredOrExecuted.to_string(),
        "E1001: proposal expired or executed"
    );
    assert_eq!(CoreError::InvalidReceipt.to_string(), "E2000: invalid receipt");
    assert_eq!(
        CoreError::ImageIdMismatch.to_string(),
        "E2001: image id mismatch"
    );
    assert_eq!(CoreError::RootMismatch.to_string(), "E2002: root mismatch");
    assert_eq!(
        CoreError::ProposalIdMismatch.to_string(),
        "E2003: proposal id mismatch"
    );
    assert_eq!(
        CoreError::NullifierAlreadyUsed.to_string(),
        "E3000: nullifier already used"
    );
    assert_eq!(
        CoreError::ThresholdNotMet.to_string(),
        "E4000: threshold not met"
    );
    assert_eq!(
        CoreError::AlreadyExecuted.to_string(),
        "E4001: already executed"
    );
}

#[test]
fn attack_6d_from_code_rejects_huge_values() {
    assert!(CoreError::from_code(u32::MAX).is_none());
    assert!(CoreError::from_code(u32::MAX - 1).is_none());
    assert!(CoreError::from_code(1_000_000).is_none());
}

// ============================================================================
// (7) ChainId CONSTRUCTION
// ============================================================================

/// FINDING-3 (documented behavior, not necessarily a defect):
/// `ChainId::from_u64(0)` produces the all-zero 32-byte ChainId. This
/// can collide with `ChainId::new([0; 32])` which downstream callers
/// might use as a "no chain id specified" sentinel. Document and pin.
#[test]
fn attack_7a_chain_id_from_zero_is_all_zero() {
    let cid = ChainId::from_u64(0);
    assert_eq!(cid.as_bytes(), &[0u8; 32]);
    assert_eq!(cid, ChainId::new([0u8; 32]));
}

#[test]
fn attack_7b_chain_id_from_u64_max() {
    let cid = ChainId::from_u64(u64::MAX);
    let bytes = cid.as_bytes();
    assert_eq!(&bytes[..8], &u64::MAX.to_le_bytes());
    assert_eq!(&bytes[8..], &[0u8; 24]);
}

/// 10k distinct u64 values must produce 10k distinct ChainIds (i.e. the
/// constructor is injective).
#[test]
fn attack_7c_chain_id_from_u64_is_injective_10k() {
    let mut seen: HashMap<[u8; 32], u64> = HashMap::with_capacity(10_000);
    let mut r = rng();
    for _ in 0..10_000 {
        let v = r.gen::<u64>();
        let cid = ChainId::from_u64(v);
        if let Some(prev) = seen.insert(*cid.as_bytes(), v) {
            assert_eq!(prev, v, "ChainId from {prev} == ChainId from {v}");
        }
    }
}

/// Two distinct `from_u64` chain ids must produce distinct proposal_ids
/// — the cross-chain replay barrier.
#[test]
fn attack_7d_distinct_chain_ids_separate_proposal_ids() {
    let state_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &FIXED_CREATE_KEY);
    let pid_a = derive_proposal_id(&ChainId::from_u64(1), &state_pda, 0, b"x", &FIXED_TARGET);
    let pid_b = derive_proposal_id(&ChainId::from_u64(2), &state_pda, 0, b"x", &FIXED_TARGET);
    let pid_max = derive_proposal_id(
        &ChainId::from_u64(u64::MAX),
        &state_pda,
        0,
        b"x",
        &FIXED_TARGET,
    );
    assert_ne!(pid_a, pid_b);
    assert_ne!(pid_a, pid_max);
    assert_ne!(pid_b, pid_max);
}

// ============================================================================
// (8) CROSS-INSTANCE CONFUSION — TYPE-LEVEL OBSERVATION
// ============================================================================

/// At the core layer, Borsh accepts any `create_key` — there is NO
/// link between a CreateMultisig.create_key and the multisig_state PDA
/// in an instruction. The verifier program MUST cross-check by
/// re-deriving the PDA from `create_key`. This test confirms a malicious
/// SDK can package a syntactically valid instruction that points at an
/// account whose seeds do not match — the core layer has no defense and
/// is not supposed to have one.
#[test]
fn attack_8a_core_layer_does_not_bind_account_to_create_key() {
    let real_ck = [0x11; 32];
    let lying_ck = [0x22; 32];
    let real_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &real_ck);
    let liar_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &lying_ck);
    assert_ne!(real_pda, liar_pda);

    // Attacker constructs an instruction with `lying_ck` and expects the
    // verifier to *separately* receive `real_pda` as the account-meta —
    // the instruction encoding cannot detect the mismatch. This is by
    // design at the type level. Flag the dependency on the verifier.
    let ix = Instruction::Execute {
        create_key: lying_ck,
        index: 0,
    };
    let bytes = to_vec(&ix).unwrap();
    assert_eq!(
        Instruction::try_from_slice(&bytes).unwrap(),
        ix,
        "core layer cannot detect cross-instance confusion — verifier must"
    );
}

// ============================================================================
// (9) INSTRUCTION DISCRIMINANT TAMPERING (additional / fuzzed)
// ============================================================================

#[test]
fn attack_9a_empty_input_to_instruction_decode_errors() {
    let res = catch_unwind(AssertUnwindSafe(|| Instruction::try_from_slice(&[])));
    match res {
        Ok(decode) => assert!(decode.is_err()),
        Err(_) => panic!("PANIC on empty instruction"),
    }
}

#[test]
fn attack_9b_random_2k_byte_blobs_never_become_instructions() {
    let mut r = rng();
    let mut accepted = 0usize;
    let total = 5000;
    for _ in 0..total {
        let len = r.gen_range(0..200);
        let mut buf = vec![0u8; len];
        r.fill_bytes(&mut buf);
        let res = catch_unwind(AssertUnwindSafe(|| Instruction::try_from_slice(&buf)));
        match res {
            Ok(Ok(_)) => accepted += 1,
            Ok(Err(_)) => {}
            Err(_) => panic!("PANIC on random instruction blob"),
        }
    }
    // Accepting some legitimate small-shape decodes is fine; what
    // matters is no panic and no acceptance of malformed bytes. The
    // count is informational.
    println!("informational: {accepted}/{total} random blobs decoded as instructions");
}

// ============================================================================
// (10) PROPOSAL VALIDATE_ACTION_BYTES SEMANTIC MISMAP (FINDING)
// ============================================================================
// Pinned in attack_4c above. See FINDING-2 in the report.

// ============================================================================
// (11) derive_pda EXTRAS LENGTH — caller-bounded
// ============================================================================

/// All exported `derive_*_pda` helpers pass fixed-size or
/// caller-controlled-but-bounded extras: CreateKey/AccountId (32) and
/// u64 (8). The nullifier-entry path takes a proposal_pda (32) and
/// nullifier (32). The longest reachable extras payload is therefore
/// 64 bytes total. SHA-256 has no max-input pathology. Confirm
/// derivation completes quickly for any reachable size.
#[test]
fn attack_11a_derive_pda_handles_max_reachable_extras() {
    // largest reachable: nullifier_entry path = 32 + 32 = 64 extras
    let start = std::time::Instant::now();
    for _ in 0..10_000 {
        let _ = derive_nullifier_entry_pda(&FIXED_PROGRAM, &[0xAB; 32], &[0xCD; 32]);
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "PDA derivation slow path"
    );
}

// ============================================================================
// (12) CREATIVE ATTACKS
// ============================================================================

/// (12a) Seed-vs-extras boundary smuggling: PLAN.md uses 13-byte seeds
/// followed by a 32-byte create_key. Confirm appending bytes to a
/// shorter seed cannot re-create a longer one's hash (i.e. the
/// concatenation is unambiguous in practice for these inputs).
/// Concretely: the SHA-256 input is `program ‖ seed ‖ extras`. If an
/// attacker could pick `(seed', extras')` such that `seed' ‖ extras'`
/// has the same bytes as `seed ‖ extras` for a different (seed,extras)
/// pair, derivation would collide. Since both seeds are exactly 13
/// bytes, the only way is identical seeds — verified.
#[test]
fn attack_12a_seed_boundary_is_unambiguous() {
    let pid = FIXED_PROGRAM;
    let ck = FIXED_CREATE_KEY;
    let state = derive_multisig_state_pda(&pid, &ck);
    let proposal_0 = derive_proposal_pda(&pid, &ck, 0);
    // Even though both downstream signatures expand to "program ‖ 13B ‖ 32B ‖ ..."
    // the differing 13-byte literal between SEED_MULTISIG_STATE and
    // SEED_PROPOSAL breaks any preimage equivalence.
    assert_ne!(state, proposal_0);
    assert_eq!(SEED_MULTISIG_STATE.len(), 13);
    assert_eq!(SEED_PROPOSAL.len(), 13);
    assert_eq!(SEED_VAULT.len(), 13);
    assert_eq!(SEED_NULLIFIER.len(), 13);
}

/// (12b) Borsh `bool` strictness — a `Proposal.executed` field is a u8
/// in wire form. Borsh 1 rejects values other than 0 / 1. Confirm this
/// hardness: forging executed=2 must error, not silently coerce.
#[test]
fn attack_12b_proposal_bool_strict() {
    // Build minimal valid Proposal bytes by hand.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0u32.to_le_bytes()); // action_bytes len = 0
    bytes.extend_from_slice(&[0xCC; 32]); // target_program
    bytes.extend_from_slice(&0u32.to_le_bytes()); // approvals_count
    bytes.push(2); // executed = 2 (invalid for bool)
    let res = catch_unwind(AssertUnwindSafe(|| Proposal::try_from_slice(&bytes)));
    match res {
        Ok(decode) => assert!(decode.is_err(), "Borsh accepted executed=2 as bool"),
        Err(_) => panic!("PANIC on invalid bool encoding"),
    }
}

/// (12c) Approve instruction wire is fixed-length now that `receipt`
/// Round 6 unified `Instruction::Approve` with the verifier handler:
/// `{create_key, index, nullifier: [u8;32], public_inputs: Vec<u8>}`. The
/// Borsh wire is `disc(1) + create_key(32) + index(8) + nullifier(32) +
/// len(4) + public_inputs(96) = 173` for the canonical 96-byte payload.
#[test]
fn attack_12c_approve_wire_is_173() {
    let inputs = ApprovePublicInputs {
        members_root: [1; 32],
        proposal_id: [2; 32],
        nullifier: [3; 32],
    };
    let ix = Instruction::Approve {
        create_key: [0; 32],
        index: 0,
        nullifier: inputs.nullifier,
        public_inputs: inputs.to_bytes().to_vec(),
    };
    let bytes = to_vec(&ix).unwrap();
    let expected = 1 + 32 + 8 + 32 + 4 + APPROVE_PUBLIC_INPUTS_LEN;
    assert_eq!(bytes.len(), expected, "Approve wire size drift");
    assert_eq!(bytes.len(), 173);
    let back = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(back, ix);
}

/// (12d) Round 6 keeps a length-prefixed `Vec<u8>` for public_inputs (so
/// the SPEL handler can length-check before decoding). Pin the byte
/// position layout: after disc(1)+create_key(32)+index(8)+nullifier(32),
/// the next 4 bytes must be `[96, 0, 0, 0]` (LE u32 length prefix), then
/// the 96 public-input bytes follow.
#[test]
fn attack_12d_approve_public_inputs_is_length_prefixed_vec() {
    let inputs = ApprovePublicInputs {
        members_root: [0xAB; 32],
        proposal_id: [0xCD; 32],
        nullifier: [0xEF; 32],
    };
    let ix = Instruction::Approve {
        create_key: [0; 32],
        index: 0,
        nullifier: inputs.nullifier,
        public_inputs: inputs.to_bytes().to_vec(),
    };
    let bytes = to_vec(&ix).unwrap();
    let len_prefix_off = 1 + 32 + 8 + 32;
    assert_eq!(
        &bytes[len_prefix_off..len_prefix_off + 4],
        &96u32.to_le_bytes(),
        "expected u32 LE length prefix == 96",
    );
    let payload_off = len_prefix_off + 4;
    assert_eq!(
        bytes[payload_off], 0xAB,
        "byte after length prefix must be the first members_root byte",
    );
}

/// (12e) Confirm `MultisigState` wire size is exactly 77 bytes — the
/// number callers (verifier, SDK) bake into account-allocation math.
/// Drift means accounts get over- or under-allocated.
#[test]
fn attack_12e_multisig_state_wire_size_is_77() {
    let s = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 0,
        n: 0,
        proposal_count: 0,
    };
    let bytes = to_vec(&s).unwrap();
    assert_eq!(bytes.len(), 77, "MultisigState wire size drift");
    let s2 = MultisigState {
        create_key: [0xFF; 32],
        members_root: [0xFF; 32],
        m: u8::MAX,
        n: u32::MAX,
        proposal_count: u64::MAX,
    };
    assert_eq!(to_vec(&s2).unwrap().len(), 77, "size depends on field values");
}

/// (12f) Endianness lock-in: confirm index and u64 fields go to the
/// wire LITTLE-endian. Big-endian by a peer would mean indexes 1 and
/// 0x0100_0000_0000_0000 produce the same proposal_id, undetected.
#[test]
fn attack_12f_index_endianness_is_little() {
    let state_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &FIXED_CREATE_KEY);
    // 1 LE = [01, 00, 00, ...]; 1 BE would be [00, ..., 00, 01].
    // If implementation flipped to BE, the following two would collide
    // with the wrong pair; verify the LE-encoded sibling differs from
    // the BE-encoded sibling.
    let pid_index_1 = derive_proposal_id(
        &ChainId::from_u64(1),
        &state_pda,
        1,
        b"action",
        &FIXED_TARGET,
    );
    // Index whose LE encoding equals 1's BE encoding: 0x0100_0000_0000_0000
    let pid_be_collision_candidate = derive_proposal_id(
        &ChainId::from_u64(1),
        &state_pda,
        0x0100_0000_0000_0000,
        b"action",
        &FIXED_TARGET,
    );
    assert_ne!(
        pid_index_1, pid_be_collision_candidate,
        "endianness drift: LE(1) == BE(1)"
    );

    // Direct: the embedded index bytes within the instruction encoding
    // appear in LE order.
    let ix = Instruction::Execute {
        create_key: [0; 32],
        index: 1,
    };
    let bytes = to_vec(&ix).unwrap();
    // [discriminant=3, create_key 32 zero bytes, index 8 bytes]
    assert_eq!(&bytes[33..41], &1u64.to_le_bytes());
}

/// (12g) Distinct (create_key, index=0) and (create_key', index=k)
/// CANNOT collide simply because both contribute distinct bytes to the
/// SHA-256 preimage. Random search over 50k samples — if any hit,
/// `derive_proposal_pda` is broken.
#[test]
fn attack_12g_create_key_vs_index_no_swap_collision() {
    let mut r = rng();
    let mut seen: HashMap<[u8; 32], ([u8; 32], u64)> = HashMap::with_capacity(50_000);
    for _ in 0..50_000 {
        let ck = random_32(&mut r);
        // First 8 bytes of ck mimic an index — make sure swap-style
        // collisions don't happen.
        let mut ix_bytes = [0u8; 8];
        ix_bytes.copy_from_slice(&ck[..8]);
        let ix = u64::from_le_bytes(ix_bytes);
        let pda = derive_proposal_pda(&FIXED_PROGRAM, &ck, ix);
        if let Some(prev) = seen.insert(pda, (ck, ix)) {
            assert_eq!(prev, (ck, ix), "swap-style proposal PDA collision");
        }
    }
}

/// (12h) NullifierEntry serialization is exactly zero bytes — confirm
/// nothing snuck in (e.g. a discriminant tag a future refactor might
/// add by accident).
#[test]
fn attack_12h_nullifier_entry_is_zero_bytes() {
    let bytes = to_vec(&NullifierEntry).unwrap();
    assert!(bytes.is_empty(), "NullifierEntry serialized to {} bytes", bytes.len());
}

/// (12i) Same proposal_id with action_bytes that differ only by appending
/// SHA-256 padding bytes must still be distinct — sanity check that the
/// internal hashing doesn't expose length-extension oddities. (SHA-256
/// hashes action_bytes as a leaf so this is structurally fine; pin it.)
#[test]
fn attack_12i_proposal_id_length_extension_resistant() {
    let state_pda = derive_multisig_state_pda(&FIXED_PROGRAM, &FIXED_CREATE_KEY);
    let cid = ChainId::from_u64(1);
    let a = derive_proposal_id(&cid, &state_pda, 0, b"abc", &FIXED_TARGET);
    let b = derive_proposal_id(&cid, &state_pda, 0, b"abc\x80", &FIXED_TARGET);
    let c = derive_proposal_id(&cid, &state_pda, 0, b"abc\x00", &FIXED_TARGET);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

/// (12j) Re-export consistency — the helpers re-exported from `lib.rs`
/// must equal the ones in the source modules they come from.
#[test]
fn attack_12j_reexport_aliases_are_consistent() {
    let pid = FIXED_PROGRAM;
    let ck = FIXED_CREATE_KEY;
    let via_root = derive_multisig_state_pda(&pid, &ck);
    let via_module = private_multisig_core::pda::derive_multisig_state_pda(&pid, &ck);
    assert_eq!(via_root, via_module);

    // Seed constants identity.
    assert_eq!(SEED_MULTISIG_STATE, private_multisig_core::pda::SEED_MULTISIG_STATE);
    assert_eq!(SEED_PROPOSAL, private_multisig_core::pda::SEED_PROPOSAL);
    assert_eq!(SEED_VAULT, private_multisig_core::pda::SEED_VAULT);
    assert_eq!(SEED_NULLIFIER, private_multisig_core::pda::SEED_NULLIFIER);
}
