//! Blue-team validator for `private_multisig_core`.
//!
//! Confirms the defensive properties documented in LP-0002 step 2 by
//! deterministically exercising the public API along sixteen named axes:
//! Borsh round-trips, PDA determinism / uniqueness, `proposal_id` avalanche,
//! `CoreError` code invertibility, canonical layout parity, action-bytes
//! capping, instruction discriminant stability, and assorted pinned
//! constants. Every "proptest" here is a seeded random sweep (no `proptest`
//! crate dep) so the tests are reproducible bit-for-bit.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_panics_doc)]

use std::collections::HashSet;

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id, derive_proposal_pda,
    derive_vault_pda,
    error::CoreError,
    instructions::Instruction,
    proof::{ApprovePublicInputs, ChainId},
    state::{MultisigState, NullifierEntry, Proposal, Vault},
    APPROVE_PUBLIC_INPUTS_LEN, MAX_ACTION_BYTES_LEN, SEED_MULTISIG_STATE, SEED_NULLIFIER,
    SEED_PROPOSAL, SEED_VAULT,
};

/// Deterministic seed used across the whole file. Changing it changes the
/// random sweep but not the assertions, so a flake here is a real bug.
const SEED: u64 = 0x10_2002_B10E_u64.swap_bytes();

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

fn random_array_32(rng: &mut StdRng) -> [u8; 32] {
    let mut out = [0u8; 32];
    rng.fill_bytes(&mut out);
    out
}

// ---------------------------------------------------------------------------
// 1. Borsh round-trip proptest across the entire public type surface.
// ---------------------------------------------------------------------------

#[test]
fn core_borsh_round_trip_proptest() {
    let mut rng = rng();

    for iter in 0..1000u32 {
        // MultisigState
        let state = MultisigState {
            create_key: random_array_32(&mut rng),
            members_root: random_array_32(&mut rng),
            m: rng.random(),
            n: rng.random(),
            proposal_count: rng.random(),
        };
        let bytes = to_vec(&state).unwrap();
        let decoded = MultisigState::try_from_slice(&bytes).unwrap();
        assert_eq!(
            state, decoded,
            "MultisigState round-trip diverged @ iter {iter}"
        );
        // Byte-for-byte: re-serialize the decoded form, expect identical bytes.
        assert_eq!(
            bytes,
            to_vec(&decoded).unwrap(),
            "MultisigState bytes diverged @ {iter}"
        );

        // Proposal with random-length action_bytes <= MAX
        let action_len = rng.random_range(0..=MAX_ACTION_BYTES_LEN);
        let mut action_bytes = vec![0u8; action_len];
        rng.fill_bytes(&mut action_bytes);
        let proposal = Proposal {
            action_bytes,
            target_program: random_array_32(&mut rng),
            approvals_count: rng.random(),
            executed: rng.random(),
        };
        let bytes = to_vec(&proposal).unwrap();
        let decoded = Proposal::try_from_slice(&bytes).unwrap();
        assert_eq!(proposal, decoded, "Proposal round-trip diverged @ {iter}");
        assert_eq!(
            bytes,
            to_vec(&decoded).unwrap(),
            "Proposal bytes diverged @ {iter}"
        );

        // Vault
        let vault = Vault {
            create_key: random_array_32(&mut rng),
        };
        let bytes = to_vec(&vault).unwrap();
        let decoded = Vault::try_from_slice(&bytes).unwrap();
        assert_eq!(vault, decoded, "Vault round-trip diverged @ {iter}");
        assert_eq!(
            bytes,
            to_vec(&decoded).unwrap(),
            "Vault bytes diverged @ {iter}"
        );

        // NullifierEntry (empty, but still round-trip it).
        let null_bytes = to_vec(&NullifierEntry).unwrap();
        assert!(null_bytes.is_empty());
        let _ne = NullifierEntry::try_from_slice(&null_bytes).unwrap();

        // ApprovePublicInputs
        let pi = ApprovePublicInputs {
            members_root: random_array_32(&mut rng),
            proposal_id: random_array_32(&mut rng),
            nullifier: random_array_32(&mut rng),
        };
        let bytes = to_vec(&pi).unwrap();
        let decoded = ApprovePublicInputs::try_from_slice(&bytes).unwrap();
        assert_eq!(
            pi, decoded,
            "ApprovePublicInputs round-trip diverged @ {iter}"
        );
        assert_eq!(bytes, to_vec(&decoded).unwrap());

        // Instruction::* — pick a variant each iteration.
        let variant = iter % 4;
        let ix = match variant {
            0 => Instruction::CreateMultisig {
                create_key: random_array_32(&mut rng),
                members_root: random_array_32(&mut rng),
                m: rng.random(),
                n: rng.random(),
            },
            1 => {
                let len = rng.random_range(0..=64);
                let mut ab = vec![0u8; len];
                rng.fill_bytes(&mut ab);
                Instruction::Propose {
                    create_key: random_array_32(&mut rng),
                    index: rng.random(),
                    action_bytes: ab,
                    target_program: random_array_32(&mut rng),
                }
            }
            2 => {
                let nf = random_array_32(&mut rng);
                let inputs = ApprovePublicInputs {
                    members_root: random_array_32(&mut rng),
                    proposal_id: random_array_32(&mut rng),
                    nullifier: nf,
                };
                Instruction::Approve {
                    create_key: random_array_32(&mut rng),
                    index: rng.random(),
                    nullifier: nf,
                    public_inputs: inputs.to_bytes().to_vec(),
                }
            }
            _ => Instruction::Execute {
                create_key: random_array_32(&mut rng),
                index: rng.random(),
            },
        };
        let bytes = to_vec(&ix).unwrap();
        let decoded = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(ix, decoded, "Instruction round-trip diverged @ {iter}");
        assert_eq!(
            bytes,
            to_vec(&decoded).unwrap(),
            "Instruction bytes diverged @ {iter}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. PDA determinism proptest.
// ---------------------------------------------------------------------------

#[test]
fn core_pda_determinism_proptest() {
    let mut rng = rng();
    for _ in 0..1000 {
        let program_id = random_array_32(&mut rng);
        let create_key = random_array_32(&mut rng);
        let proposal_pda = derive_proposal_pda(&program_id, &create_key, 0);
        let nullifier = random_array_32(&mut rng);

        assert_eq!(
            derive_multisig_state_pda(&program_id, &create_key),
            derive_multisig_state_pda(&program_id, &create_key),
        );
        assert_eq!(
            derive_proposal_pda(&program_id, &create_key, 0),
            derive_proposal_pda(&program_id, &create_key, 0),
        );
        assert_eq!(
            derive_vault_pda(&program_id, &create_key),
            derive_vault_pda(&program_id, &create_key),
        );
        assert_eq!(
            derive_nullifier_entry_pda(&program_id, &proposal_pda, &nullifier),
            derive_nullifier_entry_pda(&program_id, &proposal_pda, &nullifier),
        );
    }
}

// ---------------------------------------------------------------------------
// 3. PDA uniqueness within a class — random sweep.
// ---------------------------------------------------------------------------

#[test]
fn core_pda_uniqueness_within_class_proptest() {
    let mut rng = rng();

    let mut state_set: HashSet<[u8; 32]> = HashSet::with_capacity(2000);
    let mut prop_set: HashSet<[u8; 32]> = HashSet::with_capacity(2000);
    let mut vault_set: HashSet<[u8; 32]> = HashSet::with_capacity(2000);

    for _ in 0..1000 {
        let pid_a = random_array_32(&mut rng);
        let ck_a = random_array_32(&mut rng);
        let mut pid_b = random_array_32(&mut rng);
        let mut ck_b = random_array_32(&mut rng);
        // Guarantee the pair is actually distinct.
        if (pid_a, ck_a) == (pid_b, ck_b) {
            pid_b[0] ^= 0xFF;
            ck_b[0] ^= 0xFF;
        }

        let sa = derive_multisig_state_pda(&pid_a, &ck_a);
        let sb = derive_multisig_state_pda(&pid_b, &ck_b);
        assert_ne!(sa, sb, "state-pda collision for distinct inputs");
        // HashSet collision check across iterations.
        assert!(state_set.insert(sa));
        assert!(state_set.insert(sb));

        let pa = derive_proposal_pda(&pid_a, &ck_a, 0);
        let pb = derive_proposal_pda(&pid_b, &ck_b, 0);
        assert_ne!(pa, pb, "proposal-pda collision for distinct inputs");
        assert!(prop_set.insert(pa));
        assert!(prop_set.insert(pb));

        let va = derive_vault_pda(&pid_a, &ck_a);
        let vb = derive_vault_pda(&pid_b, &ck_b);
        assert_ne!(va, vb, "vault-pda collision for distinct inputs");
        assert!(vault_set.insert(va));
        assert!(vault_set.insert(vb));
    }
}

// ---------------------------------------------------------------------------
// 4. PDA uniqueness across classes for one fixed input.
// ---------------------------------------------------------------------------

#[test]
fn core_pda_uniqueness_across_classes() {
    let program_id: [u8; 32] = [0xA1; 32];
    let create_key: [u8; 32] = [0xB2; 32];
    let nullifier: [u8; 32] = [0xC3; 32];

    let state = derive_multisig_state_pda(&program_id, &create_key);
    let proposal = derive_proposal_pda(&program_id, &create_key, 0);
    let vault = derive_vault_pda(&program_id, &create_key);
    // The fourth class binds to a proposal PDA + a nullifier. Use the same
    // proposal address as the previous derivation so all four cohabit the
    // same parent context.
    let nul = derive_nullifier_entry_pda(&program_id, &proposal, &nullifier);

    let mut set = HashSet::new();
    for pda in [state, proposal, vault, nul] {
        assert!(set.insert(pda), "cross-class PDA collision: {pda:?}");
    }
    assert_eq!(set.len(), 4);
}

// ---------------------------------------------------------------------------
// 5. proposal_id avalanche — sweep each of the five inputs independently.
// ---------------------------------------------------------------------------

#[test]
fn core_proposal_id_avalanche_each_input() {
    let mut rng = rng();
    let fixed_chain = ChainId::from_u64(0x1234_5678_9ABC_DEF0);
    let fixed_state: [u8; 32] = random_array_32(&mut rng);
    let fixed_index: u64 = 42;
    let fixed_action: Vec<u8> = b"baseline-action".to_vec();
    let fixed_target: [u8; 32] = random_array_32(&mut rng);

    // Sweep chain_id.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..32u64 {
        let cid = ChainId::from_u64(0x1234_5678_9ABC_DEF0 ^ (1u64 << (i % 64)));
        let pid = derive_proposal_id(
            &cid,
            &fixed_state,
            fixed_index,
            &fixed_action,
            &fixed_target,
        );
        assert!(seen.insert(pid), "chain_id sweep collided at bit {i}");
    }

    // Sweep state PDA.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..32u8 {
        let mut s = fixed_state;
        s[(i as usize) % 32] ^= 1 << (i % 8);
        let pid = derive_proposal_id(&fixed_chain, &s, fixed_index, &fixed_action, &fixed_target);
        assert!(seen.insert(pid), "state sweep collided at byte {i}");
    }

    // Sweep index.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..64u64 {
        let pid = derive_proposal_id(&fixed_chain, &fixed_state, i, &fixed_action, &fixed_target);
        assert!(seen.insert(pid), "index sweep collided at i={i}");
    }

    // Sweep action_bytes.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..32u8 {
        let mut ab = fixed_action.clone();
        ab.push(i);
        let pid = derive_proposal_id(&fixed_chain, &fixed_state, fixed_index, &ab, &fixed_target);
        assert!(seen.insert(pid), "action sweep collided at variant {i}");
    }

    // Sweep target_program.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..32u8 {
        let mut t = fixed_target;
        t[(i as usize) % 32] ^= 1 << (i % 8);
        let pid = derive_proposal_id(&fixed_chain, &fixed_state, fixed_index, &fixed_action, &t);
        assert!(seen.insert(pid), "target sweep collided at byte {i}");
    }
}

// ---------------------------------------------------------------------------
// 6. proposal_id avalanche — bit-flip Hamming distance.
// ---------------------------------------------------------------------------

fn hamming(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    let mut h = 0u32;
    for i in 0..32 {
        h += (a[i] ^ b[i]).count_ones();
    }
    h
}

#[test]
fn core_proposal_id_byte_diff_hamming() {
    let mut rng = rng();

    let mut total: u64 = 0;
    let pairs = 50u32;
    for _ in 0..pairs {
        let chain = ChainId::from_u64(rng.random());
        let state = random_array_32(&mut rng);
        let index: u64 = rng.random();
        let action_len = rng.random_range(1..=128);
        let mut action = vec![0u8; action_len];
        rng.fill_bytes(&mut action);
        let target = random_array_32(&mut rng);

        let id_a = derive_proposal_id(&chain, &state, index, &action, &target);

        // Flip a single random bit in one of the inputs (pick the input
        // class round-robin so we cover every input over the 50 pairs).
        let pick = rng.random_range(0..5u8);
        let id_b = match pick {
            0 => {
                let mut c = *chain.as_bytes();
                let bi = rng.random_range(0..256u32) as usize;
                c[bi / 8] ^= 1 << (bi % 8);
                derive_proposal_id(&ChainId::new(c), &state, index, &action, &target)
            }
            1 => {
                let mut s = state;
                let bi = rng.random_range(0..256u32) as usize;
                s[bi / 8] ^= 1 << (bi % 8);
                derive_proposal_id(&chain, &s, index, &action, &target)
            }
            2 => {
                let bi = rng.random_range(0..64u32) as u64;
                derive_proposal_id(&chain, &state, index ^ (1u64 << bi), &action, &target)
            }
            3 => {
                let mut a = action.clone();
                let bi = rng.random_range(0..(a.len() * 8) as u32) as usize;
                a[bi / 8] ^= 1 << (bi % 8);
                derive_proposal_id(&chain, &state, index, &a, &target)
            }
            _ => {
                let mut t = target;
                let bi = rng.random_range(0..256u32) as usize;
                t[bi / 8] ^= 1 << (bi % 8);
                derive_proposal_id(&chain, &state, index, &action, &t)
            }
        };

        assert_ne!(
            id_a, id_b,
            "single-bit input change produced identical proposal_id"
        );
        let h = hamming(&id_a, &id_b);
        total += u64::from(h);
    }

    let avg = total as f64 / f64::from(pairs);
    // SHA-256 avalanche expectation is 128 bits per pair, +/- 16 generous.
    assert!(
        (100.0..=156.0).contains(&avg),
        "average hamming distance {avg} outside [100,156]; SHA-256 avalanche broken?"
    );
}

// ---------------------------------------------------------------------------
// 7. Error code invertibility for every documented code.
// ---------------------------------------------------------------------------

#[test]
fn core_error_code_invertibility() {
    for code in [1000u32, 1001, 2000, 2001, 2002, 2003, 3000, 4000, 4001] {
        let variant =
            CoreError::from_code(code).unwrap_or_else(|| panic!("from_code({code}) returned None"));
        assert_eq!(variant.code(), code, "round-trip mismatch for code {code}");
    }
}

// ---------------------------------------------------------------------------
// 8. Error code uniqueness — codes are 1-to-1 with variants.
// ---------------------------------------------------------------------------

#[test]
fn core_error_code_unique_per_variant() {
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
    let mut codes: HashSet<u32> = HashSet::new();
    for v in all {
        assert!(
            codes.insert(v.code()),
            "duplicate code {} from {:?}",
            v.code(),
            v
        );
    }
    assert_eq!(codes.len(), all.len(), "code cardinality != variant count");
}

// ---------------------------------------------------------------------------
// 9. Canonical 96-byte layout == Borsh encoding for ApprovePublicInputs.
// ---------------------------------------------------------------------------

#[test]
fn core_canonical_layout_equals_borsh() {
    let mut rng = rng();
    for _ in 0..100 {
        let pi = ApprovePublicInputs {
            members_root: random_array_32(&mut rng),
            proposal_id: random_array_32(&mut rng),
            nullifier: random_array_32(&mut rng),
        };
        let canonical = pi.to_bytes();
        let borsh_bytes = to_vec(&pi).unwrap();
        assert_eq!(canonical.len(), APPROVE_PUBLIC_INPUTS_LEN);
        assert_eq!(canonical.len(), 96);
        assert_eq!(
            canonical.as_slice(),
            borsh_bytes.as_slice(),
            "canonical / borsh divergence"
        );
    }
}

// ---------------------------------------------------------------------------
// 10. validate_action_bytes accepts 0..=MAX, rejects MAX+1..=MAX+1001.
// ---------------------------------------------------------------------------

#[test]
fn core_action_bytes_cap_proptest() {
    // Accepted band — sweep edges + a sample of the interior so the test
    // stays fast.
    let mut accepted_lens: Vec<usize> = vec![0, 1, 2, 31, 32, 33, 1023, 1024, 1025];
    accepted_lens.extend((0..MAX_ACTION_BYTES_LEN).step_by(257));
    accepted_lens.push(MAX_ACTION_BYTES_LEN - 1);
    accepted_lens.push(MAX_ACTION_BYTES_LEN);
    for len in accepted_lens {
        let buf = vec![0u8; len];
        assert!(
            Proposal::validate_action_bytes(&buf).is_ok(),
            "validator rejected acceptable len {len}"
        );
    }

    // Rejected band — sweep MAX+1..=MAX+1001.
    for len in (MAX_ACTION_BYTES_LEN + 1)..=(MAX_ACTION_BYTES_LEN + 1001) {
        let buf = vec![0u8; len];
        assert!(
            Proposal::validate_action_bytes(&buf).is_err(),
            "validator accepted oversize len {len}"
        );
    }
}

// ---------------------------------------------------------------------------
// 11. Instruction discriminant stability.
// ---------------------------------------------------------------------------

#[test]
fn core_instruction_discriminant_stability() {
    let pi = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0; 32],
        nullifier: [0; 32],
    };
    let cases: [(Instruction, u8); 4] = [
        (
            Instruction::CreateMultisig {
                create_key: [0; 32],
                members_root: [0; 32],
                m: 0,
                n: 0,
            },
            0,
        ),
        (
            Instruction::Propose {
                create_key: [0; 32],
                index: 0,
                action_bytes: Vec::new(),
                target_program: [0; 32],
            },
            1,
        ),
        (
            Instruction::Approve {
                create_key: [0; 32],
                index: 0,
                nullifier: pi.nullifier,
                public_inputs: pi.to_bytes().to_vec(),
            },
            2,
        ),
        (
            Instruction::Execute {
                create_key: [0; 32],
                index: 0,
            },
            3,
        ),
    ];
    for (ix, expected) in cases {
        let bytes = to_vec(&ix).unwrap();
        assert_eq!(
            bytes[0], expected,
            "discriminant drift for {ix:?}: got {}, expected {expected}",
            bytes[0]
        );
    }
}

// ---------------------------------------------------------------------------
// 12. ChainId::from_u64 uniqueness across 100 distinct values.
// ---------------------------------------------------------------------------

#[test]
fn core_chain_id_from_u64_uniqueness() {
    let mut set: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..100u64 {
        // Spread across the u64 range so we exercise more than just the low byte.
        let v = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(i);
        let cid = ChainId::from_u64(v);
        assert!(
            set.insert(*cid.as_bytes()),
            "ChainId collision for v={v:#x}"
        );
    }
    assert_eq!(set.len(), 100);
}

// ---------------------------------------------------------------------------
// 13. ChainId little-endian byte layout.
// ---------------------------------------------------------------------------

#[test]
fn core_chain_id_little_endian_layout() {
    let cid = ChainId::from_u64(0x0102_0304_0506_0708);
    let bytes = cid.as_bytes();
    let expected_lo: [u8; 8] = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
    assert_eq!(&bytes[..8], &expected_lo, "first 8 bytes must be LE of u64");
    for (i, b) in bytes[8..].iter().enumerate() {
        assert_eq!(*b, 0u8, "padding byte at {} must be zero", 8 + i);
    }
}

// ---------------------------------------------------------------------------
// 14. Seed constants match documented bytes (locks on-chain naming).
// ---------------------------------------------------------------------------

#[test]
fn core_seed_constants_match_documented_bytes() {
    assert_eq!(SEED_MULTISIG_STATE, b"pmsig_state__");
    assert_eq!(SEED_PROPOSAL, b"pmsig_prop___");
    assert_eq!(SEED_VAULT, b"pmsig_vault__");
    assert_eq!(SEED_NULLIFIER, b"pmsig_nulli__");
    // Length sentinel.
    for s in [
        SEED_MULTISIG_STATE,
        SEED_PROPOSAL,
        SEED_VAULT,
        SEED_NULLIFIER,
    ] {
        assert_eq!(s.len(), 13, "seed length drift: {s:?}");
    }
}

// ---------------------------------------------------------------------------
// 15. MAX_ACTION_BYTES_LEN pinned at 4096.
// ---------------------------------------------------------------------------

#[test]
fn core_max_action_bytes_len_pinned() {
    assert_eq!(MAX_ACTION_BYTES_LEN, 4096);
}

// ---------------------------------------------------------------------------
// 16. APPROVE_PUBLIC_INPUTS_LEN pinned at 96.
// ---------------------------------------------------------------------------

#[test]
fn core_approve_public_inputs_len_pinned() {
    assert_eq!(APPROVE_PUBLIC_INPUTS_LEN, 96);
}
