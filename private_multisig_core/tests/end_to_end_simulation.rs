//! End-to-end behavioral simulation of the LP-0002 multisig lifecycle.
//!
//! These tests stand in for the verifier program (step 4) and the Risc0 guest
//! (step 3) by producing the same consensus-critical bytes that those layers
//! will, and asserting the resulting addresses / nullifiers / public-inputs
//! tuples behave correctly across realistic batches of multisig instances.
//!
//! Every test below simulates the SDK + on-chain wire format end-to-end:
//! - identities and Merkle root derivation through `crypto`
//! - `MultisigState` validation, Borsh encoding, PDA derivation
//! - `Propose` / `Approve` / `Execute` instruction round-trips
//! - per-member nullifiers and per-(proposal, nullifier) PDA addresses
//! - cross-instance, cross-chain, and action-mutation invariants

#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_range_loop)]

use std::collections::HashSet;

use borsh::{to_vec, BorshDeserialize};
use crypto::{Identity, MerkleTree, Sha256Hasher};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id,
    derive_proposal_pda, derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction,
    MultisigState, Proposal, APPROVE_PUBLIC_INPUTS_LEN, MAX_ACTION_BYTES_LEN,
};

const PROGRAM_ID: [u8; 32] = [0x99; 32];
const DEFAULT_TARGET_PROGRAM: [u8; 32] = [0xCD; 32];
const DEFAULT_CHAIN_ID_U64: u64 = 0xABCD_EF01;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a deterministic `Identity` from a single seed byte. Same shape as
/// `tests/integration.rs::deterministic_identity` so the two test suites
/// agree on identity material across runs.
fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

/// Build a deterministic `Identity` from two seeds — used when we need more
/// than 256 distinct identities across a batch of instances.
fn identity_from_two(seed_a: u64, seed_b: u64) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    sk[..8].copy_from_slice(&seed_a.to_le_bytes());
    sk[8..16].copy_from_slice(&seed_b.to_le_bytes());
    salt[..8].copy_from_slice(&seed_b.wrapping_add(1).to_le_bytes());
    salt[8..16].copy_from_slice(&seed_a.wrapping_add(2).to_le_bytes());
    // Fill the rest deterministically.
    for i in 16..32 {
        sk[i] = (seed_a.wrapping_add(i as u64) & 0xFF) as u8;
        salt[i] = (seed_b.wrapping_add(i as u64) & 0xFF) as u8;
    }
    Identity::new(sk, salt)
}

fn members_root_for(members: &[Identity]) -> [u8; 32] {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for m in members {
        tree.insert(*m.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    tree.root()
}

/// Full per-instance bundle the harness keeps around so each scenario can
/// assert against the exact byte values an SDK would observe.
struct Instance {
    create_key: [u8; 32],
    state_pda: [u8; 32],
    vault_pda: [u8; 32],
    members: Vec<Identity>,
    members_root: [u8; 32],
    m: u8,
    n: u32,
}

fn build_instance(create_key: [u8; 32], m: u8, n: u32, seed_base: u8) -> Instance {
    assert!(n as usize <= 64, "test harness keeps member counts small");
    let members: Vec<Identity> = (0..n as u8)
        .map(|i| deterministic_identity(seed_base.wrapping_add(i)))
        .collect();
    let members_root = members_root_for(&members);
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &create_key);
    let vault_pda = derive_vault_pda(&PROGRAM_ID, &create_key);
    Instance {
        create_key,
        state_pda,
        vault_pda,
        members,
        members_root,
        m,
        n,
    }
}

/// Borsh-encode a `CreateMultisig` instruction and assert it round-trips. The
/// return value is the wire bytes the SDK would push onto the LEZ transaction.
fn build_create_ix_bytes(inst: &Instance) -> Vec<u8> {
    let ix = Instruction::CreateMultisig {
        create_key: inst.create_key,
        members_root: inst.members_root,
        m: inst.m,
        n: inst.n,
    };
    let bytes = to_vec(&ix).unwrap();
    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, ix);
    bytes
}

fn build_propose_ix_bytes(
    inst: &Instance,
    index: u64,
    action_bytes: &[u8],
    target_program: &[u8; 32],
) -> Vec<u8> {
    let ix = Instruction::Propose {
        create_key: inst.create_key,
        index,
        action_bytes: action_bytes.to_vec(),
        target_program: *target_program,
    };
    let bytes = to_vec(&ix).unwrap();
    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, ix);
    bytes
}

fn build_approve_ix_bytes(
    inst: &Instance,
    index: u64,
    inputs: ApprovePublicInputs,
    receipt: &[u8],
) -> Vec<u8> {
    let ix = Instruction::Approve {
        create_key: inst.create_key,
        index,
        receipt: receipt.to_vec(),
        public_inputs: inputs,
    };
    let bytes = to_vec(&ix).unwrap();
    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, ix);
    bytes
}

fn build_execute_ix_bytes(inst: &Instance, index: u64) -> Vec<u8> {
    let ix = Instruction::Execute {
        create_key: inst.create_key,
        index,
    };
    let bytes = to_vec(&ix).unwrap();
    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, ix);
    bytes
}

// ---------------------------------------------------------------------------
// Scenario 1 — single 3-of-5 happy path
// ---------------------------------------------------------------------------

#[test]
fn e2e_single_multisig_threshold_3_of_5_happy_path() {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    let mut create_key = [0u8; 32];
    rng.fill_bytes(&mut create_key);

    let inst = build_instance(create_key, 3, 5, 1);

    // Validate threshold + state Borsh round-trip.
    assert!(MultisigState::validate_threshold(inst.m, inst.n).is_ok());
    let state = MultisigState {
        create_key: inst.create_key,
        members_root: inst.members_root,
        m: inst.m,
        n: inst.n,
        proposal_count: 0,
    };
    assert!(state.validate().is_ok());
    let state_bytes = to_vec(&state).unwrap();
    assert_eq!(state_bytes.len(), 77);
    let decoded_state = MultisigState::try_from_slice(&state_bytes).unwrap();
    assert_eq!(decoded_state, state);

    // CreateMultisig wire bytes.
    let create_bytes = build_create_ix_bytes(&inst);
    assert_eq!(create_bytes[0], 0, "CreateMultisig is variant 0");

    // Propose: 200-byte action_bytes, target program.
    let mut action_bytes = vec![0u8; 200];
    rng.fill_bytes(&mut action_bytes);
    let target_program = DEFAULT_TARGET_PROGRAM;
    let propose_bytes = build_propose_ix_bytes(&inst, 0, &action_bytes, &target_program);
    assert_eq!(propose_bytes[0], 1, "Propose is variant 1");
    assert!(Proposal::validate_action_bytes(&action_bytes).is_ok());

    let chain_id = ChainId::from_u64(DEFAULT_CHAIN_ID_U64);
    let proposal_id =
        derive_proposal_id(&chain_id, &inst.state_pda, 0, &action_bytes, &target_program);
    assert_ne!(proposal_id, [0u8; 32]);

    let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &inst.create_key, 0);

    // 3 members approve.
    let mut nullifiers = Vec::new();
    let mut nullifier_pdas = Vec::new();
    for (i, member) in inst.members.iter().take(3).enumerate() {
        let nullifier = member.nullifier::<Sha256Hasher>(&proposal_id);
        let inputs = ApprovePublicInputs {
            members_root: inst.members_root,
            proposal_id,
            nullifier,
        };
        let canonical = inputs.to_bytes();
        assert_eq!(canonical.len(), APPROVE_PUBLIC_INPUTS_LEN);
        assert_eq!(ApprovePublicInputs::from_bytes(&canonical), inputs);

        let pda = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &nullifier);
        let approve_bytes = build_approve_ix_bytes(&inst, 0, inputs, b"receipt-bytes");
        assert_eq!(approve_bytes[0], 2, "Approve is variant 2 (member {i})");
        nullifiers.push(nullifier);
        nullifier_pdas.push(pda);
    }

    // All 3 nullifiers distinct.
    {
        let set: HashSet<_> = nullifiers.iter().collect();
        assert_eq!(set.len(), 3, "3 distinct nullifiers expected");
    }
    // All 3 NullifierEntry PDAs distinct.
    {
        let set: HashSet<_> = nullifier_pdas.iter().collect();
        assert_eq!(set.len(), 3, "3 distinct nullifier-entry PDAs expected");
    }

    // Double-vote attempt by member 1 produces the same NullifierEntry PDA.
    let replay_nullifier = inst.members[0].nullifier::<Sha256Hasher>(&proposal_id);
    let replay_pda = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &replay_nullifier);
    assert_eq!(
        replay_pda, nullifier_pdas[0],
        "double-vote PDA must collide with the first approval"
    );

    // Execute round-trip.
    let execute_bytes = build_execute_ix_bytes(&inst, 0);
    assert_eq!(execute_bytes[0], 3, "Execute is variant 3");

    // Six pairwise-distinct addresses: state, vault, proposal, n1, n2, n3.
    let all = [
        inst.state_pda,
        inst.vault_pda,
        proposal_pda,
        nullifier_pdas[0],
        nullifier_pdas[1],
        nullifier_pdas[2],
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "PDA collision between {i} and {j}");
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 2 — 100 multisigs complete lifecycle
// ---------------------------------------------------------------------------

#[test]
fn e2e_hundred_multisigs_complete_lifecycle() {
    let configs: [(u8, u32); 5] = [(1, 1), (2, 3), (3, 5), (5, 7), (10, 10)];

    let mut rng = StdRng::seed_from_u64(0xC0FF_EE00);
    let mut state_pdas = HashSet::new();
    let mut proposal_ids = HashSet::new();
    let mut all_nullifiers = HashSet::new();
    let mut all_nullifier_pdas = HashSet::new();
    let mut all_public_inputs_bytes = Vec::new();

    let mut approval_count = 0usize;

    for batch in 0..20u32 {
        for (cfg_idx, (m, n)) in configs.iter().enumerate() {
            // Distinct create_key per instance using rng — gives unique state PDAs.
            let mut create_key = [0u8; 32];
            rng.fill_bytes(&mut create_key);

            // Identities depend on the batch/cfg pair so member sets vary across
            // instances. Use a unique 16-byte combination per member.
            let members: Vec<Identity> = (0..*n)
                .map(|i| {
                    identity_from_two(
                        (batch as u64) * 1_000 + (cfg_idx as u64),
                        (batch as u64) * 1_000_003 + (cfg_idx as u64) * 17 + (i as u64),
                    )
                })
                .collect();
            let members_root = members_root_for(&members);

            let inst = Instance {
                create_key,
                state_pda: derive_multisig_state_pda(&PROGRAM_ID, &create_key),
                vault_pda: derive_vault_pda(&PROGRAM_ID, &create_key),
                members: members.clone(),
                members_root,
                m: *m,
                n: *n,
            };

            assert!(MultisigState::validate_threshold(inst.m, inst.n).is_ok());
            assert!(state_pdas.insert(inst.state_pda), "state PDA collision");

            // Build + round-trip CreateMultisig.
            let _ = build_create_ix_bytes(&inst);

            // Random action_bytes in [0, 200].
            let action_len = rng.gen_range(0..=200usize);
            let mut action_bytes = vec![0u8; action_len];
            rng.fill_bytes(&mut action_bytes);
            assert!(Proposal::validate_action_bytes(&action_bytes).is_ok());

            let _ = build_propose_ix_bytes(&inst, 0, &action_bytes, &DEFAULT_TARGET_PROGRAM);

            let chain_id = ChainId::from_u64(DEFAULT_CHAIN_ID_U64);
            let proposal_id = derive_proposal_id(
                &chain_id,
                &inst.state_pda,
                0,
                &action_bytes,
                &DEFAULT_TARGET_PROGRAM,
            );
            assert!(
                proposal_ids.insert(proposal_id),
                "duplicate proposal_id across instances"
            );

            let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &inst.create_key, 0);

            // m approvals.
            for member in inst.members.iter().take(inst.m as usize) {
                let nullifier = member.nullifier::<Sha256Hasher>(&proposal_id);
                let inputs = ApprovePublicInputs {
                    members_root: inst.members_root,
                    proposal_id,
                    nullifier,
                };
                let canonical = inputs.to_bytes();
                assert_eq!(canonical.len(), APPROVE_PUBLIC_INPUTS_LEN);
                // Cross-check Borsh = explicit layout.
                let via_borsh = to_vec(&inputs).unwrap();
                assert_eq!(via_borsh, canonical.to_vec());
                assert_eq!(
                    ApprovePublicInputs::from_bytes(&canonical),
                    inputs
                );
                all_public_inputs_bytes.push(canonical);

                assert!(
                    all_nullifiers.insert(nullifier),
                    "nullifier collision across all 100 instances"
                );

                let pda = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &nullifier);
                assert!(
                    all_nullifier_pdas.insert(pda),
                    "nullifier-entry PDA collision across all 100 instances"
                );

                let _ = build_approve_ix_bytes(&inst, 0, inputs, b"receipt");
                approval_count += 1;
            }

            let _ = build_execute_ix_bytes(&inst, 0);
        }
    }

    assert_eq!(state_pdas.len(), 100);
    assert_eq!(proposal_ids.len(), 100);
    // m_avg = (1 + 2 + 3 + 5 + 10) / 5 = 4.2 → 4.2 × 100 = 420 total approvals.
    let expected_approvals = (1 + 2 + 3 + 5 + 10) * 20;
    assert_eq!(approval_count, expected_approvals);
    assert!(approval_count >= 400);
    assert_eq!(all_nullifiers.len(), approval_count);
    assert_eq!(all_nullifier_pdas.len(), approval_count);
    assert_eq!(all_public_inputs_bytes.len(), approval_count);
    for buf in &all_public_inputs_bytes {
        assert_eq!(buf.len(), 96);
    }
}

// ---------------------------------------------------------------------------
// Scenario 3 — many proposals in one instance
// ---------------------------------------------------------------------------

#[test]
fn e2e_many_proposals_in_one_instance() {
    let inst = build_instance([0x42; 32], 3, 5, 0x11);
    let chain_id = ChainId::from_u64(DEFAULT_CHAIN_ID_U64);

    const PROPOSALS: usize = 50;

    // proposal_ids[k] is the proposal_id for index k.
    let mut proposal_ids: Vec<[u8; 32]> = Vec::with_capacity(PROPOSALS);
    let mut proposal_id_set = HashSet::new();
    let mut all_pdas = HashSet::new();

    // For each of the first 3 members, collect (proposal_index → nullifier).
    let mut per_member_nullifiers: Vec<Vec<[u8; 32]>> = (0..3)
        .map(|_| Vec::with_capacity(PROPOSALS))
        .collect();

    for k in 0..PROPOSALS {
        let mut action = b"action-".to_vec();
        action.extend_from_slice(&(k as u32).to_le_bytes());
        action.push(0xAA);
        action.push((k & 0xFF) as u8);
        assert!(Proposal::validate_action_bytes(&action).is_ok());

        let _ = build_propose_ix_bytes(&inst, k as u64, &action, &DEFAULT_TARGET_PROGRAM);

        let proposal_id =
            derive_proposal_id(&chain_id, &inst.state_pda, k as u64, &action, &DEFAULT_TARGET_PROGRAM);
        assert!(proposal_id_set.insert(proposal_id), "duplicate proposal_id");
        proposal_ids.push(proposal_id);

        let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &inst.create_key, k as u64);

        for (member_idx, member) in inst.members.iter().take(3).enumerate() {
            let nullifier = member.nullifier::<Sha256Hasher>(&proposal_id);
            per_member_nullifiers[member_idx].push(nullifier);

            let inputs = ApprovePublicInputs {
                members_root: inst.members_root,
                proposal_id,
                nullifier,
            };
            let _ = build_approve_ix_bytes(&inst, k as u64, inputs, b"receipt");

            let pda = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &nullifier);
            assert!(
                all_pdas.insert(pda),
                "duplicate NullifierEntry PDA for proposal {k}, member {member_idx}"
            );
        }
    }

    // For each member, every pair of proposals has distinct nullifiers
    // (50 × 49 / 2 = 1225 comparisons per member).
    let mut total_pairs = 0usize;
    for member_idx in 0..3 {
        let nulls = &per_member_nullifiers[member_idx];
        let unique: HashSet<_> = nulls.iter().collect();
        assert_eq!(
            unique.len(),
            PROPOSALS,
            "member {member_idx}: nullifiers must be distinct across all 50 proposals"
        );
        // Explicit pairwise check is what the scenario calls for.
        for i in 0..nulls.len() {
            for j in (i + 1)..nulls.len() {
                assert_ne!(
                    nulls[i], nulls[j],
                    "member {member_idx}: nullifier collision at ({i}, {j})"
                );
                total_pairs += 1;
            }
        }
    }
    assert_eq!(total_pairs, 3 * (PROPOSALS * (PROPOSALS - 1) / 2));
    assert_eq!(total_pairs, 3 * 1225);
    assert_eq!(all_pdas.len(), 3 * PROPOSALS);
}

// ---------------------------------------------------------------------------
// Scenario 4 — cross-instance replay blocked by proposal_id
// ---------------------------------------------------------------------------

#[test]
fn e2e_cross_instance_replay_blocked_by_proposal_id() {
    let inst_a = build_instance([0x01; 32], 3, 5, 0x10);
    let inst_b = build_instance([0x02; 32], 3, 5, 0x10);

    // Same member seed_base on both — same Identity material.
    assert_eq!(inst_a.members.len(), inst_b.members.len());
    for (a, b) in inst_a.members.iter().zip(inst_b.members.iter()) {
        assert_eq!(a.sk, b.sk);
        assert_eq!(a.salt, b.salt);
    }
    // Same members_root because same identities.
    assert_eq!(inst_a.members_root, inst_b.members_root);

    // Different create_key → different state PDA.
    assert_ne!(inst_a.create_key, inst_b.create_key);
    assert_ne!(inst_a.state_pda, inst_b.state_pda);

    let action_bytes = b"treasury_withdraw(100)".to_vec();
    let chain_id = ChainId::from_u64(DEFAULT_CHAIN_ID_U64);

    let pid_a = derive_proposal_id(
        &chain_id,
        &inst_a.state_pda,
        0,
        &action_bytes,
        &DEFAULT_TARGET_PROGRAM,
    );
    let pid_b = derive_proposal_id(
        &chain_id,
        &inst_b.state_pda,
        0,
        &action_bytes,
        &DEFAULT_TARGET_PROGRAM,
    );
    assert_ne!(pid_a, pid_b, "cross-instance proposal_id must differ");

    // Member 1's nullifier on (A, 0) vs (B, 0).
    let n_a = inst_a.members[0].nullifier::<Sha256Hasher>(&pid_a);
    let n_b = inst_b.members[0].nullifier::<Sha256Hasher>(&pid_b);
    assert_ne!(n_a, n_b, "cross-instance nullifier must differ");
}

// ---------------------------------------------------------------------------
// Scenario 5 — cross-chain replay blocked by chain_id
// ---------------------------------------------------------------------------

#[test]
fn e2e_cross_chain_replay_blocked_by_chain_id() {
    let inst = build_instance([0x33; 32], 3, 5, 0x77);
    let action_bytes = b"send_usdc(0xdead)".to_vec();
    let target_program = DEFAULT_TARGET_PROGRAM;

    let pid_1 = derive_proposal_id(
        &ChainId::from_u64(1),
        &inst.state_pda,
        0,
        &action_bytes,
        &target_program,
    );
    let pid_2 = derive_proposal_id(
        &ChainId::from_u64(2),
        &inst.state_pda,
        0,
        &action_bytes,
        &target_program,
    );
    assert_ne!(pid_1, pid_2);

    let n_1 = inst.members[0].nullifier::<Sha256Hasher>(&pid_1);
    let n_2 = inst.members[0].nullifier::<Sha256Hasher>(&pid_2);
    assert_ne!(n_1, n_2, "cross-chain nullifier must differ");

    // Different chain → different NullifierEntry PDA (proposal PDA is the same
    // because it only depends on create_key + index, but the nullifier differs).
    let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &inst.create_key, 0);
    let pda_1 = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &n_1);
    let pda_2 = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &n_2);
    assert_ne!(pda_1, pda_2);
}

// ---------------------------------------------------------------------------
// Scenario 6 — action mutation invalidates existing approvals
// ---------------------------------------------------------------------------

#[test]
fn e2e_action_mutation_invalidates_existing_approvals() {
    let inst = build_instance([0x44; 32], 3, 5, 0x88);
    let chain_id = ChainId::from_u64(DEFAULT_CHAIN_ID_U64);

    let original = b"approve".to_vec();
    let mutated = b"approve_mutated".to_vec();

    let pid_old = derive_proposal_id(
        &chain_id,
        &inst.state_pda,
        0,
        &original,
        &DEFAULT_TARGET_PROGRAM,
    );
    let pid_new = derive_proposal_id(
        &chain_id,
        &inst.state_pda,
        0,
        &mutated,
        &DEFAULT_TARGET_PROGRAM,
    );
    assert_ne!(pid_old, pid_new);

    // The approval the member already produced commits `pid_old` to its
    // public_inputs journal. After the action mutates on-chain the verifier
    // would recompute `pid_new` from the proposal state — the receipt's
    // proposal_id no longer matches.
    let member = &inst.members[0];
    let nullifier_old = member.nullifier::<Sha256Hasher>(&pid_old);
    let approval = ApprovePublicInputs {
        members_root: inst.members_root,
        proposal_id: pid_old,
        nullifier: nullifier_old,
    };
    assert_ne!(approval.proposal_id, pid_new);

    // Member's nullifier on the mutated action also differs.
    let nullifier_new = member.nullifier::<Sha256Hasher>(&pid_new);
    assert_ne!(nullifier_old, nullifier_new);
}

// ---------------------------------------------------------------------------
// Scenario 7 — m == n requires unanimous
// ---------------------------------------------------------------------------

#[test]
fn e2e_instance_with_m_eq_n_requires_unanimous() {
    let inst = build_instance([0x55; 32], 5, 5, 0x33);
    assert!(MultisigState::validate_threshold(inst.m, inst.n).is_ok());
    assert_eq!(inst.m as u32, inst.n);

    let action = b"unanimous-action".to_vec();
    let _ = build_propose_ix_bytes(&inst, 0, &action, &DEFAULT_TARGET_PROGRAM);

    let chain_id = ChainId::from_u64(DEFAULT_CHAIN_ID_U64);
    let proposal_id =
        derive_proposal_id(&chain_id, &inst.state_pda, 0, &action, &DEFAULT_TARGET_PROGRAM);
    let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &inst.create_key, 0);

    let mut nullifiers = HashSet::new();
    let mut pdas = HashSet::new();
    for member in inst.members.iter() {
        let n = member.nullifier::<Sha256Hasher>(&proposal_id);
        let inputs = ApprovePublicInputs {
            members_root: inst.members_root,
            proposal_id,
            nullifier: n,
        };
        let _ = build_approve_ix_bytes(&inst, 0, inputs, b"r");
        let pda = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &n);
        assert!(nullifiers.insert(n));
        assert!(pdas.insert(pda));
    }
    assert_eq!(nullifiers.len(), 5);
    assert_eq!(pdas.len(), 5);
}

// ---------------------------------------------------------------------------
// Scenario 8 — validate_threshold rejects bad state in lifecycle
// ---------------------------------------------------------------------------

#[test]
fn e2e_validate_threshold_rejects_bad_state_in_lifecycle() {
    assert_eq!(
        MultisigState::validate_threshold(0, 5),
        Err(CoreError::InvalidThreshold)
    );
    assert_eq!(
        MultisigState::validate_threshold(3, 0),
        Err(CoreError::InvalidThreshold)
    );
    assert_eq!(
        MultisigState::validate_threshold(6, 5),
        Err(CoreError::InvalidThreshold)
    );
    assert!(MultisigState::validate_threshold(5, 5).is_ok());

    // Bad-state struct also rejects via .validate().
    let bad = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 0,
        n: 5,
        proposal_count: 0,
    };
    assert_eq!(bad.validate(), Err(CoreError::InvalidThreshold));
    // E1003 numeric code is part of the on-chain ABI.
    assert_eq!(CoreError::InvalidThreshold.code(), 1003);

    // Even though .validate() rejects, Borsh layer cannot — bytes still
    // round-trip. The on-chain handler is the only place the rejection
    // surfaces.
    let bytes = to_vec(&bad).unwrap();
    let decoded = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, bad);
    assert_eq!(decoded.validate(), Err(CoreError::InvalidThreshold));
}

// ---------------------------------------------------------------------------
// Scenario 9 — action_bytes at MAX_ACTION_BYTES_LEN works
// ---------------------------------------------------------------------------

#[test]
fn e2e_action_bytes_at_max_size_works() {
    let inst = build_instance([0x66; 32], 3, 5, 0x44);

    let mut action = vec![0u8; MAX_ACTION_BYTES_LEN];
    // Distinguishable content so we can verify the hash is not the all-zero
    // hash by accident.
    for (i, b) in action.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    assert_eq!(action.len(), 4096);
    assert!(Proposal::validate_action_bytes(&action).is_ok());

    let chain_id = ChainId::from_u64(DEFAULT_CHAIN_ID_U64);
    let proposal_id =
        derive_proposal_id(&chain_id, &inst.state_pda, 0, &action, &DEFAULT_TARGET_PROGRAM);
    assert_ne!(proposal_id, [0u8; 32]);

    let propose_bytes = build_propose_ix_bytes(&inst, 0, &action, &DEFAULT_TARGET_PROGRAM);
    // Sanity: 4096 action bytes must show up in the encoded instruction.
    assert!(propose_bytes.len() >= 4096);

    // Proposal struct Borsh round-trip carrying the max-size action bytes.
    let prop = Proposal {
        action_bytes: action.clone(),
        target_program: DEFAULT_TARGET_PROGRAM,
        approvals_count: 0,
        executed: false,
    };
    let bytes = to_vec(&prop).unwrap();
    let decoded = Proposal::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, prop);

    // Approve also encodes cleanly with max-size action proposal_id.
    let nullifier = inst.members[0].nullifier::<Sha256Hasher>(&proposal_id);
    let inputs = ApprovePublicInputs {
        members_root: inst.members_root,
        proposal_id,
        nullifier,
    };
    let _ = build_approve_ix_bytes(&inst, 0, inputs, b"r");
}

// ---------------------------------------------------------------------------
// Scenario 10 — action_bytes over MAX rejected by validate_action_bytes
// ---------------------------------------------------------------------------

#[test]
fn e2e_action_bytes_over_max_size_rejected() {
    let inst = build_instance([0x77; 32], 3, 5, 0x55);

    let action = vec![0xCDu8; MAX_ACTION_BYTES_LEN + 1];
    assert_eq!(action.len(), 4097);
    assert_eq!(
        Proposal::validate_action_bytes(&action),
        Err(CoreError::ActionBytesTooLong)
    );
    assert_eq!(CoreError::ActionBytesTooLong.code(), 1002);

    // Borsh layer is purely syntactic — cap is semantic. The instruction
    // still serializes. The on-chain handler is what rejects it.
    let ix = Instruction::Propose {
        create_key: inst.create_key,
        index: 0,
        action_bytes: action.clone(),
        target_program: DEFAULT_TARGET_PROGRAM,
    };
    let bytes = to_vec(&ix).unwrap();
    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded, ix);

    let prop = Proposal {
        action_bytes: action,
        target_program: DEFAULT_TARGET_PROGRAM,
        approvals_count: 0,
        executed: false,
    };
    let pb = to_vec(&prop).unwrap();
    let p_decoded = Proposal::try_from_slice(&pb).unwrap();
    assert_eq!(p_decoded, prop);
    // But validate still rejects it.
    assert_eq!(
        Proposal::validate_action_bytes(&prop.action_bytes),
        Err(CoreError::ActionBytesTooLong)
    );
}

// ---------------------------------------------------------------------------
// Scenario 11 — 1000 random full lifecycles, smoke at scale
// ---------------------------------------------------------------------------

#[test]
fn e2e_thousand_random_full_lifecycles() {
    let mut rng = StdRng::seed_from_u64(0x1234_5678_9ABC_DEF0);

    // (m, n) options the random sampler picks from.
    let mn_options: [(u8, u32); 6] =
        [(1, 1), (1, 5), (2, 3), (3, 5), (5, 7), (10, 10)];

    let mut state_pdas = HashSet::new();
    let mut proposal_ids = HashSet::new();
    let mut all_nullifiers = HashSet::new();
    let mut all_nullifier_pdas = HashSet::new();

    let mut total_approvals = 0usize;

    for iter in 0..1000u32 {
        let (m, n) = mn_options[rng.gen_range(0..mn_options.len())];
        let mut create_key = [0u8; 32];
        rng.fill_bytes(&mut create_key);
        let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &create_key);
        assert!(state_pdas.insert(state_pda));

        // Build n identities from per-iteration seeds.
        let members: Vec<Identity> = (0..n)
            .map(|i| identity_from_two(iter as u64 * 1_000_003, i as u64 * 31 + iter as u64))
            .collect();
        let members_root = members_root_for(&members);

        let inst = Instance {
            create_key,
            state_pda,
            vault_pda: derive_vault_pda(&PROGRAM_ID, &create_key),
            members,
            members_root,
            m,
            n,
        };

        // Threshold + Borsh round-trip.
        assert!(MultisigState::validate_threshold(m, n).is_ok());
        let _ = build_create_ix_bytes(&inst);

        // Random action_bytes up to MAX_ACTION_BYTES_LEN (smaller for speed —
        // cap at 256 here; the max-size case is exercised by scenario 9).
        let action_len = rng.gen_range(0..=256usize);
        let mut action_bytes = vec![0u8; action_len];
        rng.fill_bytes(&mut action_bytes);

        // Random target_program.
        let mut target_program = [0u8; 32];
        rng.fill_bytes(&mut target_program);

        // Random chain_id and proposal index.
        let chain_id = ChainId::from_u64(rng.gen_range(1u64..=1024));
        let index: u64 = rng.gen_range(0u64..=64);

        let _ = build_propose_ix_bytes(&inst, index, &action_bytes, &target_program);

        let proposal_id = derive_proposal_id(
            &chain_id,
            &inst.state_pda,
            index,
            &action_bytes,
            &target_program,
        );
        // proposal_id is not required to be globally unique across the 1000
        // (chain_id varies independently and index could repeat) but with
        // random create_key it should be — assert and surface any collision.
        assert!(
            proposal_ids.insert(proposal_id),
            "proposal_id collision at iter {iter}"
        );

        let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &inst.create_key, index);

        for member in inst.members.iter().take(inst.m as usize) {
            let nullifier = member.nullifier::<Sha256Hasher>(&proposal_id);
            let inputs = ApprovePublicInputs {
                members_root: inst.members_root,
                proposal_id,
                nullifier,
            };
            let canonical = inputs.to_bytes();
            assert_eq!(canonical.len(), 96);

            assert!(
                all_nullifiers.insert(nullifier),
                "nullifier collision at iter {iter}"
            );

            let pda = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &nullifier);
            assert!(
                all_nullifier_pdas.insert(pda),
                "nullifier-entry PDA collision at iter {iter}"
            );

            let _ = build_approve_ix_bytes(&inst, index, inputs, b"r");
            total_approvals += 1;
        }

        let _ = build_execute_ix_bytes(&inst, index);
    }

    assert_eq!(state_pdas.len(), 1000);
    assert_eq!(proposal_ids.len(), 1000);
    assert!(total_approvals >= 1000); // m >= 1 for every config.
    assert_eq!(all_nullifiers.len(), total_approvals);
    assert_eq!(all_nullifier_pdas.len(), total_approvals);
}
