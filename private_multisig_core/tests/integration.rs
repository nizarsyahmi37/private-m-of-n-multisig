//! End-to-end integration test exercising the public surface in the same
//! shape the client SDK / verifier will exercise it at step 4.

use borsh::{to_vec, BorshDeserialize};
use crypto::{Identity, MerkleTree, Sha256Hasher};
use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id,
    derive_proposal_pda, derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction,
    MultisigState, Proposal, APPROVE_PUBLIC_INPUTS_LEN, MAX_ACTION_BYTES_LEN, SEED_MULTISIG_STATE,
    SEED_PROPOSAL,
};

const PROGRAM_ID: [u8; 32] = [0x99; 32];
const CREATE_KEY: [u8; 32] = [0xAB; 32];
const TARGET_PROGRAM: [u8; 32] = [0xCD; 32];
const CHAIN_ID_U64: u64 = 0xABCD_EF01;

fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

#[test]
fn full_create_propose_approve_execute_round_trip() {
    // ---- Setup: derive the multisig PDA, build the member set, freeze root.
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let proposal_pda_0 = derive_proposal_pda(&PROGRAM_ID, &CREATE_KEY, 0);
    let _vault_pda = derive_vault_pda(&PROGRAM_ID, &CREATE_KEY);

    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for m in &members {
        tree.insert(*m.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let members_root = tree.root();

    // ---- CreateMultisig instruction round-trip.
    let create_ix = Instruction::CreateMultisig {
        create_key: CREATE_KEY,
        members_root,
        m: 3,
        n: 5,
    };
    let bytes = to_vec(&create_ix).unwrap();
    assert_eq!(Instruction::try_from_slice(&bytes).unwrap(), create_ix);

    // ---- Propose: derive proposal_id, build instruction.
    let action_bytes = b"treasury_withdraw(100)".to_vec();
    let chain_id = ChainId::from_u64(CHAIN_ID_U64);
    let proposal_id = derive_proposal_id(
        &chain_id,
        &state_pda,
        0,
        &action_bytes,
        &TARGET_PROGRAM,
    );
    assert_ne!(proposal_id, [0u8; 32]);

    let propose_ix = Instruction::Propose {
        create_key: CREATE_KEY,
        index: 0,
        action_bytes: action_bytes.clone(),
        target_program: TARGET_PROGRAM,
    };
    let bytes = to_vec(&propose_ix).unwrap();
    assert_eq!(Instruction::try_from_slice(&bytes).unwrap(), propose_ix);

    // ---- Approve: simulate the client computing public_inputs the way the
    //               circuit will.
    for member in members.iter().take(3) {
        let nullifier = member.nullifier::<Sha256Hasher>(&proposal_id);
        let inputs = ApprovePublicInputs {
            members_root,
            proposal_id,
            nullifier,
        };
        // Canonical 96-byte layout serializes byte-for-byte:
        let canonical = inputs.to_bytes();
        assert_eq!(canonical.len(), APPROVE_PUBLIC_INPUTS_LEN);
        assert_eq!(ApprovePublicInputs::from_bytes(&canonical), inputs);

        // Per-member nullifier address is what the verifier will init-fail-
        // if-exists. Each member produces a distinct PDA address.
        let nullifier_pda =
            derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda_0, &nullifier);
        assert_ne!(nullifier_pda, [0u8; 32]);

        let approve_ix = Instruction::Approve {
            create_key: CREATE_KEY,
            index: 0,
            public_inputs: inputs,
        };
        let bytes = to_vec(&approve_ix).unwrap();
        assert_eq!(Instruction::try_from_slice(&bytes).unwrap(), approve_ix);
    }

    // ---- Execute round-trip.
    let execute_ix = Instruction::Execute {
        create_key: CREATE_KEY,
        index: 0,
    };
    let bytes = to_vec(&execute_ix).unwrap();
    assert_eq!(Instruction::try_from_slice(&bytes).unwrap(), execute_ix);
}

#[test]
fn distinct_members_on_same_proposal_produce_distinct_nullifiers() {
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let chain_id = ChainId::from_u64(1);
    let proposal_id = derive_proposal_id(
        &chain_id,
        &state_pda,
        0,
        b"action",
        &TARGET_PROGRAM,
    );

    let m1 = deterministic_identity(1);
    let m2 = deterministic_identity(2);
    let m3 = deterministic_identity(3);

    let n1 = m1.nullifier::<Sha256Hasher>(&proposal_id);
    let n2 = m2.nullifier::<Sha256Hasher>(&proposal_id);
    let n3 = m3.nullifier::<Sha256Hasher>(&proposal_id);

    assert_ne!(n1, n2);
    assert_ne!(n1, n3);
    assert_ne!(n2, n3);
}

#[test]
fn same_member_same_proposal_same_nullifier_double_vote_pda_collision() {
    // The on-chain `Approve` handler attempts to init the NullifierEntry
    // PDA at seeds (proposal_pda, nullifier). If the same member tries to
    // vote twice the nullifier is byte-identical, so the second init
    // targets the same address and fails.
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &CREATE_KEY, 0);
    let chain_id = ChainId::from_u64(1);
    let proposal_id = derive_proposal_id(
        &chain_id,
        &state_pda,
        0,
        b"action",
        &TARGET_PROGRAM,
    );

    let member = deterministic_identity(5);
    let n1 = member.nullifier::<Sha256Hasher>(&proposal_id);
    let n2 = member.nullifier::<Sha256Hasher>(&proposal_id);
    assert_eq!(n1, n2);

    let pda1 = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &n1);
    let pda2 = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pda, &n2);
    assert_eq!(pda1, pda2);
}

#[test]
fn same_member_different_proposals_distinct_nullifiers() {
    // Same member voting on different proposals must produce distinct
    // nullifiers — otherwise approving proposal A would block approving
    // proposal B.
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let chain_id = ChainId::from_u64(1);
    let pid_a = derive_proposal_id(
        &chain_id,
        &state_pda,
        0,
        b"action_a",
        &TARGET_PROGRAM,
    );
    let pid_b = derive_proposal_id(
        &chain_id,
        &state_pda,
        1,
        b"action_b",
        &TARGET_PROGRAM,
    );
    assert_ne!(pid_a, pid_b);

    let member = deterministic_identity(7);
    let n_a = member.nullifier::<Sha256Hasher>(&pid_a);
    let n_b = member.nullifier::<Sha256Hasher>(&pid_b);
    assert_ne!(n_a, n_b);
}

#[test]
fn cross_chain_replay_is_blocked_at_proposal_id_layer() {
    // The same multisig + action + index but a different chain_id
    // produces a different proposal_id. An attacker replaying a receipt
    // from devnet onto testnet/mainnet would face a proposal_id mismatch
    // at the verifier.
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let pid_dev = derive_proposal_id(
        &ChainId::from_u64(1),
        &state_pda,
        0,
        b"action",
        &TARGET_PROGRAM,
    );
    let pid_main = derive_proposal_id(
        &ChainId::from_u64(2),
        &state_pda,
        0,
        b"action",
        &TARGET_PROGRAM,
    );
    assert_ne!(pid_dev, pid_main);
}

#[test]
fn action_mutation_invalidates_proposal_id() {
    // Bind-action invariant: if `action_bytes` mutates between Propose
    // and Approve, the verifier recomputes proposal_id from CURRENT
    // on-chain state and the receipt's committed proposal_id no longer
    // matches.
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let chain_id = ChainId::from_u64(1);
    let pid_original = derive_proposal_id(
        &chain_id,
        &state_pda,
        0,
        b"action",
        &TARGET_PROGRAM,
    );
    let pid_mutated = derive_proposal_id(
        &chain_id,
        &state_pda,
        0,
        b"action_mutated",
        &TARGET_PROGRAM,
    );
    assert_ne!(pid_original, pid_mutated);
}

#[test]
fn pda_addresses_used_by_full_flow_are_pairwise_distinct() {
    let state = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let proposal_0 = derive_proposal_pda(&PROGRAM_ID, &CREATE_KEY, 0);
    let proposal_1 = derive_proposal_pda(&PROGRAM_ID, &CREATE_KEY, 1);
    let vault = derive_vault_pda(&PROGRAM_ID, &CREATE_KEY);
    let null_entry = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_0, &[0xAA; 32]);

    let all = [state, proposal_0, proposal_1, vault, null_entry];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "pda collision between {i} and {j}");
        }
    }
}

#[test]
fn multisig_state_round_trip_via_borsh() {
    let state = MultisigState {
        create_key: CREATE_KEY,
        members_root: [0xDE; 32],
        m: 3,
        n: 5,
        proposal_count: 0,
    };
    let bytes = to_vec(&state).unwrap();
    let decoded = MultisigState::try_from_slice(&bytes).unwrap();
    assert_eq!(state, decoded);
}

#[test]
fn proposal_size_cap_is_4_kib() {
    assert_eq!(MAX_ACTION_BYTES_LEN, 4096);
    let valid = vec![0xCDu8; MAX_ACTION_BYTES_LEN];
    let invalid = vec![0xCDu8; MAX_ACTION_BYTES_LEN + 1];
    assert!(Proposal::validate_action_bytes(&valid).is_ok());
    assert!(Proposal::validate_action_bytes(&invalid).is_err());
}

#[test]
fn error_catalog_codes_are_stable() {
    assert_eq!(CoreError::InstanceNotActive.code(), 1000);
    assert_eq!(CoreError::ProposalIdMismatch.code(), 2003);
    assert_eq!(CoreError::NullifierAlreadyUsed.code(), 3000);
    assert_eq!(CoreError::AlreadyExecuted.code(), 4001);
}

#[test]
fn seed_constants_match_documented_strings() {
    assert_eq!(SEED_MULTISIG_STATE, b"pmsig_state__");
    assert_eq!(SEED_PROPOSAL, b"pmsig_prop___");
}
