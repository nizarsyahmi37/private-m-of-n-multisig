//! End-to-end prove-and-verify test for the LP-0002 approve circuit.
//!
//! The flow this test exercises is exactly what the SDK will run for a real
//! approval:
//!
//! 1. Build a member-set Merkle tree (depth 20, SHA-256 + domain separation).
//! 2. Pick a member, derive its Merkle proof against the live root.
//! 3. Compute `proposal_id` for a synthetic proposal using the canonical
//!    `derive_proposal_id` formula from `private_multisig_core`.
//! 4. Pack the public-input prefix (`members_root || proposal_id`) plus the
//!    private witness (`sk || salt || siblings_flat || direction_bytes`)
//!    into the Risc0 `ExecutorEnv`.
//! 5. Run the prover under `RISC0_DEV_MODE=1` (skips the SNARK heavy lift
//!    but still executes the guest and produces a verifiable receipt).
//! 6. Verify the receipt against `APPROVE_CIRCUIT_IMAGE_ID`.
//! 7. Decode the 96-byte journal as `ApprovePublicInputs` and assert every
//!    field matches what the host computed independently.
//!
//! Set `RISC0_DEV_MODE=0` and re-run to exercise the real prover; the
//! assertions are identical and the test simply takes longer.

use std::env;

use crypto::{Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH};
use private_multisig_core::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

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
fn approve_circuit_proves_and_verifies_a_real_member_approval() {
    // Risc0's "dev mode" skips proof generation but still runs the guest and
    // produces a verifiable receipt, so the same test exercises the byte-
    // exact flow without the multi-minute proving cost. Unset / set to "0"
    // for a real proving run.
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: this is a single-threaded test process; no other thread
        // is reading the env at this point.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }

    // ----- Member set: enroll 5 identities, capture the frozen root. --------
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let members_root = tree.root();

    // ----- Pick member index 2 and derive its proof against the live root. -
    let approver_index = 2usize;
    let approver = &members[approver_index];
    let proof = tree.proof(approver_index).unwrap();

    // ----- Derive proposal_id for a synthetic proposal. ---------------------
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    let proposal_id = derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program);

    // ----- Compute expected nullifier and public-input bundle on the host. --
    let expected_nullifier = approver.nullifier::<Sha256Hasher>(&proposal_id);
    let expected_bundle = ApprovePublicInputs {
        members_root,
        proposal_id,
        nullifier: expected_nullifier,
    };

    // ----- Pack public-input prefix (64 bytes) for the guest. ---------------
    let mut public_prefix = [0u8; 64];
    public_prefix[..32].copy_from_slice(&members_root);
    public_prefix[32..].copy_from_slice(&proposal_id);

    // ----- Flatten the merkle path into a single byte buffer. ---------------
    let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = level * HASH_LEN;
        siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
    }
    let mut direction_bytes = [0u8; MERKLE_DEPTH];
    for (level, bit) in proof.indices.iter().enumerate() {
        direction_bytes[level] = u8::from(*bit);
    }

    // ----- Build the Risc0 ExecutorEnv (host → guest input stream). ---------
    let env_builder = ExecutorEnv::builder()
        .write_slice(&public_prefix)
        .write_slice(&approver.sk)
        .write_slice(&approver.salt)
        .write_slice(&siblings_flat)
        .write_slice(&direction_bytes)
        .build()
        .expect("ExecutorEnv build must succeed");

    // ----- Prove. ----------------------------------------------------------
    let prover = default_prover();
    let prove_info = prover
        .prove(env_builder, APPROVE_CIRCUIT_ELF)
        .expect("prover must produce a receipt for a valid witness");
    let receipt = prove_info.receipt;

    // ----- Verify against the pinned image-id. -----------------------------
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("receipt must verify against APPROVE_CIRCUIT_IMAGE_ID");

    // ----- Decode the journal and assert byte-exact match with host expect. -
    let journal_bytes = receipt.journal.bytes.as_slice();
    assert_eq!(
        journal_bytes.len(),
        APPROVE_PUBLIC_INPUTS_LEN,
        "journal must be the canonical 96-byte ApprovePublicInputs bundle"
    );
    let mut journal_arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    journal_arr.copy_from_slice(journal_bytes);
    let decoded = ApprovePublicInputs::from_bytes(&journal_arr);

    assert_eq!(decoded, expected_bundle, "journal disagreed with host");
    assert_eq!(decoded.members_root, members_root);
    assert_eq!(decoded.proposal_id, proposal_id);
    assert_eq!(decoded.nullifier, expected_nullifier);
}
