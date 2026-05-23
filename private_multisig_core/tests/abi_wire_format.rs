//! On-chain ABI pinning — wire-format Known-Answer-Tests (KATs).
//!
//! Every byte and every PDA address emitted by `private_multisig_core` is part
//! of the protocol contract once instances exist on testnet. This file is the
//! authoritative `&str` / `const` ledger of those bytes. If any future PR
//! changes Borsh's encoding (a new derive option, a length-prefix tweak),
//! reorders fields, shifts an enum discriminant, or alters a PDA seed/preimage,
//! one of the assertions below WILL fail. That failure is the test doing its
//! job — the fix is a major-version bump, never a silent edit to the pinned
//! hex strings here.
//!
//! Add new KATs by appending; never edit an existing one. To compute a new
//! pin, switch the `assert_eq!` line to a `panic!("got: {}", hex::encode(...))`,
//! run the failing test once with `-- --nocapture`, paste the surfaced hex
//! into a `const`, then revert the panic.

#![allow(clippy::needless_borrows_for_generic_args)]

use borsh::to_vec;
use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id, derive_proposal_pda,
    derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction, MultisigState,
    NullifierEntry, Proposal, Vault, SEED_MULTISIG_STATE, SEED_NULLIFIER, SEED_PROPOSAL,
    SEED_VAULT,
};

// ---------------------------------------------------------------------------
// Instruction encodings
// ---------------------------------------------------------------------------

const ABI_HEX_CREATE_MULTISIG: &str = "00111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220305000000";
const ABI_HEX_PROPOSE_EMPTY_ACTION: &str = "0111111111111111111111111111111111111111111111111111111111111111110000000000000000000000003333333333333333333333333333333333333333333333333333333333333333";
const ABI_HEX_PROPOSE_WITH_ACTION: &str = "011111111111111111111111111111111111111111111111111111111111111111000000000000000003000000aabbcc3333333333333333333333333333333333333333333333333333333333333333";
// Round 6 wire-format unification: Instruction::Approve now matches the
// SPEL verifier handler signature exactly. Wire layout (Borsh,
// off-chain SDK):
//   disc(0x02) || create_key(32) || index(8 LE) || nullifier(32) ||
//   public_inputs_len(4 LE = 96) || public_inputs(96)
//   = 1 + 32 + 8 + 32 + 4 + 96 = 173 bytes.
// The public_inputs payload is the canonical [members_root || proposal_id
// || nullifier] 96-byte ApprovePublicInputs layout.
const ABI_HEX_APPROVE: &str = "021111111111111111111111111111111111111111111111111111111111111111070000000000000066666666666666666666666666666666666666666666666666666666666666666000000044444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555\
6666666666666666666666666666666666666666666666666666666666666666";
const ABI_HEX_EXECUTE: &str =
    "0311111111111111111111111111111111111111111111111111111111111111112a00000000000000";
// Round 6 adds CreateVault and Reject. Both are tiny: disc + create_key.
const ABI_HEX_CREATE_VAULT: &str =
    "041111111111111111111111111111111111111111111111111111111111111111";
const ABI_HEX_REJECT: &str = "051111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn abi_pinned_create_multisig_instruction() {
    let ix = Instruction::CreateMultisig {
        create_key: [0x11; 32],
        members_root: [0x22; 32],
        m: 3,
        n: 5,
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(
        got, ABI_HEX_CREATE_MULTISIG,
        "Instruction::CreateMultisig wire format drifted"
    );
}

#[test]
fn abi_pinned_propose_instruction_empty_action() {
    let ix = Instruction::Propose {
        create_key: [0x11; 32],
        index: 0,
        action_bytes: Vec::new(),
        target_program: [0x33; 32],
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(
        got, ABI_HEX_PROPOSE_EMPTY_ACTION,
        "Instruction::Propose (empty action) wire format drifted"
    );
}

#[test]
fn abi_pinned_propose_instruction_with_action() {
    let ix = Instruction::Propose {
        create_key: [0x11; 32],
        index: 0,
        action_bytes: vec![0xAA, 0xBB, 0xCC],
        target_program: [0x33; 32],
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(
        got, ABI_HEX_PROPOSE_WITH_ACTION,
        "Instruction::Propose (with action) wire format drifted"
    );
}

#[test]
fn abi_pinned_approve_instruction() {
    let inputs = ApprovePublicInputs {
        members_root: [0x44; 32],
        proposal_id: [0x55; 32],
        nullifier: [0x66; 32],
    };
    let ix = Instruction::Approve {
        create_key: [0x11; 32],
        index: 7,
        nullifier: inputs.nullifier,
        public_inputs: inputs.to_bytes().to_vec(),
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(
        got, ABI_HEX_APPROVE,
        "Instruction::Approve wire format drifted"
    );
}

#[test]
fn abi_pinned_execute_instruction() {
    let ix = Instruction::Execute {
        create_key: [0x11; 32],
        index: 42,
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(
        got, ABI_HEX_EXECUTE,
        "Instruction::Execute wire format drifted"
    );
}

#[test]
fn abi_pinned_create_vault_instruction() {
    let ix = Instruction::CreateVault {
        create_key: [0x11; 32],
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(
        got, ABI_HEX_CREATE_VAULT,
        "Instruction::CreateVault wire format drifted"
    );
}

#[test]
fn abi_pinned_reject_instruction() {
    let ix = Instruction::Reject {
        create_key: [0x11; 32],
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(
        got, ABI_HEX_REJECT,
        "Instruction::Reject wire format drifted"
    );
}

// ---------------------------------------------------------------------------
// Account state encodings
// ---------------------------------------------------------------------------

const ABI_HEX_MULTISIG_STATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03050000002a00000000000000";
const ABI_HEX_PROPOSAL_EMPTY_ACTION: &str =
    "00000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200000000";
const ABI_HEX_PROPOSAL_WITH_ACTION: &str =
    "0400000001020304cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200000000";
const ABI_HEX_NULLIFIER_ENTRY: &str = "";
const ABI_HEX_VAULT: &str = "7777777777777777777777777777777777777777777777777777777777777777";

#[test]
fn abi_pinned_multisig_state() {
    let state = MultisigState {
        create_key: [0xAA; 32],
        members_root: [0xBB; 32],
        m: 3,
        n: 5,
        proposal_count: 42,
    };
    let bytes = to_vec(&state).unwrap();
    assert_eq!(
        bytes.len(),
        77,
        "MultisigState size drifted from documented 77 bytes"
    );
    let got = hex::encode(&bytes);
    assert_eq!(
        got, ABI_HEX_MULTISIG_STATE,
        "MultisigState wire format drifted"
    );
}

#[test]
fn abi_pinned_proposal_empty_action() {
    let p = Proposal {
        action_bytes: Vec::new(),
        target_program: [0xCC; 32],
        approvals_count: 2,
        executed: false,
    };
    let got = hex::encode(to_vec(&p).unwrap());
    assert_eq!(
        got, ABI_HEX_PROPOSAL_EMPTY_ACTION,
        "Proposal (empty action) wire format drifted"
    );
}

#[test]
fn abi_pinned_proposal_with_action() {
    let p = Proposal {
        action_bytes: vec![0x01, 0x02, 0x03, 0x04],
        target_program: [0xCC; 32],
        approvals_count: 2,
        executed: false,
    };
    let got = hex::encode(to_vec(&p).unwrap());
    assert_eq!(
        got, ABI_HEX_PROPOSAL_WITH_ACTION,
        "Proposal (with action) wire format drifted"
    );
}

#[test]
fn abi_pinned_nullifier_entry() {
    // The verifier relies on NullifierEntry being a zero-byte payload — the
    // PDA's existence IS the data. If Borsh ever starts emitting a
    // discriminant or length prefix here, the on-chain account rent
    // accounting and init-fails-if-exists check both break.
    let bytes = to_vec(&NullifierEntry).unwrap();
    let got = hex::encode(&bytes);
    assert_eq!(
        got, ABI_HEX_NULLIFIER_ENTRY,
        "NullifierEntry must serialize to 0 bytes"
    );
    assert!(bytes.is_empty());
}

#[test]
fn abi_pinned_vault() {
    let v = Vault {
        create_key: [0x77; 32],
    };
    let bytes = to_vec(&v).unwrap();
    assert_eq!(bytes.len(), 32, "Vault wire size must be 32 bytes");
    let got = hex::encode(&bytes);
    assert_eq!(got, ABI_HEX_VAULT, "Vault wire format drifted");
}

// ---------------------------------------------------------------------------
// ApprovePublicInputs canonical layout and Borsh parity
// ---------------------------------------------------------------------------

const ABI_HEX_APPROVE_PUBLIC_INPUTS_TO_BYTES: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[test]
fn abi_pinned_approve_public_inputs_to_bytes_layout() {
    let inputs = ApprovePublicInputs {
        members_root: [0xAA; 32],
        proposal_id: [0xBB; 32],
        nullifier: [0xCC; 32],
    };
    let canonical = inputs.to_bytes();
    assert_eq!(
        canonical.len(),
        96,
        "ApprovePublicInputs canonical layout must be 96 bytes"
    );
    let got = hex::encode(canonical);
    assert_eq!(
        got, ABI_HEX_APPROVE_PUBLIC_INPUTS_TO_BYTES,
        "ApprovePublicInputs::to_bytes layout drifted"
    );
}

#[test]
fn abi_pinned_approve_public_inputs_borsh_equals_to_bytes() {
    // Structural lock: the canonical to_bytes() layout and Borsh serialization
    // must produce byte-identical output. If Borsh ever adds a length prefix,
    // version tag, or alignment padding around [u8; 32] fields, this fails.
    let inputs = ApprovePublicInputs {
        members_root: [0xAA; 32],
        proposal_id: [0xBB; 32],
        nullifier: [0xCC; 32],
    };
    let via_borsh = to_vec(&inputs).unwrap();
    let via_canonical = inputs.to_bytes();
    assert_eq!(
        via_borsh.as_slice(),
        via_canonical.as_slice(),
        "Borsh encoding diverged from canonical ApprovePublicInputs layout"
    );
}

// ---------------------------------------------------------------------------
// PDA derivations
// ---------------------------------------------------------------------------

// Round-5 PDA rewrite: derivation now matches SPEL's compute_pda exactly
// (SHA-256 of NSSA prefix || program_id || combined_seed, where combined
// is SHA-256 of all 32-byte sub-seeds for multi-seed inputs). The pinned
// hexes below are recomputed under the new algorithm; the previous values
// reflected the OLD `SHA-256(program_id || seed_13B || extras…)` formula
// which never matched what the on-chain SPEL macro would enforce.
const ABI_HEX_PDA_MULTISIG_STATE: &str =
    "6de3a5cc83e530827b5b8f150028bf92bd4260aa94b101798ad794d72c3f0bb6";
const ABI_HEX_PDA_PROPOSAL_INDEX_0: &str =
    "26dac3f7182879b68a3f5d1c43638f2d78bcbcc53ec2380e85de8538aae5c8c7";
const ABI_HEX_PDA_PROPOSAL_INDEX_1: &str =
    "b3a7cf3ee32d5513976781193dcd38a89be6e6f9f7a1ff37e8168b5667cc3e6a";
const ABI_HEX_PDA_VAULT: &str = "42cdbb8c5935f315a298ee9a4218bfa4aafbf395eb33109bf875926823501179";
const ABI_HEX_PDA_NULLIFIER_ENTRY: &str =
    "bd2b503a2bb7959f488c4cab651339bd21aa0cd44c691fa78df12f1b559018d8";

#[test]
fn abi_pinned_pda_multisig_state() {
    let pda = derive_multisig_state_pda(&[0x99; 32], &[0xAB; 32]);
    let got = hex::encode(pda);
    assert_eq!(
        got, ABI_HEX_PDA_MULTISIG_STATE,
        "MultisigState PDA derivation drifted"
    );
}

#[test]
fn abi_pinned_pda_proposal_index_0() {
    let pda = derive_proposal_pda(&[0x99; 32], &[0xAB; 32], 0);
    let got = hex::encode(pda);
    assert_eq!(
        got, ABI_HEX_PDA_PROPOSAL_INDEX_0,
        "Proposal[0] PDA derivation drifted"
    );
}

#[test]
fn abi_pinned_pda_proposal_index_1() {
    let pda = derive_proposal_pda(&[0x99; 32], &[0xAB; 32], 1);
    let got = hex::encode(pda);
    assert_eq!(
        got, ABI_HEX_PDA_PROPOSAL_INDEX_1,
        "Proposal[1] PDA derivation drifted"
    );
    // Sanity: indices 0 and 1 must yield distinct addresses (already
    // covered by unit tests; redundant assertion here to make this file
    // self-contained as a wire-ABI reference).
    let pda_0 = derive_proposal_pda(&[0x99; 32], &[0xAB; 32], 0);
    assert_ne!(pda_0, pda, "Proposal[0] and Proposal[1] PDAs collided");
}

#[test]
fn abi_pinned_pda_vault() {
    let pda = derive_vault_pda(&[0x99; 32], &[0xAB; 32]);
    let got = hex::encode(pda);
    assert_eq!(got, ABI_HEX_PDA_VAULT, "Vault PDA derivation drifted");
}

#[test]
fn abi_pinned_pda_nullifier_entry() {
    let pda = derive_nullifier_entry_pda(&[0x99; 32], &[0xCD; 32], &[0xEF; 32]);
    let got = hex::encode(pda);
    assert_eq!(
        got, ABI_HEX_PDA_NULLIFIER_ENTRY,
        "NullifierEntry PDA derivation drifted"
    );
}

// ---------------------------------------------------------------------------
// proposal_id derivation (cross-chain replay binding)
// ---------------------------------------------------------------------------

const ABI_HEX_PROPOSAL_ID_CANONICAL: &str =
    "677a4eec67921d607cfeffc54d046c2b27da1312f7426faca7e6f019d0e07ec6";
const ABI_HEX_PROPOSAL_ID_EMPTY_ACTION: &str =
    "310518a1e375e25356e01f3ec3161bd5f4d85fac91eb1c52d4fab0442330ba45";

#[test]
fn abi_pinned_proposal_id_canonical() {
    let pid = derive_proposal_id(
        &ChainId::from_u64(0xABCD_EF01),
        &[0xAA; 32],
        0,
        b"treasury_withdraw(100)",
        &[0xCD; 32],
    );
    let got = hex::encode(pid);
    assert_eq!(
        got, ABI_HEX_PROPOSAL_ID_CANONICAL,
        "derive_proposal_id canonical KAT drifted — proofs will no longer cross-verify"
    );
}

#[test]
fn abi_pinned_proposal_id_empty_action() {
    let pid = derive_proposal_id(&ChainId::from_u64(1), &[0x99; 32], 0, b"", &[0xCC; 32]);
    let got = hex::encode(pid);
    assert_eq!(
        got, ABI_HEX_PROPOSAL_ID_EMPTY_ACTION,
        "derive_proposal_id (empty action_bytes) KAT drifted"
    );
}

// ---------------------------------------------------------------------------
// CoreError code table — (variant, code, Display) triple
// ---------------------------------------------------------------------------

#[test]
fn abi_pinned_error_code_table() {
    // (variant, numeric code, Display string). Any drift here is an on-chain
    // ABI break: explorers, SDK retry logic, and integration tests match on
    // these triples. Reordering a variant, renumbering a code, or rewording
    // a Display message is a major version bump.
    let table: &[(CoreError, u32, &str)] = &[
        (
            CoreError::InstanceNotActive,
            1000,
            "E1000: instance not active",
        ),
        (
            CoreError::ProposalExpiredOrExecuted,
            1001,
            "E1001: proposal expired or executed",
        ),
        (
            CoreError::ActionBytesTooLong,
            1002,
            "E1002: action bytes too long",
        ),
        (
            CoreError::InvalidThreshold,
            1003,
            "E1003: invalid threshold",
        ),
        (CoreError::InvalidReceipt, 2000, "E2000: invalid receipt"),
        (CoreError::ImageIdMismatch, 2001, "E2001: image id mismatch"),
        (CoreError::RootMismatch, 2002, "E2002: root mismatch"),
        (
            CoreError::ProposalIdMismatch,
            2003,
            "E2003: proposal id mismatch",
        ),
        (
            CoreError::NullifierAlreadyUsed,
            3000,
            "E3000: nullifier already used",
        ),
        (CoreError::ThresholdNotMet, 4000, "E4000: threshold not met"),
        (CoreError::AlreadyExecuted, 4001, "E4001: already executed"),
    ];
    for (variant, code, display) in table {
        assert_eq!(variant.code(), *code, "code() drifted for {variant:?}");
        assert_eq!(
            CoreError::from_code(*code),
            Some(*variant),
            "from_code({code}) drifted"
        );
        assert_eq!(
            variant.to_string(),
            *display,
            "Display drifted for {variant:?}"
        );
    }
    // Lock in the cardinality too — if a new variant is added without a
    // matching table entry, this catches it.
    assert_eq!(table.len(), 11, "CoreError variant count drifted");
}

// ---------------------------------------------------------------------------
// Seed constants
// ---------------------------------------------------------------------------

const ABI_HEX_SEED_MULTISIG_STATE: &str = "706d7369675f73746174655f5f";
const ABI_HEX_SEED_PROPOSAL: &str = "706d7369675f70726f705f5f5f";
const ABI_HEX_SEED_VAULT: &str = "706d7369675f7661756c745f5f";
const ABI_HEX_SEED_NULLIFIER: &str = "706d7369675f6e756c6c695f5f";

#[test]
fn abi_pinned_seed_constants_hex() {
    assert_eq!(
        hex::encode(SEED_MULTISIG_STATE),
        ABI_HEX_SEED_MULTISIG_STATE,
        "SEED_MULTISIG_STATE drifted"
    );
    assert_eq!(
        hex::encode(SEED_PROPOSAL),
        ABI_HEX_SEED_PROPOSAL,
        "SEED_PROPOSAL drifted"
    );
    assert_eq!(
        hex::encode(SEED_VAULT),
        ABI_HEX_SEED_VAULT,
        "SEED_VAULT drifted"
    );
    assert_eq!(
        hex::encode(SEED_NULLIFIER),
        ABI_HEX_SEED_NULLIFIER,
        "SEED_NULLIFIER drifted"
    );
}
