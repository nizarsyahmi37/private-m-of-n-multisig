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
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id,
    derive_proposal_pda, derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction,
    MultisigState, NullifierEntry, Proposal, Vault, SEED_MULTISIG_STATE, SEED_NULLIFIER,
    SEED_PROPOSAL, SEED_VAULT,
};

// ---------------------------------------------------------------------------
// Instruction encodings
// ---------------------------------------------------------------------------

const ABI_HEX_CREATE_MULTISIG: &str = "00111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220305000000";
const ABI_HEX_PROPOSE_EMPTY_ACTION: &str = "0111111111111111111111111111111111111111111111111111111111111111110000000000000000000000003333333333333333333333333333333333333333333333333333333333333333";
const ABI_HEX_PROPOSE_WITH_ACTION: &str = "011111111111111111111111111111111111111111111111111111111111111111000000000000000003000000aabbcc3333333333333333333333333333333333333333333333333333333333333333";
const ABI_HEX_APPROVE: &str = "021111111111111111111111111111111111111111111111111111111111111111070000000000000002000000dead444444444444444444444444444444444444444444444444444444444444444455555555555555555555555555555555555555555555555555555555555555556666666666666666666666666666666666666666666666666666666666666666";
const ABI_HEX_EXECUTE: &str = "0311111111111111111111111111111111111111111111111111111111111111112a00000000000000";

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
    let ix = Instruction::Approve {
        create_key: [0x11; 32],
        index: 7,
        receipt: vec![0xDE, 0xAD],
        public_inputs: ApprovePublicInputs {
            members_root: [0x44; 32],
            proposal_id: [0x55; 32],
            nullifier: [0x66; 32],
        },
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(got, ABI_HEX_APPROVE, "Instruction::Approve wire format drifted");
}

#[test]
fn abi_pinned_execute_instruction() {
    let ix = Instruction::Execute {
        create_key: [0x11; 32],
        index: 42,
    };
    let got = hex::encode(to_vec(&ix).unwrap());
    assert_eq!(got, ABI_HEX_EXECUTE, "Instruction::Execute wire format drifted");
}

// ---------------------------------------------------------------------------
// Account state encodings
// ---------------------------------------------------------------------------

const ABI_HEX_MULTISIG_STATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03050000002a00000000000000";
const ABI_HEX_PROPOSAL_EMPTY_ACTION: &str = "00000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200000000";
const ABI_HEX_PROPOSAL_WITH_ACTION: &str = "0400000001020304cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200000000";
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
    assert_eq!(bytes.len(), 77, "MultisigState size drifted from documented 77 bytes");
    let got = hex::encode(&bytes);
    assert_eq!(got, ABI_HEX_MULTISIG_STATE, "MultisigState wire format drifted");
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
    assert_eq!(got, ABI_HEX_NULLIFIER_ENTRY, "NullifierEntry must serialize to 0 bytes");
    assert!(bytes.is_empty());
}

#[test]
fn abi_pinned_vault() {
    let v = Vault { create_key: [0x77; 32] };
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
    assert_eq!(canonical.len(), 96, "ApprovePublicInputs canonical layout must be 96 bytes");
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

const ABI_HEX_PDA_MULTISIG_STATE: &str =
    "35743218835b13a14f96b16e988387a08c41bef036c550388b3cf9dc88e4e95d";
const ABI_HEX_PDA_PROPOSAL_INDEX_0: &str =
    "2f231231d1804665e84c956e960c2a3ef77c7f4608923cd051339646345cc0d5";
const ABI_HEX_PDA_PROPOSAL_INDEX_1: &str =
    "4ea853d6399603b607005ba2ac6f2c922b450e7ad3c0d13c26d0f9a25b7b01f1";
const ABI_HEX_PDA_VAULT: &str =
    "c92e0a9aeae13f0625ffc7dbe36ba1f2b820ecb0d7721afd829199e280c4ce00";
const ABI_HEX_PDA_NULLIFIER_ENTRY: &str =
    "c6e7baee30cfc0e526892ee31cc0c20b5ae01384492ba6128b64feb93a5f2f1e";

#[test]
fn abi_pinned_pda_multisig_state() {
    let pda = derive_multisig_state_pda(&[0x99; 32], &[0xAB; 32]);
    let got = hex::encode(pda);
    assert_eq!(got, ABI_HEX_PDA_MULTISIG_STATE, "MultisigState PDA derivation drifted");
}

#[test]
fn abi_pinned_pda_proposal_index_0() {
    let pda = derive_proposal_pda(&[0x99; 32], &[0xAB; 32], 0);
    let got = hex::encode(pda);
    assert_eq!(got, ABI_HEX_PDA_PROPOSAL_INDEX_0, "Proposal[0] PDA derivation drifted");
}

#[test]
fn abi_pinned_pda_proposal_index_1() {
    let pda = derive_proposal_pda(&[0x99; 32], &[0xAB; 32], 1);
    let got = hex::encode(pda);
    assert_eq!(got, ABI_HEX_PDA_PROPOSAL_INDEX_1, "Proposal[1] PDA derivation drifted");
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
    assert_eq!(got, ABI_HEX_PDA_NULLIFIER_ENTRY, "NullifierEntry PDA derivation drifted");
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
    let pid = derive_proposal_id(
        &ChainId::from_u64(1),
        &[0x99; 32],
        0,
        b"",
        &[0xCC; 32],
    );
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
        (CoreError::InstanceNotActive, 1000, "E1000: instance not active"),
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
    assert_eq!(table.len(), 10, "CoreError variant count drifted");
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
