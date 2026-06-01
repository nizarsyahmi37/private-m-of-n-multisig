//! SDK-consumer perspective audit.
//!
//! These tests exercise `private_multisig_core` the way `private_multisig_sdk`
//! will exercise it next week: generating member identities, constructing
//! instructions, deriving PDAs, computing `proposal_id`, packing public
//! inputs for the Risc0 circuit, validating user input, decoding chain
//! errors, and persisting partial-approval session state across restarts.
//!
//! Each test is named `sdk_consumer_<scenario>` and includes inline notes
//! about any ergonomic gap surfaced — those are the items the SDK will need
//! to wrap.

#![allow(clippy::too_many_lines, clippy::similar_names)]

use std::collections::{BTreeMap, HashMap};

use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use crypto::{Hasher, Identity, IdentityCommitment, MerkleTree, Sha256Hasher};
use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id, derive_proposal_pda,
    derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction, MultisigState,
    Proposal, APPROVE_PUBLIC_INPUTS_LEN, MAX_ACTION_BYTES_LEN,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

// ---------------------------------------------------------------------------
// Helpers (the kind of thing the SDK will likely wrap)
// ---------------------------------------------------------------------------

const PROGRAM_ID: [u8; 32] = [0x99; 32];
const CREATE_KEY: [u8; 32] = [0xAB; 32];
const TARGET_PROGRAM: [u8; 32] = [0xCD; 32];

/// Deterministic identity helper. Real SDK will pull `sk` and `salt` from a
/// CSPRNG; we use `StdRng` with a fixed seed so failures are reproducible.
fn rng_identity(rng: &mut StdRng) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut sk);
    rng.fill_bytes(&mut salt);
    Identity::new(sk, salt)
}

/// Build a Merkle tree over `n` member commitments and return both the tree
/// and the per-member identity vector so the test can also look up which
/// identity sits at which leaf index.
fn build_member_set(n: usize, rng: &mut StdRng) -> (Vec<Identity>, MerkleTree<Sha256Hasher>) {
    let members: Vec<Identity> = (0..n).map(|_| rng_identity(rng)).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for m in &members {
        // ERGONOMIC FRICTION (Annoyance): `MerkleTree::insert` takes
        // `Hash = [u8; 32]` by value. `IdentityCommitment::as_bytes()`
        // returns `&[u8; 32]` so we have to dereference (`*`) at every call
        // site. The SDK will probably wrap this as
        // `tree.insert_commitment(&commitment)` to hide the dereference.
        tree.insert(*m.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    (members, tree)
}

// ---------------------------------------------------------------------------
// Scenario 1 — identity + commitment
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_can_generate_member_identity_and_commit() {
    // The "CLI generates a member key" flow: a user passes `sk` + `salt`
    // (sourced from `secrecy::Secret<[u8;32]>` in the real SDK) and gets
    // back a 32-byte commitment ready to be enrolled.
    let mut rng = StdRng::seed_from_u64(0xC0DEC0DE);
    let id = rng_identity(&mut rng);

    // The commitment type is `IdentityCommitment(Hash)`. Determinism check.
    let c1: IdentityCommitment = id.commitment::<Sha256Hasher>();
    let c2: IdentityCommitment = id.commitment::<Sha256Hasher>();
    assert_eq!(c1, c2, "commitment must be deterministic in (sk, salt)");

    // The 32-byte payload is reachable via `.as_bytes()`.
    let bytes: &[u8; 32] = c1.as_bytes();
    assert_eq!(bytes.len(), 32);

    // FRICTION (Annoyance): the natural call `tree.insert(&commitment)` does
    // not compile — `insert` takes `Hash` by value (`[u8; 32]`) and
    // `IdentityCommitment` does not implement `Into<[u8;32]>` or
    // `Borrow<[u8;32]>`. The SDK author has to write `*c.as_bytes()`. We
    // pin the working form below so any future API change that breaks it
    // surfaces immediately.
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    tree.insert(*c1.as_bytes()).unwrap();
    assert_eq!(tree.len(), 1);

    // Debug must redact secret material — protects CLI logs from leaking sk.
    let debug_render = format!("{id:?}");
    assert!(debug_render.contains("REDACTED"));
}

// ---------------------------------------------------------------------------
// Scenario 2 — CreateMultisig instruction construction
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_can_construct_create_multisig_instruction() {
    let mut rng = StdRng::seed_from_u64(2);
    let (_members, tree) = build_member_set(5, &mut rng);

    // FRICTION (Annoyance): there is no helper such as
    // `Instruction::create_multisig_with_members(&[Identity], m)` that takes
    // an identity slice and folds them into a Merkle root, nor a
    // `MultisigBuilder` that bundles `(create_key, members_root, m, n)`. The
    // consumer constructs the variant directly, which means every SDK call
    // site has to remember to: build the Merkle tree, take the root, compute
    // `n = members.len() as u32`, pick `m`, and rebind `create_key`. Easy to
    // forget the `n` cast or to pass `m > n`. Suggested fix: add
    // `Instruction::create_multisig(create_key, members_root, m, n) -> Self`
    // plus `MultisigState::validate_threshold` (already exists, see
    // scenario 9) as a pre-flight gate.
    let ix = Instruction::CreateMultisig {
        create_key: CREATE_KEY,
        members_root: tree.root(),
        m: 3,
        n: 5,
    };

    // Round-trip to confirm the variant we just constructed is wire-stable.
    let bytes = to_vec(&ix).unwrap();
    let decoded = Instruction::try_from_slice(&bytes).unwrap();
    assert_eq!(ix, decoded);

    // Variant discriminant is 0 (CreateMultisig is first). The SDK relies on
    // this for fast "what kind of ix is this?" sniffing without full decode.
    assert_eq!(bytes[0], 0);
}

// ---------------------------------------------------------------------------
// Scenario 3 — derive all PDAs a consumer needs for one instance
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_can_derive_all_needed_pdas() {
    // One instance, four proposals (0..3), one approval nullifier — covers
    // the full PDA-derivation surface an SDK call site touches.
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let vault_pda = derive_vault_pda(&PROGRAM_ID, &CREATE_KEY);
    let proposal_pdas: Vec<[u8; 32]> = (0..4u64)
        .map(|i| derive_proposal_pda(&PROGRAM_ID, &CREATE_KEY, i))
        .collect();

    // All four proposal PDAs must be distinct from each other and from the
    // state and vault PDAs — anything else would let `Approve` for one
    // proposal collide with the state of a sibling.
    for (i, p) in proposal_pdas.iter().enumerate() {
        assert_ne!(*p, state_pda, "proposal[{i}] collides with state");
        assert_ne!(*p, vault_pda, "proposal[{i}] collides with vault");
    }
    for i in 0..proposal_pdas.len() {
        for j in (i + 1)..proposal_pdas.len() {
            assert_ne!(proposal_pdas[i], proposal_pdas[j]);
        }
    }

    // Nullifier-entry PDA for proposal 0, one fake nullifier value.
    let fake_nullifier = [0x77u8; 32];
    let nullifier_pda = derive_nullifier_entry_pda(&PROGRAM_ID, &proposal_pdas[0], &fake_nullifier);
    assert_ne!(nullifier_pda, state_pda);
    assert_ne!(nullifier_pda, proposal_pdas[0]);

    // FRICTION (Nit): every PDA helper takes `&ProgramId` and the SDK will
    // almost certainly carry a fixed `program_id` on a `Client` struct. The
    // signature is fine (consumers will write `client.state_pda()` etc.),
    // but `derive_nullifier_entry_pda` taking `&AccountId` for the proposal
    // PDA position is easy to confuse with the `state_pda`. Suggested fix:
    // newtype `ProposalPda(AccountId)` so the compiler catches argument
    // swaps at the call site.
}

// ---------------------------------------------------------------------------
// Scenario 4 — ChainId from a domain string
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_compute_proposal_id_with_string_chain_id() {
    // FRICTION (Annoyance): `ChainId` exposes `new([u8; 32])` and
    // `from_u64(u64)`. The LEZ chain-id today is a domain string such as
    // `"lez-testnet-v1"`. No `ChainId::from_str(&str)` helper exists.
    //
    // Workaround used here: hash the domain string with the same
    // `Sha256Hasher` the rest of the crate uses, wrap with `ChainId::new`.
    // The SDK will need to ship this as
    // `ChainId::from_domain(&str) -> Self` (or `from_str`) so every consumer
    // hashes the same way. Without that helper, two SDKs that pick
    // different prehash schemes will derive divergent `proposal_id`s and
    // proofs will silently fail to verify cross-chain. High-leverage fix
    // for a tiny API addition.
    let cid = ChainId::new(Sha256Hasher::hash(b"lez-testnet-v1"));
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);

    let pid = derive_proposal_id(
        &cid,
        &state_pda,
        0,
        b"treasury_withdraw(100)",
        &TARGET_PROGRAM,
    );
    assert_ne!(pid, [0u8; 32]);

    // Sanity: a different chain string must yield a different proposal_id.
    let other = ChainId::new(Sha256Hasher::hash(b"lez-mainnet-v1"));
    let pid_other = derive_proposal_id(
        &other,
        &state_pda,
        0,
        b"treasury_withdraw(100)",
        &TARGET_PROGRAM,
    );
    assert_ne!(pid, pid_other);
}

// ---------------------------------------------------------------------------
// Scenario 5 — tracking pending approvals locally
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_track_pending_approvals_by_proposal_id() {
    // The SDK keeps a local store of `(proposal_id, status)` per user. This
    // must work with both `HashMap` (fast lookup) and `BTreeMap` (stable
    // iteration order for the UI). Since `proposal_id` is `[u8; 32]`, all
    // the derived trait bounds are satisfied by the standard library.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[allow(dead_code)]
    enum Status {
        Drafted,
        Proving,
        Submitted,
        Confirmed,
    }

    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let cid = ChainId::from_u64(1);

    let mut hash_store: HashMap<[u8; 32], Status> = HashMap::new();
    let mut btree_store: BTreeMap<[u8; 32], Status> = BTreeMap::new();

    for i in 0..4u64 {
        let pid = derive_proposal_id(&cid, &state_pda, i, b"noop", &TARGET_PROGRAM);
        hash_store.insert(pid, Status::Drafted);
        btree_store.insert(pid, Status::Drafted);
    }

    assert_eq!(hash_store.len(), 4);
    assert_eq!(btree_store.len(), 4);

    // Update one entry: simulate the user moving past `Proving`.
    let pid_0 = derive_proposal_id(&cid, &state_pda, 0, b"noop", &TARGET_PROGRAM);
    hash_store.insert(pid_0, Status::Submitted);
    btree_store.insert(pid_0, Status::Submitted);
    assert_eq!(hash_store.get(&pid_0), Some(&Status::Submitted));
    assert_eq!(btree_store.get(&pid_0), Some(&Status::Submitted));

    // BTreeMap iteration order is byte-lex over `proposal_id` — deterministic
    // and useful for snapshot-comparing two clients' local state.
    let ordered: Vec<[u8; 32]> = btree_store.keys().copied().collect();
    let mut sorted = ordered.clone();
    sorted.sort();
    assert_eq!(ordered, sorted);

    // No extra trait gymnastics needed — confirms `proposal_id: [u8; 32]`
    // is everything the SDK's local store needs.
}

// ---------------------------------------------------------------------------
// Scenario 6 — wire-size sentinel for the most common Approve
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_serialize_and_deserialize_approve_for_submission() {
    // The most common Approve case: receipt is 256 bytes (well under the
    // STARK receipt size budget, exact final number TBD per PLAN.md step 1),
    // public_inputs is the canonical 96-byte bundle.
    //
    // Layout breakdown:
    //   1 byte   enum discriminant
    //   32 bytes create_key
    //   8 bytes  index (u64 LE)
    //   4 bytes  Vec<u8> length prefix for receipt
    //   256 bytes receipt body
    //   96 bytes ApprovePublicInputs (3 × 32, no length prefix)
    //   -----
    //   397 bytes total
    //
    // Pin the number. If a future PR adds a version byte or changes a
    // length prefix width, this assertion catches the wire break before it
    // ships to the verifier.
    // Round 5 dropped `receipt: Vec<u8>` from Instruction::Approve, so the
    // Round 6 unified Instruction::Approve with the verifier handler.
    // The Borsh wire is now disc(1) + create_key(32) + index(8) +
    // nullifier(32) + public_inputs_len(4) + public_inputs(96) = 173
    // bytes for the canonical 96-byte ApprovePublicInputs payload. The
    // verifier accepts the SAME enum via SPEL's external_instruction
    // route and decodes via risc0_zkvm::serde::Deserializer.
    let inputs = ApprovePublicInputs {
        members_root: [0x11; 32],
        proposal_id: [0x22; 32],
        nullifier: [0x33; 32],
    };
    let ix = Instruction::Approve {
        create_key: CREATE_KEY,
        index: 0,
        nullifier: inputs.nullifier,
        public_inputs: inputs.to_bytes().to_vec(),
    };

    let bytes = to_vec(&ix).expect("serialize Approve");
    assert_eq!(
        bytes.len(),
        1 + 32 + 8 + 32 + 4 + 96,
        "wire size drifted from the 173-byte Approve sentinel"
    );
    assert_eq!(bytes.len(), 173);

    // Round-trip back through Borsh — what the SDK does locally.
    let decoded = Instruction::try_from_slice(&bytes).expect("deserialize Approve");
    assert_eq!(ix, decoded);

    // Variant discriminant 2 (Approve is third).
    assert_eq!(bytes[0], 2);
}

// ---------------------------------------------------------------------------
// Scenario 7 — partial-approval session state machine
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_build_partial_approval_state_machine() {
    // PLAN.md Reliability requires the SDK to survive client restarts during
    // the multi-step approval flow (draft → prove → submit → confirm). The
    // SDK will model this as a state machine and persist it via Borsh.
    //
    // Confirms core ships everything we need: the canonical 96-byte public
    // inputs, the `proposal_id`, the `nullifier`, and the `CoreError` codes
    // returned from chain — nothing else is needed to drive the state
    // machine and resume after a restart.

    #[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    enum ApprovalSession {
        Drafted {
            proposal_id: [u8; 32],
            index: u64,
        },
        Proving {
            proposal_id: [u8; 32],
            index: u64,
            // Public inputs are known the moment the user clicks "approve",
            // BEFORE the receipt comes back — so a session that died
            // mid-Risc0-prove can be resumed without redoing the witness
            // wiring.
            public_inputs: ApprovePublicInputs,
        },
        Proved {
            proposal_id: [u8; 32],
            index: u64,
            public_inputs: ApprovePublicInputs,
            receipt: Vec<u8>,
        },
        Submitted {
            proposal_id: [u8; 32],
            index: u64,
            tx_id: [u8; 32],
        },
        Confirmed {
            proposal_id: [u8; 32],
            index: u64,
        },
    }

    let mut rng = StdRng::seed_from_u64(7);
    let (members, tree) = build_member_set(5, &mut rng);
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let cid = ChainId::from_u64(1);
    let proposal_id = derive_proposal_id(&cid, &state_pda, 0, b"action", &TARGET_PROGRAM);

    // The "Proving" state carries enough to resume after a restart.
    let inputs = ApprovePublicInputs {
        members_root: tree.root(),
        proposal_id,
        nullifier: members[0].nullifier::<Sha256Hasher>(&proposal_id),
    };
    let session = ApprovalSession::Proving {
        proposal_id,
        index: 0,
        public_inputs: inputs,
    };

    // Borsh round-trip: what gets written to disk and read back.
    let bytes = to_vec(&session).unwrap();
    let restored = ApprovalSession::try_from_slice(&bytes).unwrap();
    assert_eq!(session, restored);

    // A Submitted session is what survives the user closing the CLI before
    // chain confirmation arrives. The tx_id is opaque to the core crate.
    let later = ApprovalSession::Submitted {
        proposal_id,
        index: 0,
        tx_id: [0xEE; 32],
    };
    let bytes2 = to_vec(&later).unwrap();
    let restored2 = ApprovalSession::try_from_slice(&bytes2).unwrap();
    assert_eq!(later, restored2);

    // No gaps surfaced: every field the state machine carries comes from
    // either the core crate or a chain-issued opaque blob.
}

// ---------------------------------------------------------------------------
// Scenario 8 — nullifier without exposing sk
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_compute_nullifier_for_member_pkproposal() {
    // Round-2 added `Identity::nullifier::<H>(&proposal_id)` precisely so
    // the SDK can compute a member's nullifier without ever pulling `sk`
    // out of the `Identity` struct into a wider scope. Confirms the helper
    // is present and that it matches the free `crypto::nullifier` function
    // byte-for-byte.
    let mut rng = StdRng::seed_from_u64(8);
    let id = rng_identity(&mut rng);
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);
    let proposal_id = derive_proposal_id(
        &ChainId::from_u64(1),
        &state_pda,
        0,
        b"action",
        &TARGET_PROGRAM,
    );

    // SDK call site stays clean: no `&id.sk` floating around.
    let n_via_helper = id.nullifier::<Sha256Hasher>(&proposal_id);

    // Equivalence to the free function, which is what the on-chain
    // verifier and the Risc0 guest call.
    let n_via_free = crypto::nullifier::<Sha256Hasher>(&id.sk, &proposal_id);
    assert_eq!(n_via_helper, n_via_free);

    // Distinct proposals MUST yield distinct nullifiers, otherwise the
    // double-vote check breaks across proposals.
    let pid_other = derive_proposal_id(
        &ChainId::from_u64(1),
        &state_pda,
        1,
        b"action",
        &TARGET_PROGRAM,
    );
    let n_other = id.nullifier::<Sha256Hasher>(&pid_other);
    assert_ne!(n_via_helper, n_other);
}

// ---------------------------------------------------------------------------
// Scenario 9 — pre-flight validation
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_validate_user_input_before_submission() {
    // Before the SDK ships an instruction over the wire, it gates input on
    // the same checks the verifier runs. Both helpers return `CoreError` so
    // the SDK error type can flatten directly.

    // Threshold: zero, n=0, and m > n all rejected.
    assert!(MultisigState::validate_threshold(3, 5).is_ok());
    assert_eq!(
        MultisigState::validate_threshold(0, 5),
        Err(CoreError::InvalidThreshold),
    );
    assert_eq!(
        MultisigState::validate_threshold(3, 0),
        Err(CoreError::InvalidThreshold),
    );
    assert_eq!(
        MultisigState::validate_threshold(6, 5),
        Err(CoreError::InvalidThreshold),
    );

    // Action bytes: at-cap accepted, over-cap rejected.
    assert!(Proposal::validate_action_bytes(&[]).is_ok());
    assert!(Proposal::validate_action_bytes(&vec![0u8; MAX_ACTION_BYTES_LEN]).is_ok());
    assert_eq!(
        Proposal::validate_action_bytes(&vec![0u8; MAX_ACTION_BYTES_LEN + 1]),
        Err(CoreError::ActionBytesTooLong),
    );

    // Both helpers return the SAME error type — the SDK error enum only
    // needs one `#[from] CoreError` arm.
    let err: CoreError = MultisigState::validate_threshold(0, 0).unwrap_err();
    assert_eq!(err.code(), 1003);
}

// ---------------------------------------------------------------------------
// Scenario 10 — error-code lifting
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_can_inspect_error_codes_from_chain() {
    // When the verifier rejects a tx, the LEZ runtime returns a `u32` error
    // code in the tx result. The SDK has to lift that back to a typed
    // variant so consumers can match on it (e.g. retry on `NullifierAlreadyUsed`
    // → "you already voted", surface `RootMismatch` → "your local member set
    // is stale").
    //
    // Every documented code in PLAN.md step 4 must lift cleanly.
    let documented = [
        (1000u32, CoreError::InstanceNotActive),
        (1001, CoreError::ProposalExpiredOrExecuted),
        (1002, CoreError::ActionBytesTooLong),
        (1003, CoreError::InvalidThreshold),
        (2000, CoreError::InvalidReceipt),
        (2001, CoreError::ImageIdMismatch),
        (2002, CoreError::RootMismatch),
        (2003, CoreError::ProposalIdMismatch),
        (3000, CoreError::NullifierAlreadyUsed),
        (4000, CoreError::ThresholdNotMet),
        (4001, CoreError::AlreadyExecuted),
    ];
    for (code, expected) in documented {
        assert_eq!(
            CoreError::from_code(code),
            Some(expected),
            "code {code} must lift to {expected:?}"
        );
        // Round-trip: variant -> code -> variant.
        assert_eq!(expected.code(), code);
    }

    // Unknown codes must return None (never silently coerce to a variant).
    assert_eq!(CoreError::from_code(0), None);
    assert_eq!(CoreError::from_code(9999), None);
    assert_eq!(CoreError::from_code(u32::MAX), None);

    // Display strings carry the `E…` code so log greps work.
    assert!(CoreError::NullifierAlreadyUsed
        .to_string()
        .contains("E3000"));
}

// ---------------------------------------------------------------------------
// Scenario 11 — packing for the Risc0 circuit
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_pack_approve_public_inputs_for_circuit() {
    // The Risc0 guest reads its journal as the canonical 96-byte layout, NOT
    // Borsh. The SDK packs via `to_bytes()` before handing off to the
    // prover. Confirms:
    //   - layout is exactly `members_root || proposal_id || nullifier`
    //   - length matches the `APPROVE_PUBLIC_INPUTS_LEN` constant
    //   - round-trip via `from_bytes` is bit-exact
    //   - Borsh encoding happens to match the canonical layout (parity),
    //     so a SDK that accidentally Borsh-encodes still produces correct
    //     journal bytes — defense in depth.
    let inputs = ApprovePublicInputs {
        members_root: [0xAA; 32],
        proposal_id: [0xBB; 32],
        nullifier: [0xCC; 32],
    };

    let canonical = inputs.to_bytes();
    assert_eq!(canonical.len(), APPROVE_PUBLIC_INPUTS_LEN);
    assert_eq!(canonical.len(), 96);

    assert_eq!(&canonical[..32], &[0xAA; 32]);
    assert_eq!(&canonical[32..64], &[0xBB; 32]);
    assert_eq!(&canonical[64..96], &[0xCC; 32]);

    // Round-trip.
    let recovered = ApprovePublicInputs::from_bytes(&canonical);
    assert_eq!(recovered, inputs);

    // Parity with Borsh — the SDK never relies on this, but it means any
    // accidental Borsh path still emits the correct bytes.
    let via_borsh = to_vec(&inputs).unwrap();
    assert_eq!(via_borsh.len(), APPROVE_PUBLIC_INPUTS_LEN);
    assert_eq!(via_borsh.as_slice(), canonical.as_slice());

    // Note on perf: round-3 benches put `to_bytes` ~2.5× faster than Borsh
    // (no allocator, fixed-size array, no length prefix). Not retested
    // here — that lives in `benches/core_bench.rs` — but the SDK should
    // prefer `to_bytes()` on the hot path.
}

// ---------------------------------------------------------------------------
// Scenario 12 — doc audit on crate-root re-exports
// ---------------------------------------------------------------------------

#[test]
fn sdk_consumer_doc_audit() {
    // Pulls each src file and checks that every `pub` item the crate root
    // re-exports has at least one `///` line immediately above it. Anything
    // without a docstring fails the assertion with a clear message.
    //
    // The check is intentionally simple: we read the source and look for a
    // `///` immediately preceding (or, allowing `#[derive(...)]` between)
    // the `pub` line. False positives are acceptable for an SDK-readiness
    // audit; false negatives would let an undocumented item slip past.

    fn has_doc_above(source: &str, needle: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let Some(idx) = lines
            .iter()
            .position(|l| l.trim_start().starts_with(needle))
        else {
            return false;
        };
        // Walk upward, looking for `///` while transparently consuming
        // anything that could be a preceding attribute. Attributes can
        // span multiple lines (`#[derive(\n    Foo, Bar,\n)]`), so we
        // track bracket depth.
        let mut i = idx;
        let mut depth: i32 = 0;
        while i > 0 {
            i -= 1;
            let raw = lines[i];
            let trimmed = raw.trim_start();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("///") {
                return true;
            }
            // Update bracket depth from this line's `[` / `]` so we keep
            // walking through multi-line `#[derive(...)]` blocks.
            let opens = raw.matches('[').count() as i32;
            let closes = raw.matches(']').count() as i32;
            depth += closes - opens;
            if depth > 0 || trimmed.starts_with("#[") || trimmed.starts_with("#![") {
                // Either we are still inside an unclosed attribute walking
                // backwards, or this line opens one.
                continue;
            }
            // Hit a real code line with no docstring above.
            return false;
        }
        false
    }

    // Each (file, needle, label) probes one re-exported pub item.
    let lib = include_str!("../src/lib.rs");
    let pda = include_str!("../src/pda.rs");
    let proof = include_str!("../src/proof.rs");
    let state = include_str!("../src/state.rs");
    let error = include_str!("../src/error.rs");
    let instructions = include_str!("../src/instructions.rs");

    // Items that DO have docs today — protect against regressions.
    let documented = [
        (pda, "pub const SEED_MULTISIG_STATE", "SEED_MULTISIG_STATE"),
        (pda, "pub const SEED_PROPOSAL", "SEED_PROPOSAL"),
        (pda, "pub const SEED_VAULT", "SEED_VAULT"),
        (pda, "pub const SEED_NULLIFIER", "SEED_NULLIFIER"),
        (pda, "pub fn derive_pda", "derive_pda"),
        (
            pda,
            "pub fn derive_multisig_state_pda",
            "derive_multisig_state_pda",
        ),
        (pda, "pub fn derive_proposal_pda", "derive_proposal_pda"),
        (pda, "pub fn derive_vault_pda", "derive_vault_pda"),
        (
            pda,
            "pub fn derive_nullifier_entry_pda",
            "derive_nullifier_entry_pda",
        ),
        (
            proof,
            "pub const APPROVE_PUBLIC_INPUTS_LEN",
            "APPROVE_PUBLIC_INPUTS_LEN",
        ),
        (
            proof,
            "pub struct ApprovePublicInputs",
            "ApprovePublicInputs",
        ),
        (proof, "pub struct ChainId", "ChainId"),
        (proof, "pub fn derive_proposal_id", "derive_proposal_id"),
        (
            state,
            "pub const MAX_ACTION_BYTES_LEN",
            "MAX_ACTION_BYTES_LEN",
        ),
        (state, "pub struct MultisigState", "MultisigState"),
        (state, "pub struct Proposal", "Proposal"),
        (state, "pub struct NullifierEntry", "NullifierEntry"),
        (state, "pub struct Vault", "Vault"),
        (error, "pub enum CoreError", "CoreError"),
    ];
    for (source, needle, label) in documented {
        assert!(
            has_doc_above(source, needle),
            "expected {label} ({needle}) to have a /// docstring",
        );
    }

    // FRICTION (Nit): the following crate-root re-exports do NOT have a
    // docstring at their definition site. The crate-level module docs cover
    // most of them in prose, but `cargo doc` will render them without any
    // per-item summary. Suggested fix: add a one-line `///` to each.
    //
    // We surface the gap as a *soft* check — log it via the test name and
    // a panic message if anything in the list ever gets a doc (so this list
    // stays accurate), but don't fail the test today; the SDK can ship
    // without these and the doc gaps are nits, not blockers.
    let undocumented = [
        // The type aliases moved to lib.rs in the no_std refactor so the guest
        // can see them without compiling the std-gated `pda` module.
        (lib, "pub type ProgramId", "ProgramId"),
        (lib, "pub type AccountId", "AccountId"),
        (lib, "pub type CreateKey", "CreateKey"),
        (instructions, "pub enum Instruction", "Instruction"),
    ];
    let mut still_missing = Vec::new();
    for (source, needle, label) in undocumented {
        if !has_doc_above(source, needle) {
            still_missing.push(label);
        }
    }
    // All four items previously flagged as undocumented have since been
    // given rustdoc; the doc-gap set is now empty. Any future regression
    // that removes a docstring shows up here.
    let empty: Vec<&str> = Vec::new();
    assert_eq!(
        still_missing, empty,
        "doc-gap set drifted; update sdk_consumer_doc_audit"
    );
}
