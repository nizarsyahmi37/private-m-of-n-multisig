//! Blue-team round-4 validator for `private_multisig_core`.
//!
//! Rounds 1–3 closed every structural finding (E1002 `ActionBytesTooLong`,
//! E1003 `InvalidThreshold` + `validate_threshold`, removal of unused
//! `PdaSeed`, plus 276 named regression tests). This round pressures the
//! crate from THREE angles those earlier passes did not cover:
//!
//!   1. **debug-vs-release parity** — every hash output and every Borsh
//!      encoding is pinned to a hex literal computed once and baked in. If
//!      a compiler optimization, an LLVM upgrade, or a future refactor
//!      causes ANY divergence between `cargo test` and
//!      `cargo test --release`, these literals trip on whichever profile
//!      drifted. The literals are profile-independent: SHA-256 over a
//!      byte-string and Borsh-serialize-of-POD have no implementation
//!      latitude, so any difference is a real bug.
//!   2. **parallel-thread stress** — 16 OS threads × 1000 iterations
//!      hammering each pure-functional API. Since `derive_*` and
//!      `validate_threshold` take only `&` references and touch no globals,
//!      they should be perfectly Send + Sync + race-free. This round
//!      asserts that defensively.
//!   3. **determinism under load** — sentinel loops that run the full
//!      derivation flow 100 and 10000 times and assert every iteration
//!      produces byte-identical output.
//!
//! Every `v4_*` test maps 1:1 to a defense from the round-4 brief.
//!
//! Constraints (enforced by the brief):
//! - Only file this round may touch.
//! - Allowed deps: `rand`, `hex`, `borsh`, `crypto`, `private_multisig_core`,
//!   `std::thread`. `proptest` is permitted by the brief but is NOT in the
//!   workspace; we use seeded `StdRng` sweeps for the randomized assertions
//!   so reproductions are byte-stable without adding a dependency (matches
//!   the convention established by `blue_team_core_v3.rs`).

#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::type_complexity)]

use std::mem::size_of;
use std::sync::Arc;
use std::thread;

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id,
    derive_proposal_pda, derive_vault_pda,
    error::CoreError,
    instructions::Instruction,
    proof::{ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN},
    state::{MultisigState, NullifierEntry, Proposal, Vault},
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Convenience: decode a hex literal into a `[u8; 32]`. Panics on bad input —
/// these are baked-in test fixtures, so a decode failure IS a test failure.
fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    assert_eq!(v.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

// ===========================================================================
// 1. v4_debug_release_parity_pda_derivation
// ===========================================================================
//
// Hard-pinned hex outputs for the four PDA derivation helpers under fixed
// inputs. The hex values were computed once by running
// `derive_*_pda` against the literal inputs below and pasted in. Any
// compiler-optimization-induced divergence between debug and release builds
// trips THIS test on the affected profile. The values are profile-independent
// — SHA-256 over a known byte string has no implementation latitude.
#[test]
fn v4_debug_release_parity_pda_derivation() {
    let program_id = [0x11u8; 32];
    let create_key = [0x22u8; 32];
    let nullifier_bytes = [0x44u8; 32];

    let state_pda = derive_multisig_state_pda(&program_id, &create_key);
    let proposal_pda = derive_proposal_pda(&program_id, &create_key, 0);
    let vault_pda = derive_vault_pda(&program_id, &create_key);
    let nullifier_pda =
        derive_nullifier_entry_pda(&program_id, &proposal_pda, &nullifier_bytes);

    // Pins below recomputed under the round-5 SPEL-compatible PDA
    // derivation (see private_multisig_core/src/pda.rs round-5 fix note).
    assert_eq!(
        state_pda,
        h32("93b8f698cd4ced03f1fa0c7bd3025552f37c6f89ae9d5b482467c264eebfabe7"),
        "derive_multisig_state_pda drifted; check SHA-256 wiring",
    );
    assert_eq!(
        proposal_pda,
        h32("3ba8afe167f3085e215327d9d1214c4c32bd44a58d3c237e4753b623b9522cb6"),
        "derive_proposal_pda(index=0) drifted",
    );
    assert_eq!(
        vault_pda,
        h32("9d00add1aa402eb1d89ace0c705bc5e71a131310e7e85973f8e0dad545d16356"),
        "derive_vault_pda drifted",
    );
    assert_eq!(
        nullifier_pda,
        h32("d5794bbccf85f2efb99290b7100a0fae5212a1a5ad546f430628e4fbb392c2ec"),
        "derive_nullifier_entry_pda drifted",
    );
}

// ===========================================================================
// 2. v4_debug_release_parity_proposal_id
// ===========================================================================
//
// Reuses the three KAT input tuples from `cross_crate_parity.rs::bridge_kat_pinned`
// and pins the proposal_id hex for each. Provides defense-in-depth: if
// anyone refactors `derive_proposal_id`, the parity file AND this file both
// trip — and this file specifically trips under whichever build profile
// diverged.
#[test]
fn v4_debug_release_parity_proposal_id() {
    // KAT 1 — minimal-input baseline.
    {
        let state_pda = derive_multisig_state_pda(&[0x11u8; 32], &[0x22u8; 32]);
        let pid = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            0,
            b"kat_action_1",
            &[0x33u8; 32],
        );
        assert_eq!(
            pid,
            h32("011f06dfcbbc20115b121180f32972ad28edc775c7969d4ec228a979442a179c"),
            "KAT1 proposal_id drifted",
        );
    }

    // KAT 2 — empty action_bytes, non-trivial chain_id and index.
    {
        let mut create_key = [0u8; 32];
        for i in 0..32 {
            create_key[i] = i as u8;
        }
        let state_pda = derive_multisig_state_pda(&[0xA0u8; 32], &create_key);
        let pid = derive_proposal_id(
            &ChainId::from_u64(0xABCD_EF01),
            &state_pda,
            42,
            b"",
            &[0xFFu8; 32],
        );
        assert_eq!(
            pid,
            h32("b01d89ef9e4e0d05198d11a7b31cb1cbc38868ee01d4d76456b435ef78276113"),
            "KAT2 proposal_id drifted",
        );
    }

    // KAT 3 — realistic-shape inputs.
    {
        let state_pda = derive_multisig_state_pda(&[0x99u8; 32], &[0xABu8; 32]);
        let pid = derive_proposal_id(
            &ChainId::from_u64(0xDEAD_BEEF),
            &state_pda,
            999,
            b"treasury_withdraw(100,recipient=0xABCD)",
            &[0xCDu8; 32],
        );
        assert_eq!(
            pid,
            h32("db41d7e974dc92f89a9506a0f0cf605f88ecd0cde734a329a7b055709ec2ad8f"),
            "KAT3 proposal_id drifted",
        );
    }
}

// ===========================================================================
// 3. v4_debug_release_parity_borsh_round_trip
// ===========================================================================
//
// Pins the Borsh-serialized hex for one of each: `MultisigState`, `Proposal`
// (4-byte action), `Vault`, `NullifierEntry`, `ApprovePublicInputs`, and
// `Instruction::Approve`. Borsh `to_vec` must produce the pinned hex byte-for-
// byte under both debug and release. Borsh has no implementation latitude
// over `[u8; 32]` and primitives, so any drift = real ABI break.
#[test]
fn v4_debug_release_parity_borsh_round_trip() {
    // MultisigState — fixed 77-byte wire size.
    {
        let ms = MultisigState {
            create_key: [0xAAu8; 32],
            members_root: [0xBBu8; 32],
            m: 3,
            n: 5,
            proposal_count: 42,
        };
        let bytes = to_vec(&ms).unwrap();
        let expected = hex::decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\
             03\
             05000000\
             2a00000000000000",
        )
        .unwrap();
        assert_eq!(bytes, expected, "MultisigState Borsh encoding drifted");
        let round: MultisigState = MultisigState::try_from_slice(&bytes).unwrap();
        assert_eq!(round, ms);
    }

    // Proposal with 4-byte action_bytes.
    {
        let prop = Proposal {
            action_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            target_program: [0xCCu8; 32],
            approvals_count: 2,
            executed: false,
        };
        let bytes = to_vec(&prop).unwrap();
        let expected = hex::decode(
            "04000000\
             deadbeef\
             cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\
             02000000\
             00",
        )
        .unwrap();
        assert_eq!(bytes, expected, "Proposal(4-byte action) Borsh encoding drifted");
        let round: Proposal = Proposal::try_from_slice(&bytes).unwrap();
        assert_eq!(round, prop);
    }

    // Vault — 32 bytes flat, no length prefix on the inner array.
    {
        let v = Vault { create_key: [0x77u8; 32] };
        let bytes = to_vec(&v).unwrap();
        let expected = vec![0x77u8; 32];
        assert_eq!(bytes, expected, "Vault Borsh encoding drifted");
        let round: Vault = Vault::try_from_slice(&bytes).unwrap();
        assert_eq!(round, v);
    }

    // NullifierEntry — zero-byte payload.
    {
        let n = NullifierEntry;
        let bytes = to_vec(&n).unwrap();
        assert!(bytes.is_empty(), "NullifierEntry must serialize to 0 bytes");
        let round: NullifierEntry = NullifierEntry::try_from_slice(&bytes).unwrap();
        assert_eq!(round, n);
    }

    // ApprovePublicInputs — fixed 96 bytes, three concatenated arrays.
    {
        let api = ApprovePublicInputs {
            members_root: [0x11u8; 32],
            proposal_id: [0x22u8; 32],
            nullifier: [0x33u8; 32],
        };
        let bytes = to_vec(&api).unwrap();
        let expected = hex::decode(
            "1111111111111111111111111111111111111111111111111111111111111111\
             2222222222222222222222222222222222222222222222222222222222222222\
             3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        assert_eq!(bytes, expected, "ApprovePublicInputs Borsh encoding drifted");
        assert_eq!(bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
        let round = ApprovePublicInputs::try_from_slice(&bytes).unwrap();
        assert_eq!(round, api);
    }

    // Instruction::Approve — discriminant 0x02, plus packed fields.
    // Round 5 dropped the `receipt: Vec<u8>` field, so the wire is now
    // discriminant(1) || create_key(32) || index(8 LE) || public_inputs(96).
    {
        let api = ApprovePublicInputs {
            members_root: [0x11u8; 32],
            proposal_id: [0x22u8; 32],
            nullifier: [0x33u8; 32],
        };
        let ix = Instruction::Approve {
            create_key: [0xAAu8; 32],
            index: 7,
            public_inputs: api,
        };
        let bytes = to_vec(&ix).unwrap();
        let expected = hex::decode(
            "02\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             0700000000000000\
             1111111111111111111111111111111111111111111111111111111111111111\
             2222222222222222222222222222222222222222222222222222222222222222\
             3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        assert_eq!(bytes, expected, "Instruction::Approve Borsh encoding drifted");
        let round = Instruction::try_from_slice(&bytes).unwrap();
        assert_eq!(round, ix);
    }
}

// ===========================================================================
// 4. v4_100_run_determinism
// ===========================================================================
//
// For 5 random configurations, run the full PDA + proposal_id + Borsh round-
// trip flow 100 times. Every run produces byte-identical output. The seeded
// RNG guarantees the *inputs* are stable across runs of this test; the inner
// 100-iteration loop guarantees the *outputs* are stable across repeated
// invocations of the underlying functions. Sentinel against any future non-
// determinism (e.g. iterator order bug, HashMap leak into pure path, etc.).
#[test]
fn v4_100_run_determinism() {
    let mut rng = StdRng::seed_from_u64(0xD3B0_07D3_u64);

    for case in 0..5 {
        let program_id: [u8; 32] = rng.gen();
        let create_key: [u8; 32] = rng.gen();
        let chain_id_inner: [u8; 32] = rng.gen();
        let index: u64 = rng.next_u64();
        let target_program: [u8; 32] = rng.gen();
        let action_len = (rng.next_u32() % 256) as usize;
        let mut action_bytes = vec![0u8; action_len];
        rng.fill_bytes(&mut action_bytes);

        // Snapshot the first run.
        let chain_id = ChainId::new(chain_id_inner);
        let state_pda = derive_multisig_state_pda(&program_id, &create_key);
        let proposal_pda = derive_proposal_pda(&program_id, &create_key, index);
        let vault_pda = derive_vault_pda(&program_id, &create_key);
        let pid = derive_proposal_id(
            &chain_id, &state_pda, index, &action_bytes, &target_program,
        );
        let null_pda = derive_nullifier_entry_pda(&program_id, &proposal_pda, &pid);
        let api = ApprovePublicInputs {
            members_root: [0xAAu8; 32],
            proposal_id: pid,
            nullifier: null_pda,
        };
        let api_bytes = to_vec(&api).unwrap();
        let ms = MultisigState {
            create_key,
            members_root: [0xBBu8; 32],
            m: 1,
            n: 1,
            proposal_count: index,
        };
        let ms_bytes = to_vec(&ms).unwrap();

        // Re-run 100× and assert byte-identical outputs every time.
        for iter in 0..100 {
            let chain_id_r = ChainId::new(chain_id_inner);
            let state_pda_r = derive_multisig_state_pda(&program_id, &create_key);
            let proposal_pda_r = derive_proposal_pda(&program_id, &create_key, index);
            let vault_pda_r = derive_vault_pda(&program_id, &create_key);
            let pid_r = derive_proposal_id(
                &chain_id_r,
                &state_pda_r,
                index,
                &action_bytes,
                &target_program,
            );
            let null_pda_r =
                derive_nullifier_entry_pda(&program_id, &proposal_pda_r, &pid_r);
            let api_r = ApprovePublicInputs {
                members_root: [0xAAu8; 32],
                proposal_id: pid_r,
                nullifier: null_pda_r,
            };
            let api_bytes_r = to_vec(&api_r).unwrap();
            let ms_r = MultisigState {
                create_key,
                members_root: [0xBBu8; 32],
                m: 1,
                n: 1,
                proposal_count: index,
            };
            let ms_bytes_r = to_vec(&ms_r).unwrap();

            assert_eq!(state_pda_r, state_pda, "case {case} iter {iter}: state_pda drift");
            assert_eq!(proposal_pda_r, proposal_pda, "case {case} iter {iter}: proposal_pda drift");
            assert_eq!(vault_pda_r, vault_pda, "case {case} iter {iter}: vault_pda drift");
            assert_eq!(pid_r, pid, "case {case} iter {iter}: proposal_id drift");
            assert_eq!(null_pda_r, null_pda, "case {case} iter {iter}: nullifier_pda drift");
            assert_eq!(api_bytes_r, api_bytes, "case {case} iter {iter}: APIs borsh drift");
            assert_eq!(ms_bytes_r, ms_bytes, "case {case} iter {iter}: MS borsh drift");
        }
    }
}

// ===========================================================================
// 5. v4_parallel_pda_derivation_no_race
// ===========================================================================
//
// 16 OS threads × 1000 iterations of `derive_multisig_state_pda` on the same
// input. All 16000 results must agree byte-for-byte. The function is pure-
// functional (`&` references, no globals, allocates a local Vec); this
// passes trivially today, but the test pins the invariant so any future
// `static mut` or `lazy_static` slipping into the derive path is caught.
#[test]
fn v4_parallel_pda_derivation_no_race() {
    let program_id = Arc::new([0x33u8; 32]);
    let create_key = Arc::new([0x44u8; 32]);
    let expected = derive_multisig_state_pda(&program_id, &create_key);

    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let pid = Arc::clone(&program_id);
        let ck = Arc::clone(&create_key);
        handles.push(thread::spawn(move || {
            let mut results = Vec::with_capacity(1000);
            for _ in 0..1000 {
                results.push(derive_multisig_state_pda(&pid, &ck));
            }
            results
        }));
    }
    for h in handles {
        let results = h.join().expect("worker thread panicked");
        for r in results {
            assert_eq!(r, expected, "thread produced a divergent state PDA");
        }
    }
}

// ===========================================================================
// 6. v4_parallel_proposal_id_no_race
// ===========================================================================
//
// Same shape: 16 threads × 1000 iters of `derive_proposal_id` on the same
// input. All agree byte-for-byte.
#[test]
fn v4_parallel_proposal_id_no_race() {
    let chain_id = Arc::new(ChainId::from_u64(0xABCD_EF01));
    let state_pda = Arc::new([0x55u8; 32]);
    let action_bytes = Arc::new(b"parallel-no-race-action".to_vec());
    let target_program = Arc::new([0x66u8; 32]);
    let index: u64 = 1234;

    let expected = derive_proposal_id(
        &chain_id,
        &state_pda,
        index,
        &action_bytes,
        &target_program,
    );

    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let cid = Arc::clone(&chain_id);
        let pda = Arc::clone(&state_pda);
        let ab = Arc::clone(&action_bytes);
        let tp = Arc::clone(&target_program);
        handles.push(thread::spawn(move || {
            let mut results = Vec::with_capacity(1000);
            for _ in 0..1000 {
                results.push(derive_proposal_id(&cid, &pda, index, &ab, &tp));
            }
            results
        }));
    }
    for h in handles {
        let results = h.join().expect("worker thread panicked");
        for r in results {
            assert_eq!(r, expected, "thread produced a divergent proposal_id");
        }
    }
}

// ===========================================================================
// 7. v4_parallel_borsh_no_race
// ===========================================================================
//
// 16 threads, each Borsh-round-tripping a fresh `MultisigState` on its own.
// All produce the same bytes for the same struct value, and all decode back
// to that value. Confirms Borsh's `to_vec` / `try_from_slice` are pure and
// have no hidden shared state.
#[test]
fn v4_parallel_borsh_no_race() {
    let template = MultisigState {
        create_key: [0xCCu8; 32],
        members_root: [0xDDu8; 32],
        m: 7,
        n: 11,
        proposal_count: 314,
    };
    let expected_bytes = to_vec(&template).unwrap();

    let mut handles = Vec::with_capacity(16);
    let shared = Arc::new(template);
    for _ in 0..16 {
        let tpl = Arc::clone(&shared);
        let expected = expected_bytes.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..1000 {
                let bytes = to_vec(&*tpl).unwrap();
                assert_eq!(bytes, expected, "thread Borsh encoding drift");
                let round = MultisigState::try_from_slice(&bytes).unwrap();
                assert_eq!(round, *tpl, "thread Borsh round-trip drift");
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }
}

// ===========================================================================
// 8. v4_parallel_validate_threshold_no_panic
// ===========================================================================
//
// 16 threads, each calling `validate_threshold` on a random `(m, n)` pair for
// 1000 iterations. No panics, and the result is always consistent with the
// known specification — `Ok(())` iff `m > 0 && n > 0 && u32::from(m) <= n`.
#[test]
fn v4_parallel_validate_threshold_no_panic() {
    let mut handles = Vec::with_capacity(16);
    for tid in 0..16u64 {
        handles.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(0x0BAD_F00D ^ tid);
            for _ in 0..1000 {
                let m: u8 = rng.gen();
                let n: u32 = rng.gen();
                let result = MultisigState::validate_threshold(m, n);
                let expected_ok = m != 0 && n != 0 && u32::from(m) <= n;
                match result {
                    Ok(()) => {
                        assert!(
                            expected_ok,
                            "validate_threshold({m}, {n}) returned Ok but spec says Err"
                        );
                    }
                    Err(e) => {
                        assert!(
                            !expected_ok,
                            "validate_threshold({m}, {n}) returned Err({e:?}) but spec says Ok"
                        );
                        assert_eq!(e, CoreError::InvalidThreshold);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }
}

// ===========================================================================
// 9. v4_no_global_state
// ===========================================================================
//
// Sanity test: create two `MultisigState` values in sequence; mutate the
// first; assert the second's fields are unchanged. Catches any accidental
// sharing via `static`, `lazy_static`, `thread_local!`, or interior
// mutability. The struct is plain `Clone`, but the test pins the invariant
// so a future "optimization" replacing fields with shared `Arc`s is caught.
#[test]
fn v4_no_global_state() {
    let mut a = MultisigState {
        create_key: [0xAAu8; 32],
        members_root: [0xBBu8; 32],
        m: 1,
        n: 1,
        proposal_count: 0,
    };
    let b = MultisigState {
        create_key: [0xAAu8; 32],
        members_root: [0xBBu8; 32],
        m: 1,
        n: 1,
        proposal_count: 0,
    };
    let b_snapshot = b.clone();

    // Mutate every mutable field of a, then READ each one back so dead-
    // store lints don't fire and so the mutation is genuinely observable.
    a.create_key = [0x00u8; 32];
    a.members_root = [0x01u8; 32];
    a.m = 99;
    a.n = 9999;
    a.proposal_count = u64::MAX;
    assert_eq!(a.create_key, [0x00u8; 32]);
    assert_eq!(a.members_root, [0x01u8; 32]);
    assert_eq!(a.m, 99);
    assert_eq!(a.n, 9999);
    assert_eq!(a.proposal_count, u64::MAX);

    // b must be untouched.
    assert_eq!(b, b_snapshot, "mutating one MultisigState leaked into another");
    assert_eq!(b.create_key, [0xAAu8; 32]);
    assert_eq!(b.members_root, [0xBBu8; 32]);
    assert_eq!(b.m, 1);
    assert_eq!(b.n, 1);
    assert_eq!(b.proposal_count, 0);

    // Cross-check for Proposal too — has a Vec inside, which is the most
    // likely candidate for accidental sharing via clone-on-write or Arc.
    let mut p1 = Proposal {
        action_bytes: vec![0x11, 0x22, 0x33],
        target_program: [0x44u8; 32],
        approvals_count: 0,
        executed: false,
    };
    let p2 = p1.clone();
    p1.action_bytes.push(0xFF);
    p1.target_program = [0x55u8; 32];
    p1.approvals_count = 7;
    p1.executed = true;
    assert_eq!(p2.action_bytes, vec![0x11, 0x22, 0x33]);
    assert_eq!(p2.target_program, [0x44u8; 32]);
    assert_eq!(p2.approvals_count, 0);
    assert!(!p2.executed);
}

// ===========================================================================
// 10. v4_proposal_id_stable_across_borsh_round_trip
// ===========================================================================
//
// Derive `proposal_id` from inputs, embed in `ApprovePublicInputs`, round-
// trip via Borsh, assert decoded `proposal_id` is byte-identical. Sentinel
// against any future encoding bug that munges 32-byte arrays inside a
// derived Borsh struct.
#[test]
fn v4_proposal_id_stable_across_borsh_round_trip() {
    let state_pda = derive_multisig_state_pda(&[0x77u8; 32], &[0x88u8; 32]);
    let pid = derive_proposal_id(
        &ChainId::from_u64(13),
        &state_pda,
        7,
        b"stable_round_trip_action",
        &[0x99u8; 32],
    );

    let api = ApprovePublicInputs {
        members_root: [0x12u8; 32],
        proposal_id: pid,
        nullifier: [0x34u8; 32],
    };

    // Borsh path.
    let bytes = to_vec(&api).unwrap();
    assert_eq!(bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);
    let decoded = ApprovePublicInputs::try_from_slice(&bytes).unwrap();
    assert_eq!(decoded.proposal_id, pid, "Borsh round trip mangled proposal_id");

    // Explicit pack path (cross-check the second wire surface).
    let packed = api.to_bytes();
    assert_eq!(&packed[32..64], &pid, "explicit pack misplaced proposal_id");
    let unpacked = ApprovePublicInputs::from_bytes(&packed);
    assert_eq!(unpacked.proposal_id, pid);

    // Borsh and explicit must produce the same bytes — already pinned in
    // proof.rs::borsh_encoding_matches_explicit_layout, but re-pinned here
    // as a defense-in-depth sentinel.
    assert_eq!(bytes.as_slice(), packed.as_slice());
}

// ===========================================================================
// 11. v4_error_code_stable_across_threads
// ===========================================================================
//
// Call `CoreError::from_code(1003)` from 16 threads × 100 iters; all return
// `Some(InvalidThreshold)`. Confirms `const fn` truly is — and would catch
// any future refactor that quietly turned `from_code` into a stateful
// lookup table.
#[test]
fn v4_error_code_stable_across_threads() {
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        handles.push(thread::spawn(|| {
            for _ in 0..100 {
                let r = CoreError::from_code(1003);
                assert_eq!(r, Some(CoreError::InvalidThreshold));
                // Spot-check every known code from every thread.
                assert_eq!(CoreError::from_code(1000), Some(CoreError::InstanceNotActive));
                assert_eq!(
                    CoreError::from_code(1001),
                    Some(CoreError::ProposalExpiredOrExecuted)
                );
                assert_eq!(CoreError::from_code(1002), Some(CoreError::ActionBytesTooLong));
                assert_eq!(CoreError::from_code(2000), Some(CoreError::InvalidReceipt));
                assert_eq!(CoreError::from_code(2001), Some(CoreError::ImageIdMismatch));
                assert_eq!(CoreError::from_code(2002), Some(CoreError::RootMismatch));
                assert_eq!(CoreError::from_code(2003), Some(CoreError::ProposalIdMismatch));
                assert_eq!(
                    CoreError::from_code(3000),
                    Some(CoreError::NullifierAlreadyUsed)
                );
                assert_eq!(CoreError::from_code(4000), Some(CoreError::ThresholdNotMet));
                assert_eq!(CoreError::from_code(4001), Some(CoreError::AlreadyExecuted));
                assert_eq!(CoreError::from_code(0), None);
                assert_eq!(CoreError::from_code(u32::MAX), None);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }
}

// ===========================================================================
// 12. v4_all_kat_vectors_reproduced
// ===========================================================================
//
// Defense-in-depth: re-pin and re-assert the 3 cross-crate KATs from
// `cross_crate_parity.rs::bridge_kat_pinned`. If anyone refactors
// `derive_proposal_id` or its inputs, multiple tests trip simultaneously —
// the bigger the explosion, the harder a silent regression is.
#[test]
fn v4_all_kat_vectors_reproduced() {
    // Pins recomputed under round-5 SPEL-compatible PDA derivation.

    // KAT 1
    {
        let state_pda = derive_multisig_state_pda(&[0x11u8; 32], &[0x22u8; 32]);
        assert_eq!(
            state_pda,
            h32("93b8f698cd4ced03f1fa0c7bd3025552f37c6f89ae9d5b482467c264eebfabe7"),
        );
        let pid = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            0,
            b"kat_action_1",
            &[0x33u8; 32],
        );
        assert_eq!(
            pid,
            h32("011f06dfcbbc20115b121180f32972ad28edc775c7969d4ec228a979442a179c"),
        );
    }

    // KAT 2
    {
        let mut create_key = [0u8; 32];
        for i in 0..32 {
            create_key[i] = i as u8;
        }
        let state_pda = derive_multisig_state_pda(&[0xA0u8; 32], &create_key);
        assert_eq!(
            state_pda,
            h32("18d93f1fb3524fbe933f86cf2a52d09c80885d18771eefd0efc4b88f2300fd49"),
        );
        let pid = derive_proposal_id(
            &ChainId::from_u64(0xABCD_EF01),
            &state_pda,
            42,
            b"",
            &[0xFFu8; 32],
        );
        assert_eq!(
            pid,
            h32("b01d89ef9e4e0d05198d11a7b31cb1cbc38868ee01d4d76456b435ef78276113"),
        );
    }

    // KAT 3
    {
        let state_pda = derive_multisig_state_pda(&[0x99u8; 32], &[0xABu8; 32]);
        assert_eq!(
            state_pda,
            h32("6de3a5cc83e530827b5b8f150028bf92bd4260aa94b101798ad794d72c3f0bb6"),
        );
        let pid = derive_proposal_id(
            &ChainId::from_u64(0xDEAD_BEEF),
            &state_pda,
            999,
            b"treasury_withdraw(100,recipient=0xABCD)",
            &[0xCDu8; 32],
        );
        assert_eq!(
            pid,
            h32("db41d7e974dc92f89a9506a0f0cf605f88ecd0cde734a329a7b055709ec2ad8f"),
        );
    }
}

// ===========================================================================
// 13. v4_release_size_sentinels_pinned
// ===========================================================================
//
// `mem::size_of` for every public type — pinning today's layout so future
// padding changes or repr drift are noticed BEFORE they bite the Risc0
// guest, where stack budget is tight. Values are platform-conventional on
// 64-bit; if any port to 32-bit happens these will need adjustment, which
// is the entire point of pinning them.
#[test]
fn v4_release_size_sentinels_pinned() {
    // SHA-256 output width.
    assert_eq!(size_of::<[u8; 32]>(), 32);

    // ApprovePublicInputs = three [u8; 32] fields back-to-back = 96 bytes
    // with no padding. Same as APPROVE_PUBLIC_INPUTS_LEN.
    assert_eq!(size_of::<ApprovePublicInputs>(), 96);
    assert_eq!(size_of::<ApprovePublicInputs>(), APPROVE_PUBLIC_INPUTS_LEN);

    // Vault is one [u8; 32] field, no padding.
    assert_eq!(size_of::<Vault>(), 32);

    // NullifierEntry is a unit struct.
    assert_eq!(size_of::<NullifierEntry>(), 0);

    // ChainId wraps one [u8; 32].
    assert_eq!(size_of::<ChainId>(), 32);

    // MultisigState: 32 (create_key) + 32 (members_root) + 1 (m) + 4 (n)
    // + 8 (proposal_count) = 77 logical bytes; on 64-bit with default repr
    // the struct rounds up to 80 bytes for alignment. Pin both observed
    // values so any field reorder or align change is caught.
    assert_eq!(size_of::<MultisigState>(), 80);

    // Proposal: Vec<u8> (24 bytes on 64-bit) + [u8; 32] + u32 + bool
    // -> 24 + 32 + 4 + 1 padded to 8 = 64 bytes. Pin the observed value.
    assert_eq!(size_of::<Proposal>(), 64);

    // Instruction: enum size = max(variant) + discriminant, padded. Round
    // 5 dropped Approve.receipt so Propose is now the largest variant
    // (carries action_bytes: Vec<u8>). Today's size is 144 bytes. Pin it;
    // future variant additions or field-shape changes show up in a diff.
    assert_eq!(size_of::<Instruction>(), 144);
}

// ===========================================================================
// 14. v4_chain_id_borsh_equals_explicit
// ===========================================================================
//
// `ChainId` derives Borsh. Confirm `to_vec(&ChainId::new([0xAB; 32]))`
// produces exactly 32 bytes of `0xAB` — no length prefix on the inner array.
// If Borsh ever changes its tuple-struct-of-array encoding, this trips.
#[test]
fn v4_chain_id_borsh_equals_explicit() {
    let cid = ChainId::new([0xABu8; 32]);
    let bytes = to_vec(&cid).unwrap();
    assert_eq!(bytes.len(), 32, "ChainId Borsh size drifted");
    assert_eq!(bytes, vec![0xABu8; 32]);

    // Round trip.
    let round = ChainId::try_from_slice(&bytes).unwrap();
    assert_eq!(round, cid);

    // Also pin the as_bytes view.
    assert_eq!(cid.as_bytes(), &[0xABu8; 32]);

    // And `from_u64` path.
    let cid_u = ChainId::from_u64(0x0102_0304_0506_0708);
    let bytes_u = to_vec(&cid_u).unwrap();
    assert_eq!(bytes_u.len(), 32);
    // Little-endian: LSB first.
    assert_eq!(bytes_u[0], 0x08);
    assert_eq!(bytes_u[7], 0x01);
    for b in &bytes_u[8..] {
        assert_eq!(*b, 0u8);
    }
}

// ===========================================================================
// 15. v4_kat_roundtrip_at_load
// ===========================================================================
//
// Burn-in for determinism: for the 3 cross-crate KATs, run each in a loop
// of 10000 iterations and confirm every iteration produces byte-identical
// output. If the SHA-256 backend, the Vec allocator, or any path on the
// hot loop ever introduces non-determinism, this catches it.
#[test]
fn v4_kat_roundtrip_at_load() {
    // KAT 1
    {
        let state_pda = derive_multisig_state_pda(&[0x11u8; 32], &[0x22u8; 32]);
        let pid_first = derive_proposal_id(
            &ChainId::from_u64(1),
            &state_pda,
            0,
            b"kat_action_1",
            &[0x33u8; 32],
        );
        let expected =
            h32("011f06dfcbbc20115b121180f32972ad28edc775c7969d4ec228a979442a179c");
        assert_eq!(pid_first, expected);
        for _ in 0..10_000 {
            let s = derive_multisig_state_pda(&[0x11u8; 32], &[0x22u8; 32]);
            assert_eq!(s, state_pda);
            let p = derive_proposal_id(
                &ChainId::from_u64(1),
                &s,
                0,
                b"kat_action_1",
                &[0x33u8; 32],
            );
            assert_eq!(p, expected);
        }
    }

    // KAT 2
    {
        let mut create_key = [0u8; 32];
        for i in 0..32 {
            create_key[i] = i as u8;
        }
        let state_pda = derive_multisig_state_pda(&[0xA0u8; 32], &create_key);
        let expected =
            h32("b01d89ef9e4e0d05198d11a7b31cb1cbc38868ee01d4d76456b435ef78276113");
        for _ in 0..10_000 {
            let s = derive_multisig_state_pda(&[0xA0u8; 32], &create_key);
            assert_eq!(s, state_pda);
            let p = derive_proposal_id(
                &ChainId::from_u64(0xABCD_EF01),
                &s,
                42,
                b"",
                &[0xFFu8; 32],
            );
            assert_eq!(p, expected);
        }
    }

    // KAT 3
    {
        let state_pda = derive_multisig_state_pda(&[0x99u8; 32], &[0xABu8; 32]);
        let expected =
            h32("db41d7e974dc92f89a9506a0f0cf605f88ecd0cde734a329a7b055709ec2ad8f");
        for _ in 0..10_000 {
            let s = derive_multisig_state_pda(&[0x99u8; 32], &[0xABu8; 32]);
            assert_eq!(s, state_pda);
            let p = derive_proposal_id(
                &ChainId::from_u64(0xDEAD_BEEF),
                &s,
                999,
                b"treasury_withdraw(100,recipient=0xABCD)",
                &[0xCDu8; 32],
            );
            assert_eq!(p, expected);
        }
    }
}
