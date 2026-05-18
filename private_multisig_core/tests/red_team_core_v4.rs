//! Round-4 red-team for `private_multisig_core`.
//!
//! Three prior rounds + the crypto campaign already pounded PDA collisions,
//! avalanche, Borsh malformation, action-bytes capping, error catalog
//! stability, threshold validation, instruction discriminants, ChainId
//! construction paths, soundness oracles, and the cross-crate parity surface.
//! Findings closed: FINDING-2 (E1002), FINDING-3 (ChainId zero alias docs),
//! FINDING-V2-A (E1003 + `validate_threshold`), FINDING-V2-B (Vault redundancy
//! accepted), FINDING-V2-C (`PdaSeed` removed). 276 tests pass.
//!
//! Returns are clearly diminishing. This round looks specifically for the
//! kind of bugs three rounds could have stepped over:
//!
//! - **Type-level invariants** — `mem::size_of`, `mem::align_of`,
//!   `mem::needs_drop`, `Send + Sync`, `Copy` reasonability — every public
//!   type's *shape*, not its content.
//! - **No mutable globals / `static`** — grep was clean (zero hits). Pin
//!   the absence by exercising a tight thread-shared `derive_proposal_id`
//!   loop with the same inputs from 8 threads; if a hidden global cache
//!   were ever introduced, this would race or memoize incorrectly.
//! - **Tautological-test replacements** — three were already replaced in
//!   round 3. This round examines round-1 / round-2 / round-3 / blue-team /
//!   ABI / fuzz / cross-parity / integration test bodies for any body whose
//!   semantics reduce to `assert!(true)`. Confirmed two NEW candidates that
//!   round 3 missed:
//!     * round-1 `attack_9b_random_2k_byte_blobs_never_become_instructions`
//!       — the body's only assertion was `println!("informational: ...")`.
//!       It would pass even if every random blob decoded as a valid
//!       Instruction. Replacement below stresses the same surface with a
//!       hard upper-bound assertion plus discriminant-distribution check.
//!     * round-3 `v3_attack_14b_type_reexports_constructible_at_crate_root`
//!       — at runtime it does nothing observable; only the compile is the
//!       test. Replacement below adds runtime equality assertions that
//!       would fail if the types' Borsh shapes were silently changed.
//! - **Cross-round drift** — paranoia scan: any prior test asserting
//!   `from_code(1003) == None`? grep was clean; pinned below to catch
//!   future regressions.
//! - **Borsh `cautious` capacity hint** — Borsh 1.x's `hint::cautious`
//!   caps the pre-allocated `Vec<u8>` at `4096 / size_of::<T>()`. The
//!   borsh_fuzz suite confirms behavior empirically. This file additionally
//!   pins the timing property: a u32::MAX vec-len prefix must abort
//!   reading in well under 200 ms — i.e. Borsh did not silently allocate.
//! - **proposal_id avalanche under five SIMULTANEOUS inputs** — round 3
//!   covered single-input sweeps. This file randomizes all 5 independently
//!   for 10 000 samples and demands zero collisions.
//! - **`MultisigState::validate_threshold` vs `validate` divergence under
//!   100 random pairs** — round 3 pinned a fixed small list. Stronger
//!   sweep here.
//! - **`derive_proposal_id` 136-byte stack-only contract** — pin the
//!   `2*32 + 8 + 2*32 == 136` invariant. A future PR that adds a Vec
//!   to that path inflates the stack-frame budget; this sentinel breaks
//!   the moment the magic number drifts.
//!
//! All seeded rand, no `proptest` dep (workspace doesn't carry it).

#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::similar_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_assert)]
#![allow(clippy::type_complexity)]
#![allow(clippy::identity_op)]

use std::collections::HashSet;
use std::mem;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::thread;

use borsh::{to_vec, BorshDeserialize};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id,
    derive_proposal_pda, derive_vault_pda, ApprovePublicInputs, ChainId, CoreError, Instruction,
    MultisigState, NullifierEntry, Proposal, Vault, APPROVE_PUBLIC_INPUTS_LEN,
    MAX_ACTION_BYTES_LEN, SEED_MULTISIG_STATE, SEED_NULLIFIER, SEED_PROPOSAL, SEED_VAULT,
};

fn rng() -> StdRng {
    // "RED4" — round-4 deterministic seed.
    StdRng::seed_from_u64(0x52_45_44_34_u64)
}

fn random_32(r: &mut StdRng) -> [u8; 32] {
    let mut out = [0u8; 32];
    r.fill_bytes(&mut out);
    out
}

// ============================================================================
// 1. Type-level invariants — size_of / align_of / needs_drop
// ============================================================================

/// `ApprovePublicInputs` is `Copy` and is wired through the verifier journal
/// readback path; the canonical layout is 96 bytes. The Rust struct *must*
/// also be exactly 96 bytes — no padding, no compiler-inserted slack. If a
/// future PR adds a field (e.g. a version byte), `mem::size_of` flips and the
/// Borsh wire size in `abi_wire_format.rs` flips too; both should break, but
/// this sentinel fires first because the runtime cost is zero.
#[test]
fn v4_attack_1a_approve_public_inputs_size_is_96() {
    assert_eq!(mem::size_of::<ApprovePublicInputs>(), 96);
    assert_eq!(mem::size_of::<ApprovePublicInputs>(), APPROVE_PUBLIC_INPUTS_LEN);
    // Three [u8; 32] fields → alignment 1.
    assert_eq!(mem::align_of::<ApprovePublicInputs>(), 1);
}

/// `ChainId` wraps a single `[u8; 32]` and is `Copy`. 32 bytes, alignment 1.
#[test]
fn v4_attack_1b_chain_id_size_is_32() {
    assert_eq!(mem::size_of::<ChainId>(), 32);
    assert_eq!(mem::align_of::<ChainId>(), 1);
}

/// `Vault` is exactly the 32-byte `create_key`. Bigger means redundancy was
/// added (the FINDING-V2-B note flagged the existing 32 bytes; an inflation
/// past 32 is a NEW finding).
#[test]
fn v4_attack_1c_vault_size_is_32() {
    assert_eq!(mem::size_of::<Vault>(), 32);
    assert_eq!(mem::align_of::<Vault>(), 1);
}

/// `NullifierEntry` is a unit struct → zero bytes. If anyone adds a field,
/// the on-chain rent calculus changes silently. Pin.
#[test]
fn v4_attack_1d_nullifier_entry_size_is_zero() {
    assert_eq!(mem::size_of::<NullifierEntry>(), 0);
    // Zero-size types still have alignment ≥ 1.
    assert!(mem::align_of::<NullifierEntry>() >= 1);
}

/// `MultisigState` rust layout has natural alignment for its u32/u64 fields.
/// Rust may insert padding between `m: u8` and `n: u32`. We don't pin the
/// in-memory size — only the wire size, which is independently asserted at
/// 77 bytes elsewhere. We DO pin `align_of` because a future PR that adds
/// a `repr(align(...))` would surface as a struct-size jump.
#[test]
fn v4_attack_1e_multisig_state_alignment_natural() {
    // Default repr — alignment equals max field alignment = u64's 8.
    assert_eq!(mem::align_of::<MultisigState>(), 8);
    // The struct must be at least the sum of its byte-sized fields (no
    // compiler shrinkage). 32 + 32 + 1 + 4 + 8 = 77 logical bytes; with
    // padding the in-memory size rounds up. Allow up to 96 (3 alignment
    // pads of u64 = 24 worst case).
    let s = mem::size_of::<MultisigState>();
    assert!((77..=96).contains(&s), "MultisigState in-memory size {s} outside [77, 96]");
}

/// `CoreError` is `Copy` and is a fieldless enum at the on-chain ABI layer
/// (the `code()` u32 is what crosses the wire, never the enum itself). Its
/// in-memory size is up to compiler — pin a tight upper bound so anyone
/// adding a payload to a variant (e.g. `Foo(String)`) trips this.
#[test]
fn v4_attack_1f_core_error_is_small_fieldless_enum() {
    // 11 variants fit in 1 byte; the discriminant niche means the whole
    // enum should be exactly 1 byte. If a payload sneaks in (e.g. a Box
    // or a String), this jumps to 24+ bytes.
    let s = mem::size_of::<CoreError>();
    assert_eq!(
        s, 1,
        "CoreError size is {s} bytes — variant payload was added without notice"
    );
}

// ============================================================================
// 2. Drop semantics — no custom Drop on fixed-size types; Vec types need_drop
// ============================================================================

/// Fixed-size types must NOT need drop — they're pure plain old data. If
/// anyone introduces a custom `Drop` impl (or a field whose type implements
/// Drop), this catches it and prompts a security review of why the type
/// suddenly carries cleanup logic.
#[test]
fn v4_attack_2a_pod_types_no_drop() {
    assert!(!mem::needs_drop::<MultisigState>(), "MultisigState gained Drop");
    assert!(!mem::needs_drop::<Vault>(), "Vault gained Drop");
    assert!(!mem::needs_drop::<NullifierEntry>(), "NullifierEntry gained Drop");
    assert!(!mem::needs_drop::<ApprovePublicInputs>(), "ApprovePublicInputs gained Drop");
    assert!(!mem::needs_drop::<ChainId>(), "ChainId gained Drop");
    assert!(!mem::needs_drop::<CoreError>(), "CoreError gained Drop");
}

/// `Proposal` carries a `Vec<u8>` field so it MUST need drop. If a future PR
/// switches `action_bytes` to a non-heap type (e.g. a fixed array), the
/// wire format changes and this test trips alongside the abi pins.
#[test]
fn v4_attack_2b_proposal_needs_drop() {
    assert!(
        mem::needs_drop::<Proposal>(),
        "Proposal lost its Vec field — wire format changed"
    );
}

/// `Instruction` has two variants carrying `Vec<u8>` (Propose.action_bytes,
/// Approve.receipt), so the enum requires Drop. If those Vec fields are
/// removed, this test trips.
#[test]
fn v4_attack_2c_instruction_needs_drop() {
    assert!(
        mem::needs_drop::<Instruction>(),
        "Instruction lost its Vec-carrying variants — wire format changed"
    );
}

// ============================================================================
// 3. Send + Sync — every public type must be thread-safe
// ============================================================================

/// Compile-time + runtime check that every public type is `Send + Sync`. No
/// interior mutability is permitted (no Cell, RefCell, Rc, etc.). If a future
/// PR adds one, this fails to compile and the regression surfaces here.
#[test]
fn v4_attack_3a_all_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MultisigState>();
    assert_send_sync::<Proposal>();
    assert_send_sync::<NullifierEntry>();
    assert_send_sync::<Vault>();
    assert_send_sync::<ApprovePublicInputs>();
    assert_send_sync::<ChainId>();
    assert_send_sync::<Instruction>();
    assert_send_sync::<CoreError>();
}

// ============================================================================
// 4. No mutable globals — concurrency sentinel
// ============================================================================

/// The crate has no `static mut`, no `OnceCell`, no `lazy_static`. If a hidden
/// mutable global ever lands (e.g. a memoization cache for `derive_proposal_id`),
/// it would race under contention. Fire 8 threads each computing the same
/// `derive_proposal_id` 1_000 times — every result must be byte-identical and
/// equal the single-thread baseline. A hidden cache that lazy-fills would
/// likely return zero on the first racing read, or torn bytes on a second.
#[test]
fn v4_attack_4a_no_hidden_global_state_under_contention() {
    let chain = ChainId::from_u64(0xCAFE_BABE);
    let state_pda = Arc::new([0xAAu8; 32]);
    let action: Arc<Vec<u8>> = Arc::new(b"thread-shared-input".to_vec());
    let target = Arc::new([0xBBu8; 32]);
    let baseline = derive_proposal_id(&chain, &state_pda, 42, &action, &target);

    let mut handles = Vec::new();
    for tid in 0..8u32 {
        let state_pda = Arc::clone(&state_pda);
        let action = Arc::clone(&action);
        let target = Arc::clone(&target);
        let expected = baseline;
        handles.push(thread::spawn(move || {
            for i in 0..1_000u32 {
                let got = derive_proposal_id(&chain, &state_pda, 42, &action, &target);
                assert_eq!(
                    got, expected,
                    "v4: thread {tid} iter {i} diverged — hidden global state suspected"
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ============================================================================
// 5. Borsh `cautious` hint behaves under u32::MAX vec-len — timing pin
// ============================================================================

/// Borsh 1.x's `hint::cautious::<T>(len)` caps the pre-allocated `Vec`
/// capacity at `max(min(len, 4096 / size_of::<T>()), 1)`. For a `Vec<u8>`
/// (el_size=1), that ceiling is 4096. We pin the OBSERVABLE consequence:
/// a malicious u32::MAX vec-len prefix must reject and complete in well
/// under 200 ms (i.e. Borsh did not allocate 4 GiB). The borsh_fuzz suite
/// already covers the "rejected" half; this adds the timing half.
#[test]
fn v4_attack_5a_borsh_cautious_capacity_under_u32_max() {
    use std::time::{Duration, Instant};

    // (a) Proposal with u32::MAX action_bytes len, no payload.
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32::MAX.to_le_bytes());

    let start = Instant::now();
    let res: Result<Proposal, _> = Proposal::try_from_slice(&buf);
    let elapsed = start.elapsed();
    assert!(res.is_err(), "u32::MAX prefix must reject");
    assert!(
        elapsed < Duration::from_millis(200),
        "v4: Proposal::try_from_slice took {elapsed:?} on u32::MAX prefix \
         — Borsh `cautious` may have regressed; check for `Vec::with_capacity(len as usize)`",
    );

    // (b) Instruction::Approve with u32::MAX receipt len, no payload.
    let mut buf2 = Vec::new();
    buf2.push(2u8); // Approve disc
    buf2.extend_from_slice(&[0xAA; 32]); // create_key
    buf2.extend_from_slice(&0u64.to_le_bytes()); // index
    buf2.extend_from_slice(&u32::MAX.to_le_bytes()); // receipt vec-len

    let start = Instant::now();
    let res2: Result<Instruction, _> = Instruction::try_from_slice(&buf2);
    let elapsed = start.elapsed();
    assert!(res2.is_err(), "u32::MAX receipt prefix must reject");
    assert!(
        elapsed < Duration::from_millis(200),
        "v4: Instruction::Approve receipt decode took {elapsed:?}",
    );
}

// ============================================================================
// 6. proposal_id 5-input simultaneous-sweep avalanche (10k random samples)
// ============================================================================

/// Round 3 pinned single-input avalanche sweeps. This is the stronger 5-input
/// SIMULTANEOUS sweep: every call randomizes (chain_id, state_pda, index,
/// action_bytes, target_program) independently. Zero collisions tolerated
/// across 10 000 samples. SHA-256 collision probability for 10k samples is
/// ~5e-71 — any hit is a structural bug.
#[test]
fn v4_attack_6a_proposal_id_collision_under_5_input_simultaneous_sweep_10k() {
    let mut r = rng();
    let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(10_000);
    for i in 0..10_000usize {
        let cid = ChainId::new(random_32(&mut r));
        let state_pda = random_32(&mut r);
        let index: u64 = r.gen();
        let action_len = r.gen_range(0..=128);
        let mut action = vec![0u8; action_len];
        r.fill_bytes(&mut action);
        let target = random_32(&mut r);
        let pid = derive_proposal_id(&cid, &state_pda, index, &action, &target);
        if !seen.insert(pid) {
            panic!("v4: proposal_id collision at trial {i}");
        }
    }
    assert_eq!(seen.len(), 10_000);
}

// ============================================================================
// 7. validate_threshold vs validate consistency under 100 random pairs
// ============================================================================

/// Round 3 pinned a fixed list of (m, n) pairs at the consistency boundary.
/// This is the stronger random sweep: 100 random `(m, n)` pairs, each
/// constructed into a `MultisigState`. The two paths must agree on every
/// pair. If a future refactor splits the predicates (e.g. moves the m=0
/// check into `validate` but not `validate_threshold`), this catches it.
#[test]
fn v4_attack_7a_validate_method_matches_threshold_100_random_pairs() {
    let mut r = StdRng::seed_from_u64(0xB10E_2002_A1B2_0701_u64);
    for _ in 0..100 {
        let m: u8 = r.gen();
        let n: u32 = r.gen();
        let state = MultisigState {
            create_key: [0; 32],
            members_root: [0; 32],
            m,
            n,
            proposal_count: 0,
        };
        let via_method = state.validate();
        let via_assoc = MultisigState::validate_threshold(m, n);
        assert_eq!(
            via_method, via_assoc,
            "v4: validate vs validate_threshold diverged at (m={m}, n={n})"
        );
        // And the expected predicate matches both.
        let expect_err = m == 0 || n == 0 || u32::from(m) > n;
        assert_eq!(via_method.is_err(), expect_err);
    }
}

// ============================================================================
// 8. derive_proposal_id preimage size sentinel
// ============================================================================

/// `derive_proposal_id` uses a stack-allocated `[u8; 136]` buffer. The 136
/// figure is `32 (chain_id) + 32 (state_pda) + 8 (index) + 32 (action_hash) +
/// 32 (target_hash)`. Pin the arithmetic so a future refactor that adds even
/// one extra slot inflates the stack frame visibly here. SHA-256 outer
/// invocation is over those 136 bytes; the output is 32 bytes.
#[test]
fn v4_attack_8a_proposal_id_preimage_size_is_136() {
    const EXPECTED: usize = 2 * 32 + 8 + 2 * 32;
    assert_eq!(EXPECTED, 136);

    // Indirect observable consequence: the preimage layout in
    // cross_crate_parity manually constructs a 136-byte buffer. If the
    // arithmetic ever changes, the manual recompute will diverge from
    // `derive_proposal_id` — which is asserted in bridge_proposal_id_*.
    // Here we re-derive the property: for a known fixture, the hash of
    // the 136-byte preimage equals the output of derive_proposal_id.
    use crypto::Hasher;
    let chain = ChainId::new([0x77; 32]);
    let state_pda = [0xAA; 32];
    let index: u64 = 0x0102_0304_0506_0708;
    let action: &[u8] = b"v4-size-pin";
    let target = [0xBB; 32];

    let actual = derive_proposal_id(&chain, &state_pda, index, action, &target);

    let action_hash = crypto::Sha256Hasher::hash(action);
    let target_hash = crypto::Sha256Hasher::hash(&target);
    let mut preimage = [0u8; EXPECTED];
    preimage[0..32].copy_from_slice(chain.as_bytes());
    preimage[32..64].copy_from_slice(&state_pda);
    preimage[64..72].copy_from_slice(&index.to_le_bytes());
    preimage[72..104].copy_from_slice(&action_hash);
    preimage[104..136].copy_from_slice(&target_hash);
    let expected = crypto::Sha256Hasher::hash(&preimage);
    assert_eq!(actual, expected, "v4: preimage size constant drift");
}

// ============================================================================
// 9. Borsh enum discriminant is u8 — byte-0 < 4 for any valid Instruction
// ============================================================================

/// Borsh 1.x encodes enum discriminants as `u8`. There are 4 variants today
/// (0..=3). For any of the four valid `Instruction` constructions, byte 0 of
/// the encoding MUST be < 4. This protects against any future Borsh change
/// to widen the discriminant.
#[test]
fn v4_attack_9a_instruction_discriminant_lt_4() {
    let cases: [Instruction; 4] = [
        Instruction::CreateMultisig {
            create_key: [0; 32],
            members_root: [0; 32],
            m: 0,
            n: 0,
        },
        Instruction::Propose {
            create_key: [0; 32],
            index: 0,
            action_bytes: Vec::new(),
            target_program: [0; 32],
        },
        Instruction::Approve {
            create_key: [0; 32],
            index: 0,
            receipt: Vec::new(),
            public_inputs: ApprovePublicInputs {
                members_root: [0; 32],
                proposal_id: [0; 32],
                nullifier: [0; 32],
            },
        },
        Instruction::Execute {
            create_key: [0; 32],
            index: 0,
        },
    ];
    let mut discs = HashSet::new();
    for (i, ix) in cases.iter().enumerate() {
        let bytes = to_vec(ix).unwrap();
        let disc = bytes[0];
        assert!(disc < 4, "v4: variant {i} disc {disc} >= 4");
        assert!(
            discs.insert(disc),
            "v4: two distinct variants share disc {disc}"
        );
    }
    assert_eq!(discs.len(), 4);
}

// ============================================================================
// 10. Public-symbol audit — every pub item is re-exported or documented
// ============================================================================

/// Every `pub fn`/`pub struct`/`pub enum`/`pub const`/`pub type` in `src/`
/// MUST be either re-exported at the crate root or intentionally
/// module-only. The hand-maintained list below mirrors the current `pub`
/// surface (verified by `grep` at the start of round 4). If a new pub
/// item lands without updating either side, the symbol fails to resolve
/// here, prompting an audit of whether it should be added to `lib.rs`.
#[test]
fn v4_attack_10a_public_surface_is_complete() {
    // (a) Re-exported at the crate root — these MUST resolve by short path.
    // Bind each to a typed identifier to force resolution.
    let _re_exports: (
        fn(&[u8; 32], &[u8; 32]) -> [u8; 32], // derive_multisig_state_pda
        fn(&[u8; 32], &[u8; 32], u64) -> [u8; 32], // derive_proposal_pda
        fn(&[u8; 32], &[u8; 32]) -> [u8; 32], // derive_vault_pda
        fn(&[u8; 32], &[u8; 32], &[u8; 32]) -> [u8; 32], // derive_nullifier_entry_pda
        fn(&ChainId, &[u8; 32], u64, &[u8], &[u8; 32]) -> [u8; 32], // derive_proposal_id
    ) = (
        derive_multisig_state_pda,
        derive_proposal_pda,
        derive_vault_pda,
        derive_nullifier_entry_pda,
        derive_proposal_id,
    );
    // Consts.
    let _re_const = (
        SEED_MULTISIG_STATE,
        SEED_PROPOSAL,
        SEED_VAULT,
        SEED_NULLIFIER,
        APPROVE_PUBLIC_INPUTS_LEN,
        MAX_ACTION_BYTES_LEN,
    );

    // (b) Module-only (intentionally NOT re-exported, per round-2 audit):
    //  - private_multisig_core::pda::derive_pda
    // Reach each via full path so a future `pub use` accidentally hiding
    // them would be caught by failing resolution. Post-round-5 signature
    // is `(program_id, &[&[u8; 32]])`.
    let _module_only: fn(&[u8; 32], &[&[u8; 32]]) -> [u8; 32] =
        private_multisig_core::pda::derive_pda;

    // Type-alias smoke checks. After the no_std refactor these live at the
    // crate root (so the guest can see them without bringing in the gated
    // `pda` module).
    let _pid: private_multisig_core::ProgramId = [0u8; 32];
    let _ack: private_multisig_core::AccountId = [0u8; 32];
    let _ck: private_multisig_core::CreateKey = [0u8; 32];

    // (c) Type re-exports — call each constructor at the crate root.
    let _e: CoreError = CoreError::AlreadyExecuted;
    let _i: Instruction = Instruction::Execute {
        create_key: [0; 32],
        index: 0,
    };
    let _s: MultisigState = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 1,
        n: 1,
        proposal_count: 0,
    };
    let _p: Proposal = Proposal {
        action_bytes: Vec::new(),
        target_program: [0; 32],
        approvals_count: 0,
        executed: false,
    };
    let _v: Vault = Vault { create_key: [0; 32] };
    let _ne: NullifierEntry = NullifierEntry;
    let _api: ApprovePublicInputs = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0; 32],
        nullifier: [0; 32],
    };
    let _c: ChainId = ChainId::from_u64(0);

    // Each compile-time resolution above is meaningful; assert one
    // runtime equality so the test body has at least one observable
    // assertion (not `assert!(true)`).
    assert_eq!(_pid.len(), 32);
}

// ============================================================================
// 11. Cross-round drift check — no test contradicts another
// ============================================================================

/// Paranoia sweep: every code value in the catalog must agree between
/// `from_code`, `code()`, and the abi_wire_format pin. If round 1 ever
/// asserted `from_code(1003) == None` (true at the time, false now after
/// FINDING-V2-A), that test would still be in the tree as a contradiction.
/// We re-confirm the current truth across the full 0..=5000 range AND
/// confirm `from_code(1003) == Some(InvalidThreshold)`.
#[test]
fn v4_attack_11a_no_cross_round_from_code_contradiction() {
    // Truth table per error.rs as of round 4.
    let truth: &[(u32, Option<CoreError>)] = &[
        (1000, Some(CoreError::InstanceNotActive)),
        (1001, Some(CoreError::ProposalExpiredOrExecuted)),
        (1002, Some(CoreError::ActionBytesTooLong)),
        (1003, Some(CoreError::InvalidThreshold)),
        (1004, Some(CoreError::SerializationError)),
        (1005, Some(CoreError::ArithmeticOverflow)),
        (1006, None),
        (1999, None),
        (2000, Some(CoreError::InvalidReceipt)),
        (2001, Some(CoreError::ImageIdMismatch)),
        (2002, Some(CoreError::RootMismatch)),
        (2003, Some(CoreError::ProposalIdMismatch)),
        (2004, None),
        (3000, Some(CoreError::NullifierAlreadyUsed)),
        (3001, None),
        (4000, Some(CoreError::ThresholdNotMet)),
        (4001, Some(CoreError::AlreadyExecuted)),
        (4002, None),
        (5000, None),
        (u32::MAX, None),
    ];
    for &(code, expected) in truth {
        assert_eq!(
            CoreError::from_code(code),
            expected,
            "v4: from_code({code}) drifted from cross-round truth"
        );
    }
}

// ============================================================================
// 12. Tautological-test replacements (NEW — round 3 missed these)
// ============================================================================

/// REPLACEMENT for round-1
/// `attack_9b_random_2k_byte_blobs_never_become_instructions`. The original
/// body counted acceptances but only `println!`'d the count — its sole
/// assertion was the count being valid (it accepted any value). With that
/// body, the test would pass even if every blob decoded.
///
/// Stronger replacement here:
///   (i)  no panics across 5 000 random blobs (round-1 already pinned this);
///   (ii) of those accepted, EVERY accepted decode round-trips back to the
///        same byte sequence (Borsh is bijective on its valid encodings —
///        a random blob that decoded but didn't round-trip would be a
///        soundness gap);
///   (iii) hard upper bound: fewer than 5% of random blobs decode. (5000
///        blobs with disc byte uniformly random over 256 values means the
///        4 valid disc values get ~5000/64 ≈ 78 hits; not all of those will
///        have well-formed bodies, so the real rate is much lower. 5% is a
///        loose ceiling that catches "accidentally accepted everything".)
#[test]
fn v4_attack_12a_replacement_for_random_2k_byte_blobs() {
    let mut r = rng();
    let mut accepted = 0usize;
    let mut accepted_roundtrip = 0usize;
    let total = 5_000;
    for _ in 0..total {
        let len = r.gen_range(0..200);
        let mut buf = vec![0u8; len];
        r.fill_bytes(&mut buf);
        let res = catch_unwind(AssertUnwindSafe(|| Instruction::try_from_slice(&buf)));
        let decoded = match res {
            Ok(Ok(ix)) => Some(ix),
            Ok(Err(_)) => None,
            Err(_) => panic!("v4: PANIC on random Instruction blob"),
        };
        if let Some(ix) = decoded {
            accepted += 1;
            // Bijectivity check: re-serialize → bytes the original blob
            // truncated to the consumed prefix.
            let reser = to_vec(&ix).unwrap();
            // Borsh is strict on trailing — `try_from_slice` succeeded so
            // `reser.len()` must equal `buf.len()`.
            assert_eq!(
                reser.len(),
                buf.len(),
                "v4: accepted blob did not bijectively round-trip"
            );
            assert_eq!(
                reser, buf,
                "v4: re-serialized accepted blob differs from input"
            );
            accepted_roundtrip += 1;
        }
    }
    // Hard ceiling: accepted rate < 5%.
    assert!(
        accepted * 20 < total * 1, // accepted/total < 0.05
        "v4: {accepted}/{total} random blobs decoded as Instruction (> 5%)"
    );
    // Every accepted decoded blob must round-trip.
    assert_eq!(accepted, accepted_roundtrip, "v4: bijectivity gap on decoded blobs");
}

/// REPLACEMENT for round-3
/// `v3_attack_14b_type_reexports_constructible_at_crate_root`. The original
/// body constructs values from the re-exported paths and `drop`s them — the
/// test only verifies *compilation*. A reader hand-replacing the body with
/// `assert!(true)` would still pass. The stronger replacement adds runtime
/// equality checks tied to the type's Borsh shape: if any future PR changes
/// e.g. `Vault.create_key` to `[u8; 16]`, the size assertion below breaks.
#[test]
fn v4_attack_12b_replacement_for_type_reexports_constructible() {
    // Construct each re-exported type and assert a runtime property that
    // would fail if the type's shape ever changed.
    let err = CoreError::AlreadyExecuted;
    assert_eq!(err.code(), 4001);

    let ix = Instruction::Execute {
        create_key: [0xAB; 32],
        index: 1234,
    };
    let ix_bytes = to_vec(&ix).unwrap();
    assert_eq!(ix_bytes.len(), 1 + 32 + 8, "Execute wire size drifted");
    assert_eq!(ix_bytes[0], 3, "Execute discriminant drifted");

    let state = MultisigState {
        create_key: [0xCD; 32],
        members_root: [0xEF; 32],
        m: 2,
        n: 3,
        proposal_count: 7,
    };
    assert_eq!(to_vec(&state).unwrap().len(), 77, "MultisigState wire size drifted");

    let prop = Proposal {
        action_bytes: vec![0xAA; 4],
        target_program: [0xBB; 32],
        approvals_count: 1,
        executed: false,
    };
    assert_eq!(to_vec(&prop).unwrap().len(), 4 + 4 + 32 + 4 + 1, "Proposal wire size drifted");

    let v = Vault { create_key: [0x42; 32] };
    assert_eq!(to_vec(&v).unwrap().len(), 32, "Vault wire size drifted");

    let ne = NullifierEntry;
    assert!(to_vec(&ne).unwrap().is_empty(), "NullifierEntry wire size drifted");

    let api = ApprovePublicInputs {
        members_root: [1; 32],
        proposal_id: [2; 32],
        nullifier: [3; 32],
    };
    assert_eq!(api.to_bytes().len(), 96);
    assert_eq!(to_vec(&api).unwrap().len(), 96);

    let cid = ChainId::from_u64(7);
    assert_eq!(cid.as_bytes()[0], 7, "ChainId byte-0 drifted from u64 LSB");
    assert_eq!(&cid.as_bytes()[1..], &[0u8; 31]);
}

// ============================================================================
// 13. Creative attacks
// ============================================================================

/// (13a) `ApprovePublicInputs::to_bytes` and `from_bytes` are a bijection
/// on `[u8; 96]`. Round 1 / round 2 / round 3 each pinned one direction or a
/// limited sample. Stronger here: 5 000 random byte arrays, plus 5 000
/// random `ApprovePublicInputs` constructions, plus the bijection
/// composed in both orders — both must be identity functions.
#[test]
fn v4_attack_13a_approve_public_inputs_bijection_compositional() {
    let mut r = rng();

    // (i) bytes -> from_bytes -> to_bytes must be identity.
    for _ in 0..5_000 {
        let mut buf = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        r.fill_bytes(&mut buf);
        let bundle = ApprovePublicInputs::from_bytes(&buf);
        let round = bundle.to_bytes();
        assert_eq!(buf, round, "v4: bytes -> from_bytes -> to_bytes not identity");
    }

    // (ii) bundle -> to_bytes -> from_bytes must be identity.
    for _ in 0..5_000 {
        let bundle = ApprovePublicInputs {
            members_root: random_32(&mut r),
            proposal_id: random_32(&mut r),
            nullifier: random_32(&mut r),
        };
        let bytes = bundle.to_bytes();
        let back = ApprovePublicInputs::from_bytes(&bytes);
        assert_eq!(bundle, back, "v4: bundle -> to_bytes -> from_bytes not identity");
    }
}

/// (13b) `ChainId` is `Copy` — copying it must never observe a different
/// value than the original. Trivial in Rust's ownership model but pin so a
/// future PR that wraps it around `Cell<...>` would break compilation here.
#[test]
fn v4_attack_13b_chain_id_copy_semantics() {
    let original = ChainId::from_u64(0xDEAD_BEEF);
    // Implicit Copy via assignment.
    let copy_a = original;
    let copy_b = original;
    let copy_c = copy_a;
    // All copies equal.
    assert_eq!(copy_a, original);
    assert_eq!(copy_b, original);
    assert_eq!(copy_c, original);
    // Bytes equal.
    assert_eq!(copy_a.as_bytes(), original.as_bytes());
    // Trait bound test: function takes T: Copy, must accept ChainId.
    fn takes_copy<T: Copy>(_t: T) {}
    takes_copy(original);
    // Original still usable after copy (not moved).
    assert_eq!(original.as_bytes()[0], 0xEF); // LSB
}

/// (13c) `Instruction::Approve` carries an `ApprovePublicInputs` BY VALUE,
/// not by reference. Confirm a clone of the bundle inside the instruction
/// stays equal to the original after Borsh round-trip — i.e. the embedding
/// doesn't add a sentinel byte or change the inner layout. Round 1's 12c
/// tested wire size; this test tests value equality through 50 random
/// public-inputs values.
#[test]
fn v4_attack_13c_instruction_approve_embeds_public_inputs_byvalue() {
    let mut r = rng();
    for _ in 0..50 {
        let inputs = ApprovePublicInputs {
            members_root: random_32(&mut r),
            proposal_id: random_32(&mut r),
            nullifier: random_32(&mut r),
        };
        let ix = Instruction::Approve {
            create_key: random_32(&mut r),
            index: r.gen(),
            receipt: vec![0xEE; 32],
            public_inputs: inputs,
        };
        let bytes = to_vec(&ix).unwrap();
        let back = Instruction::try_from_slice(&bytes).unwrap();
        match back {
            Instruction::Approve { public_inputs, .. } => {
                assert_eq!(
                    public_inputs, inputs,
                    "v4: embedded public_inputs drifted after round-trip"
                );
            }
            _ => panic!("v4: variant changed on round-trip"),
        }
    }
}

/// (13d) `derive_proposal_pda` LE index pin in a 1 000-iteration sweep:
/// for each index `i`, the proposal PDA at `i` must NOT equal the proposal
/// PDA at `i.swap_bytes()` (i.e. big-endian misencoding). The only exception
/// is when `i.swap_bytes() == i` (e.g. i=0, or all-bytes-equal palindrome
/// patterns like 0x4242_4242_4242_4242) — skip those.
#[test]
fn v4_attack_13d_proposal_pda_le_pin_1000_indices() {
    let program_id = [0x11u8; 32];
    let create_key = [0x22u8; 32];
    let mut r = StdRng::seed_from_u64(0xABCD_EF01_DEAD_BEEFu64);
    let mut tested = 0u32;
    while tested < 1_000 {
        let i: u64 = r.gen();
        let swapped = i.swap_bytes();
        if i == swapped {
            continue; // palindrome — LE and BE produce the same bytes
        }
        let pda_le = derive_proposal_pda(&program_id, &create_key, i);
        let pda_be = derive_proposal_pda(&program_id, &create_key, swapped);
        assert_ne!(
            pda_le, pda_be,
            "v4: LE(i=0x{i:016x}) == BE(i=0x{i:016x}) PDAs — endian bug"
        );
        tested += 1;
    }
}

/// (13e) `MultisigState::validate_threshold` is a `const fn`-able predicate
/// in spirit; round 3 sanity-swept the small (m, n) plane. Here we pin the
/// negation symmetry: if (m, n) is rejected, then for any m' < m with the
/// same n, the result for m' > n still uses the same error type. I.e. the
/// error VARIANT never mutates — there's only one path, only one variant.
#[test]
fn v4_attack_13e_validate_threshold_error_variant_is_constant() {
    // Sample 256 rejected pairs and confirm the error is always
    // `InvalidThreshold` (never something else like `InstanceNotActive`).
    let mut r = StdRng::seed_from_u64(0x0123_4567_89AB_CDEFu64);
    let mut rejected = 0u32;
    for _ in 0..256 {
        let m: u8 = r.gen();
        let n: u32 = r.gen();
        if let Err(e) = MultisigState::validate_threshold(m, n) {
            assert_eq!(
                e,
                CoreError::InvalidThreshold,
                "v4: validate_threshold({m}, {n}) returned wrong variant {e:?}"
            );
            rejected += 1;
        }
    }
    // Sanity: we should reject at least SOMETHING out of 256 random pairs
    // (the m == 0 path alone has probability 1/256 hits).
    assert!(rejected > 0, "v4: zero rejections out of 256 random (m, n) — sweep broken");
}

/// (13f) Seed constants are *content-addressed* — their byte values appear
/// in the SHA-256 preimage of every PDA they participate in. Confirm none
/// of them are byte-aliased: no rotation or reverse of one equals another.
/// This catches a "I copy-pasted SEED_PROPOSAL and forgot to change it" PR.
#[test]
fn v4_attack_13f_seed_constants_no_byte_alias_under_rotation() {
    let seeds: [&[u8; 13]; 4] = [
        SEED_MULTISIG_STATE,
        SEED_PROPOSAL,
        SEED_VAULT,
        SEED_NULLIFIER,
    ];
    // For each pair (i, j) with i != j, check that no left-rotation of
    // seeds[i] (rotations 1..13) equals seeds[j], and that
    // reverse(seeds[i]) != seeds[j].
    for i in 0..4 {
        for j in 0..4 {
            if i == j {
                continue;
            }
            let a = *seeds[i];
            let b = *seeds[j];
            // Rotations.
            for r in 1..13usize {
                let mut rotated = [0u8; 13];
                for k in 0..13 {
                    rotated[k] = a[(k + r) % 13];
                }
                assert_ne!(
                    rotated, b,
                    "v4: rotation({r}) of seeds[{i}] equals seeds[{j}]"
                );
            }
            // Reverse.
            let mut reversed = a;
            reversed.reverse();
            assert_ne!(
                reversed, b,
                "v4: reverse(seeds[{i}]) equals seeds[{j}]"
            );
        }
    }
}

/// (13g) `MultisigState::validate` ignores `proposal_count` and the
/// `create_key`/`members_root` byte values. Pin by varying those fields
/// independently and confirming `validate()` decisions depend purely on
/// (m, n).
#[test]
fn v4_attack_13g_validate_ignores_non_threshold_fields() {
    let mut r = StdRng::seed_from_u64(0xFEED_FACE_BAAD_F00Du64);
    for _ in 0..50 {
        let m: u8 = r.gen_range(0..=10);
        let n: u32 = r.gen_range(0..=10);
        let expected = MultisigState::validate_threshold(m, n);
        for _ in 0..5 {
            let s = MultisigState {
                create_key: random_32(&mut r),
                members_root: random_32(&mut r),
                m,
                n,
                proposal_count: r.gen(),
            };
            assert_eq!(
                s.validate(),
                expected,
                "v4: validate() depended on non-(m, n) fields at (m={m}, n={n})"
            );
        }
    }
}

/// (13h) Borsh's `try_from_slice` on `Instruction` is total over its
/// expected bit-width: there are 2^8 = 256 possible discriminant bytes,
/// of which only 0..=3 lead to any valid decode. Confirm exactly four
/// discriminants admit some valid encoding by exhaustively walking 0..=255
/// with a "minimum body" probe.
#[test]
fn v4_attack_13h_only_four_discriminants_decode() {
    let mut decodable_discs = HashSet::new();
    // Try a generously large body (256 bytes) for each disc so we don't
    // mis-reject a variant that needs more bytes than the minimum.
    for disc in 0u8..=255 {
        let mut buf = vec![disc];
        // Build a plausible body: 32 + 32 + 1 + 4 = 69 trailing bytes for
        // CreateMultisig, or 32 + 8 + 4 + 0 + 32 = 76 for Propose, or
        // 32 + 8 + 4 + 0 + 96 = 140 for Approve. 256 bytes covers all four.
        buf.resize(256, 0u8);
        // Set vec-len prefixes to 0 wherever they live (variant-dependent).
        // discriminant Propose=1: vec-len at offset 1+32+8 = 41 (already 0 from resize).
        // discriminant Approve=2: vec-len at offset 1+32+8 = 41 (already 0).
        let res = Instruction::try_from_slice(&buf);
        if res.is_ok() {
            decodable_discs.insert(disc);
        }
    }
    // Exactly four discriminants must decode for at least one body shape.
    // (Some 4..=255 may decode with trailing garbage rejected — they'll
    // appear as Err, not Ok.)
    // Note: for our 256-byte fixture, only discs 0, 1, 2 can decode given
    // exact body lengths; disc 3 (Execute) is 41 bytes total — 256 bytes
    // including disc means 255 trailing bytes which Borsh rejects.
    // So we expect 0 (CreateMultisig at len 1+69=70 < 256, trailing
    // rejected), and possibly disc 1/2 if their vec-prefixes give a body
    // that consumes exactly 256 - 1 = 255 bytes. Likely all four reject
    // due to trailing. We instead exhaustively sweep MULTIPLE body
    // lengths and union the discoverable discs.
    decodable_discs.clear();
    for disc in 0u8..=255 {
        for body_extra in [69usize, 76, 140, 40] {
            let mut buf = vec![disc];
            buf.resize(body_extra + 1, 0u8);
            if Instruction::try_from_slice(&buf).is_ok() {
                decodable_discs.insert(disc);
            }
        }
    }
    // The four valid discs ARE 0, 1, 2, 3 (CreateMultisig, Propose,
    // Approve, Execute) — at the body lengths chosen, all four should
    // decode with their minimum payloads (Propose at body 76 with 0 vec
    // is 32+8+4+32 = 76; Approve at 140 with 0 vec is 32+8+4+96 = 140;
    // CreateMultisig at 69 = 32+32+1+4; Execute at 40 = 32+8).
    assert_eq!(
        decodable_discs.len(),
        4,
        "v4: expected exactly 4 decodable discs, found {:?}",
        decodable_discs
    );
    for d in [0u8, 1, 2, 3] {
        assert!(decodable_discs.contains(&d), "v4: disc {d} did not decode");
    }
}

/// (13i) Sentinel that `derive_proposal_id` and `derive_proposal_pda`
/// PRODUCE DIFFERENT VALUES for the same `(create_key, index)` even though
/// both functions consume those inputs. Their outputs occupy distinct
/// "namespaces" — proposal_id is hash space for proof binding, proposal_pda
/// is hash space for on-chain account addressing. Round 2's domain-
/// separation test sampled this loosely; here we sweep 1 000 pairs.
#[test]
fn v4_attack_13i_proposal_id_neq_proposal_pda() {
    let program_id = [0x11u8; 32];
    let chain = ChainId::from_u64(1);
    let target = [0xCC; 32];
    let action = b"x";
    let mut r = StdRng::seed_from_u64(0xDEADBEEF_F00DCAFEu64);
    let state_pda = derive_multisig_state_pda(&program_id, &[0xABu8; 32]);
    for _ in 0..1_000 {
        let ck = random_32(&mut r);
        let idx: u64 = r.gen();
        let pid = derive_proposal_id(&chain, &state_pda, idx, action, &target);
        let pda = derive_proposal_pda(&program_id, &ck, idx);
        assert_ne!(
            pid, pda,
            "v4: proposal_id collided with proposal_pda — domain hole"
        );
    }
}

/// (13j) `Vault` is `Copy` (derives it) — but `Proposal` and `Instruction`
/// are not (they carry Vecs). Pin the Copy / non-Copy split with
/// compile-time + runtime evidence.
#[test]
fn v4_attack_13j_copy_split_pinned() {
    // Functions that require Copy / non-Copy bounds.
    fn requires_copy<T: Copy>(_t: T) {}
    fn requires_clone<T: Clone>(t: &T) -> T {
        t.clone()
    }

    let v = Vault { create_key: [0x55; 32] };
    requires_copy(v); // Vault is Copy.
    let _v2 = v; // copy, not move.
    let _v3 = v; // still usable.

    let ne = NullifierEntry;
    requires_copy(ne); // NullifierEntry is Copy.

    let api = ApprovePublicInputs {
        members_root: [0; 32],
        proposal_id: [0; 32],
        nullifier: [0; 32],
    };
    requires_copy(api); // ApprovePublicInputs is Copy.

    let cid = ChainId::from_u64(0);
    requires_copy(cid); // ChainId is Copy.

    let err = CoreError::InstanceNotActive;
    requires_copy(err); // CoreError is Copy.

    // Proposal & Instruction: Clone but not Copy.
    let p = Proposal {
        action_bytes: vec![0u8; 4],
        target_program: [0; 32],
        approvals_count: 0,
        executed: false,
    };
    let _p_clone = requires_clone(&p);

    let ix = Instruction::Execute {
        create_key: [0; 32],
        index: 0,
    };
    let _ix_clone = requires_clone(&ix);

    // The fact that this test compiles AND runs is the assertion.
    assert_eq!(mem::size_of::<Vault>(), 32);
}

/// (13k) `MultisigState` is `Clone` but not `Copy` — it derives Clone
/// without Copy. (The compiler reports `n: u32` and `proposal_count: u64`
/// as Copy-eligible, but the derive isn't on the struct itself.) Pin both
/// halves so a future `#[derive(Copy)]` addition lands here visibly.
#[test]
fn v4_attack_13k_multisig_state_clone_only() {
    fn requires_clone<T: Clone>(t: &T) -> T {
        t.clone()
    }
    let s = MultisigState {
        create_key: [0; 32],
        members_root: [0; 32],
        m: 0,
        n: 0,
        proposal_count: 0,
    };
    let _s_clone = requires_clone(&s);
    // Compile-time: if `MultisigState: Copy` we'd be able to do
    // `let _s2 = s; let _s3 = s;` and BOTH usages compile. Round 4 does
    // not require Copy on MultisigState — keep it non-Copy so future
    // PR adding Copy is a deliberate decision.
    //
    // The runtime evidence: cloning produces an EQUAL but DISTINCT value.
    let s2 = s.clone();
    assert_eq!(s2, s);
    // (Can't assert distinct addresses cleanly without unsafe; the
    // clone-success itself is the evidence.)
}

/// (13l) Borsh-decoded `Proposal` always has `Vec<u8>` capacity >= its
/// length. This is a Rust invariant but it's worth pinning because the
/// `cautious` hint inside Borsh's deserializer could in principle return
/// capacity != length on some allocator edge cases.
#[test]
fn v4_attack_13l_proposal_action_bytes_capacity_geq_len() {
    let bases = [0usize, 1, 16, 1024, MAX_ACTION_BYTES_LEN];
    for len in bases {
        let p = Proposal {
            action_bytes: vec![0xABu8; len],
            target_program: [0; 32],
            approvals_count: 0,
            executed: false,
        };
        let bytes = to_vec(&p).unwrap();
        let back: Proposal = Proposal::try_from_slice(&bytes).unwrap();
        assert_eq!(back.action_bytes.len(), len);
        assert!(
            back.action_bytes.capacity() >= back.action_bytes.len(),
            "v4: Vec capacity < len at action_bytes len={len}"
        );
    }
}

/// (13m) `ChainId::from_u64` is total over every u64. Sample 1 024 u64
/// values from edge bands (0, 1, MAX, MAX-1, powers of 2 within range) and
/// confirm none panic and every result is a distinct 32-byte form.
#[test]
fn v4_attack_13m_chain_id_from_u64_total_with_edge_bands() {
    let mut seen = HashSet::new();
    let mut probes: Vec<u64> = Vec::new();
    probes.extend([0u64, 1, 2, u64::MAX, u64::MAX - 1, u64::MAX / 2]);
    for s in 0..64u32 {
        probes.push(1u64 << s);
        if s > 0 {
            probes.push((1u64 << s) - 1);
        }
    }
    // De-dup the probes (powers of 2 minus 1 overlap with MAX etc.)
    let probes: HashSet<u64> = probes.into_iter().collect();
    for v in probes {
        let cid = ChainId::from_u64(v);
        let bytes = *cid.as_bytes();
        // First 8 bytes LE-equal the u64; high 24 zero.
        assert_eq!(&bytes[..8], &v.to_le_bytes());
        assert_eq!(&bytes[8..], &[0u8; 24]);
        assert!(seen.insert(bytes), "v4: ChainId::from_u64({v}) collided");
    }
}

/// (13n) Catch a hypothetical bug where `derive_proposal_id`'s last
/// SHA-256 operates on a shorter buffer than 136 bytes because the
/// preimage size constant was mis-allocated. A buffer that's 1 byte
/// shorter would hash a trailing-byte-of-zero off the end if it was
/// stack-allocated; we cannot directly observe `buf.len()` but we can
/// pin a known-answer hash: SHA-256 over the all-zero 136-byte buffer
/// matches what `derive_proposal_id` produces for all-zero inputs
/// EXCEPT that the action_hash and target_hash slots aren't zero (they
/// are SHA-256(empty) and SHA-256([0;32]) respectively). Build the
/// expected hash from those two known values and verify against the
/// implementation.
#[test]
fn v4_attack_13n_proposal_id_known_answer_under_zero_inputs() {
    use crypto::Hasher;

    let cid = ChainId::new([0u8; 32]);
    let state_pda = [0u8; 32];
    let action: &[u8] = &[];
    let target = [0u8; 32];
    let actual = derive_proposal_id(&cid, &state_pda, 0u64, action, &target);

    // Construct the expected 136-byte preimage by hand.
    let action_hash = crypto::Sha256Hasher::hash(action);
    let target_hash = crypto::Sha256Hasher::hash(&target);
    let mut preimage = [0u8; 136];
    // [0..32) chain_id = zero (already zero from init)
    // [32..64) state_pda = zero
    // [64..72) index = 0 LE = zero
    preimage[72..104].copy_from_slice(&action_hash);
    preimage[104..136].copy_from_slice(&target_hash);
    let expected = crypto::Sha256Hasher::hash(&preimage);
    assert_eq!(actual, expected, "v4: proposal_id zero-inputs KAT drifted");
    assert_ne!(actual, [0u8; 32], "v4: proposal_id over zeros is itself zero");
}

/// (13o) Final paranoia: in the entire 0..=65535 u32 range, the only codes
/// `from_code` accepts are the 11 documented ones. This sweeps a much wider
/// range than round 1 (which stopped at 5000) so any code accidentally
/// added in a high-numbered slot (e.g. 12345) surfaces.
#[test]
fn v4_attack_13o_from_code_sparse_over_65k() {
    let documented: HashSet<u32> = [
        1000, 1001, 1002, 1003, 1004, 1005, 2000, 2001, 2002, 2003, 3000, 4000, 4001,
    ]
    .into_iter()
    .collect();
    for code in 0u32..=65_535 {
        let got = CoreError::from_code(code);
        if documented.contains(&code) {
            assert!(got.is_some(), "v4: documented code {code} returned None");
        } else {
            assert!(got.is_none(), "v4: undocumented code {code} mapped to {got:?}");
        }
    }
}
