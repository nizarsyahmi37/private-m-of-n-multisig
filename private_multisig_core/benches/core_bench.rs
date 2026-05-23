//! Performance benchmarks for the `private_multisig_core` crate.
//!
//! Covers PDA derivation, `derive_proposal_id`, Borsh round-trips for every
//! public type, the cheap `validate_threshold` predicate, and the explicit
//! `ApprovePublicInputs::{to_bytes, from_bytes}` versus its Borsh equivalent.
//!
//! Run with: `cargo bench -p private_multisig_core`.

use borsh::{to_vec, BorshDeserialize};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use private_multisig_core::proof::ChainId;
use private_multisig_core::{
    derive_multisig_state_pda, derive_nullifier_entry_pda, derive_proposal_id, derive_proposal_pda,
    derive_vault_pda, ApprovePublicInputs, Instruction, MultisigState, NullifierEntry, Proposal,
    Vault,
};

// ---------- shared fixtures ----------

const PROGRAM_ID: [u8; 32] = [0xA1; 32];
const CREATE_KEY: [u8; 32] = [0xB2; 32];
const TARGET_PROGRAM: [u8; 32] = [0xCC; 32];
const NULLIFIER: [u8; 32] = [0x44; 32];

fn sample_state() -> MultisigState {
    MultisigState {
        create_key: CREATE_KEY,
        members_root: [0xBB; 32],
        m: 3,
        n: 5,
        proposal_count: 42,
    }
}

fn sample_proposal(action_len: usize) -> Proposal {
    Proposal {
        action_bytes: vec![0xFEu8; action_len],
        target_program: TARGET_PROGRAM,
        approvals_count: 2,
        executed: false,
    }
}

fn sample_inputs() -> ApprovePublicInputs {
    ApprovePublicInputs {
        members_root: [0x11; 32],
        proposal_id: [0x22; 32],
        nullifier: [0x33; 32],
    }
}

// ---------- 1. PDA derivation ----------

fn bench_pda_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pda_derivation");

    group.bench_function("derive_multisig_state_pda", |b| {
        b.iter(|| derive_multisig_state_pda(black_box(&PROGRAM_ID), black_box(&CREATE_KEY)));
    });

    group.bench_function("derive_proposal_pda_index_0", |b| {
        b.iter(|| {
            derive_proposal_pda(black_box(&PROGRAM_ID), black_box(&CREATE_KEY), black_box(0))
        });
    });

    group.bench_function("derive_proposal_pda_index_u64_max", |b| {
        b.iter(|| {
            derive_proposal_pda(
                black_box(&PROGRAM_ID),
                black_box(&CREATE_KEY),
                black_box(u64::MAX),
            )
        });
    });

    group.bench_function("derive_vault_pda", |b| {
        b.iter(|| derive_vault_pda(black_box(&PROGRAM_ID), black_box(&CREATE_KEY)));
    });

    let proposal_pda = derive_proposal_pda(&PROGRAM_ID, &CREATE_KEY, 0);
    group.bench_function("derive_nullifier_entry_pda", |b| {
        b.iter(|| {
            derive_nullifier_entry_pda(
                black_box(&PROGRAM_ID),
                black_box(&proposal_pda),
                black_box(&NULLIFIER),
            )
        });
    });

    group.finish();
}

// ---------- 2. derive_proposal_id at varied action_bytes sizes ----------

fn bench_derive_proposal_id(c: &mut Criterion) {
    let mut group = c.benchmark_group("derive_proposal_id");
    let chain_id = ChainId::from_u64(1);
    let state_pda = derive_multisig_state_pda(&PROGRAM_ID, &CREATE_KEY);

    for &len in &[0usize, 100, 4096] {
        let action_bytes = vec![0xCDu8; len];
        group.bench_with_input(
            BenchmarkId::from_parameter(len),
            &action_bytes,
            |b, action| {
                b.iter(|| {
                    derive_proposal_id(
                        black_box(&chain_id),
                        black_box(&state_pda),
                        black_box(0),
                        black_box(action),
                        black_box(&TARGET_PROGRAM),
                    )
                });
            },
        );
    }
    group.finish();
}

// ---------- 3. Borsh round-trip for every public type ----------

fn bench_borsh_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("borsh_round_trip");

    let state = sample_state();
    group.bench_function("MultisigState", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&state)).unwrap();
            let decoded = MultisigState::try_from_slice(&bytes).unwrap();
            black_box(decoded)
        });
    });

    for &action_len in &[0usize, 100, 4096] {
        let proposal = sample_proposal(action_len);
        group.bench_with_input(
            BenchmarkId::new("Proposal", action_len),
            &proposal,
            |b, p| {
                b.iter(|| {
                    let bytes = to_vec(black_box(p)).unwrap();
                    let decoded = Proposal::try_from_slice(&bytes).unwrap();
                    black_box(decoded)
                });
            },
        );
    }

    let vault = Vault {
        create_key: CREATE_KEY,
    };
    group.bench_function("Vault", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&vault)).unwrap();
            let decoded = Vault::try_from_slice(&bytes).unwrap();
            black_box(decoded)
        });
    });

    let nullifier_entry = NullifierEntry;
    group.bench_function("NullifierEntry", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&nullifier_entry)).unwrap();
            let decoded = NullifierEntry::try_from_slice(&bytes).unwrap();
            black_box(decoded)
        });
    });

    let inputs = sample_inputs();
    group.bench_function("ApprovePublicInputs", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&inputs)).unwrap();
            let decoded = ApprovePublicInputs::try_from_slice(&bytes).unwrap();
            black_box(decoded)
        });
    });

    // ---- Instruction variants ----

    let ix_create = Instruction::CreateMultisig {
        create_key: CREATE_KEY,
        members_root: [0xBB; 32],
        m: 3,
        n: 5,
    };
    group.bench_function("Instruction::CreateMultisig", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&ix_create)).unwrap();
            let decoded = Instruction::try_from_slice(&bytes).unwrap();
            black_box(decoded)
        });
    });

    for &action_len in &[0usize, 100] {
        let ix_propose = Instruction::Propose {
            create_key: CREATE_KEY,
            index: 7,
            action_bytes: vec![0xABu8; action_len],
            target_program: TARGET_PROGRAM,
        };
        group.bench_with_input(
            BenchmarkId::new("Instruction::Propose", action_len),
            &ix_propose,
            |b, ix| {
                b.iter(|| {
                    let bytes = to_vec(black_box(ix)).unwrap();
                    let decoded = Instruction::try_from_slice(&bytes).unwrap();
                    black_box(decoded)
                });
            },
        );
    }

    // Round 6 unified Approve with the verifier handler shape:
    // {create_key, index, nullifier, public_inputs: Vec<u8>}. The wire is
    // 173 bytes for the canonical 96-byte ApprovePublicInputs payload.
    let ix_approve = Instruction::Approve {
        create_key: CREATE_KEY,
        index: 7,
        nullifier: inputs.nullifier,
        public_inputs: inputs.to_bytes().to_vec(),
    };
    group.bench_function("Instruction::Approve", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&ix_approve)).unwrap();
            let decoded = Instruction::try_from_slice(&bytes).unwrap();
            black_box(decoded)
        });
    });

    let ix_execute = Instruction::Execute {
        create_key: CREATE_KEY,
        index: 12345,
    };
    group.bench_function("Instruction::Execute", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&ix_execute)).unwrap();
            let decoded = Instruction::try_from_slice(&bytes).unwrap();
            black_box(decoded)
        });
    });

    group.finish();
}

// ---------- 4. validate_threshold ----------

fn bench_validate_threshold(c: &mut Criterion) {
    c.bench_function("MultisigState::validate_threshold", |b| {
        b.iter(|| MultisigState::validate_threshold(black_box(3u8), black_box(5u32)));
    });
}

// ---------- 5. ApprovePublicInputs explicit layout vs Borsh ----------

fn bench_approve_public_inputs_layouts(c: &mut Criterion) {
    let mut group = c.benchmark_group("ApprovePublicInputs_layout");

    let inputs = sample_inputs();
    group.bench_function("to_bytes", |b| {
        b.iter(|| black_box(&inputs).to_bytes());
    });

    let bytes96 = inputs.to_bytes();
    group.bench_function("from_bytes", |b| {
        b.iter(|| ApprovePublicInputs::from_bytes(black_box(&bytes96)));
    });

    group.bench_function("borsh_to_vec", |b| {
        b.iter(|| to_vec(black_box(&inputs)).unwrap());
    });

    let borsh_bytes = to_vec(&inputs).unwrap();
    group.bench_function("borsh_try_from_slice", |b| {
        b.iter(|| ApprovePublicInputs::try_from_slice(black_box(&borsh_bytes)).unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_pda_derivation,
    bench_derive_proposal_id,
    bench_borsh_round_trip,
    bench_validate_threshold,
    bench_approve_public_inputs_layouts,
);
criterion_main!(benches);
