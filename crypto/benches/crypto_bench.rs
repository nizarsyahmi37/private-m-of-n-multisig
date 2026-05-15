//! Performance benchmarks for the crypto crate primitives.
//!
//! These numbers feed the PLAN.md "laptop-feasible proving" claim for LP-0002
//! Private M-of-N Multisig. The hot loop inside the Risc0 guest will be
//! `verify_proof`, which calls `hash_leaf` once and `hash_node` 20 times per
//! approval. The on-chain verifier runs the same code.
//!
//! Run with: `cargo bench -p crypto`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use crypto::{
    nullifier, verify_proof, Hasher, Identity, MerkleTree, Sha256Hasher, HASH_LEN, MERKLE_DEPTH,
};

fn bench_hash_varied(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sha256Hasher::hash");
    for size in [32usize, 64, 96, 128] {
        let input = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &input, |b, input| {
            b.iter(|| Sha256Hasher::hash(black_box(input)));
        });
    }
    group.finish();
}

fn bench_hash_leaf(c: &mut Criterion) {
    let leaf = [0x11u8; HASH_LEN];
    c.bench_function("Sha256Hasher::hash_leaf", |b| {
        b.iter(|| Sha256Hasher::hash_leaf(black_box(&leaf)));
    });
}

fn bench_hash_node(c: &mut Criterion) {
    let l = [0x22u8; HASH_LEN];
    let r = [0x33u8; HASH_LEN];
    c.bench_function("Sha256Hasher::hash_node", |b| {
        b.iter(|| Sha256Hasher::hash_node(black_box(&l), black_box(&r)));
    });
}

fn bench_hash_pair(c: &mut Criterion) {
    let l = [0x44u8; HASH_LEN];
    let r = [0x55u8; HASH_LEN];
    c.bench_function("Sha256Hasher::hash_pair", |b| {
        b.iter(|| Sha256Hasher::hash_pair(black_box(&l), black_box(&r)));
    });
}

fn bench_identity_commitment(c: &mut Criterion) {
    let id = Identity::new([0x77u8; 32], [0x88u8; 32]);
    c.bench_function("Identity::commitment", |b| {
        b.iter(|| black_box(&id).commitment::<Sha256Hasher>());
    });
}

fn bench_identity_nullifier(c: &mut Criterion) {
    let id = Identity::new([0x77u8; 32], [0x88u8; 32]);
    let pid = [0x99u8; HASH_LEN];
    c.bench_function("Identity::nullifier", |b| {
        b.iter(|| black_box(&id).nullifier::<Sha256Hasher>(black_box(&pid)));
    });
}

fn bench_nullifier_free_fn(c: &mut Criterion) {
    let sk = [0x77u8; 32];
    let pid = [0x99u8; HASH_LEN];
    c.bench_function("nullifier (free fn)", |b| {
        b.iter(|| nullifier::<Sha256Hasher>(black_box(&sk), black_box(&pid)));
    });
}

fn bench_merkle_new(c: &mut Criterion) {
    c.bench_function("MerkleTree::new", |b| {
        b.iter(MerkleTree::<Sha256Hasher>::new);
    });
}

fn bench_merkle_insert(c: &mut Criterion) {
    c.bench_function("MerkleTree::insert", |b| {
        b.iter_batched(
            MerkleTree::<Sha256Hasher>::new,
            |mut tree| {
                let leaf = [0xCDu8; HASH_LEN];
                tree.insert(black_box(leaf)).unwrap();
                tree
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn make_tree(n: usize) -> MerkleTree<Sha256Hasher> {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for i in 0..n {
        // Avoid leaf == [0;32] (rejected by FINDING-1b guard). i starts at 0
        // so derive bytes that are never all-zero.
        let mut leaf = [0u8; HASH_LEN];
        leaf[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        leaf[8] = 0x01; // ensures non-zero even when i == 0
        tree.insert(leaf).unwrap();
    }
    tree
}

fn bench_merkle_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("MerkleTree::root");
    for n in [1usize, 64, 1024, 8192] {
        let tree = make_tree(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &tree, |b, tree| {
            b.iter(|| black_box(tree).root());
        });
    }
    group.finish();
}

fn bench_merkle_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("MerkleTree::proof");
    for n in [64usize, 1024, 8192] {
        let tree = make_tree(n);
        let idx = n / 2;
        group.bench_with_input(BenchmarkId::from_parameter(n), &(tree, idx), |b, (t, i)| {
            b.iter(|| black_box(t).proof(black_box(*i)).unwrap());
        });
    }
    group.finish();
}

fn bench_verify_proof(c: &mut Criterion) {
    // Use a non-trivial tree so the proof is realistic, then capture root +
    // proof + leaf so the bench body only exercises the verifier.
    let tree = make_tree(1024);
    let idx = 512usize;
    let mut leaf = [0u8; HASH_LEN];
    leaf[0..8].copy_from_slice(&(idx as u64).to_le_bytes());
    leaf[8] = 0x01;
    let proof = tree.proof(idx).unwrap();
    let root = tree.root();

    // Sanity: must verify before we benchmark it.
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &proof));
    assert_eq!(MERKLE_DEPTH, 20);

    c.bench_function("verify_proof", |b| {
        b.iter(|| {
            verify_proof::<Sha256Hasher>(black_box(&root), black_box(&leaf), black_box(&proof))
        });
    });
}

criterion_group!(
    benches,
    bench_hash_varied,
    bench_hash_leaf,
    bench_hash_node,
    bench_hash_pair,
    bench_identity_commitment,
    bench_identity_nullifier,
    bench_nullifier_free_fn,
    bench_merkle_new,
    bench_merkle_insert,
    bench_merkle_root,
    bench_merkle_proof,
    bench_verify_proof,
);
criterion_main!(benches);
