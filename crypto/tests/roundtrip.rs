//! End-to-end round trip exercising the full crypto core in one flow:
//!   identity → commitment → enroll into Merkle tree → derive proof → derive
//!   nullifier → verify Merkle proof against the tree root.
//!
//! This is the integration test PLAN.md §Implementation order step 1 calls for.

use crypto::{merkle::verify_proof, Identity, MerkleTree, Sha256Hasher};

const N: usize = 8;
const M: usize = 5;

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
fn full_enrollment_and_approval_round_trip() {
    let members: Vec<Identity> = (0..N as u8).map(deterministic_identity).collect();

    // Admin enrolls N commitments into the Merkle tree.
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut commitments = Vec::with_capacity(N);
    let mut indices = Vec::with_capacity(N);
    for m in &members {
        let c = m.commitment::<Sha256Hasher>();
        let idx = tree.insert(*c.as_bytes()).unwrap();
        commitments.push(c);
        indices.push(idx);
    }
    let root = tree.root();

    // The first M members each produce a Merkle proof against the final root,
    // and a nullifier for a sample proposal_id. Both must verify locally before
    // they would ever be submitted on-chain.
    let proposal_id: [u8; 32] = [0xABu8; 32];
    let mut nullifiers = Vec::with_capacity(M);
    for (i, m) in members.iter().take(M).enumerate() {
        let leaf = *commitments[i].as_bytes();
        let proof = tree.proof(indices[i]).expect("proof for own leaf");
        assert!(
            verify_proof::<Sha256Hasher>(&root, &leaf, &proof),
            "member {i} cannot prove membership"
        );

        let n = crypto::nullifier::<Sha256Hasher>(&m.sk, &proposal_id);
        nullifiers.push(n);
    }

    // All nullifiers in a single (member-set, proposal) are distinct — this is
    // the property the on-chain `NullifierEntry` PDA leans on for double-vote
    // prevention (THREAT_MODEL.md T2.1, T2.2).
    let mut sorted = nullifiers.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), nullifiers.len(), "nullifier collision");

    // The same member voting on the same proposal twice produces the same
    // nullifier — what we want, because the second submission's PDA init fails.
    let replay = crypto::nullifier::<Sha256Hasher>(&members[0].sk, &proposal_id);
    assert_eq!(replay, nullifiers[0]);
}

#[test]
fn member_outside_tree_cannot_forge_membership() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for i in 0..4 {
        let id = deterministic_identity(i);
        tree.insert(*id.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let root = tree.root();

    // An outsider tries to claim membership at index 0 with their own leaf.
    let outsider = deterministic_identity(99);
    let outsider_leaf = *outsider.commitment::<Sha256Hasher>().as_bytes();
    let proof = tree.proof(0).unwrap();

    assert!(
        !verify_proof::<Sha256Hasher>(&root, &outsider_leaf, &proof),
        "outsider's leaf must not verify against the real tree's proof shape"
    );
}
