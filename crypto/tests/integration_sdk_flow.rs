//! Downstream-consumer smoke test for the `crypto` crate.
//!
//! Written from the perspective of the SDK author and the Risc0 guest author
//! who will start writing code against this crate next week (PLAN.md steps 2,
//! 3, 4). Each test below is a realistic slice of the end-to-end flow:
//!
//!   member-enrollment → proposal_id derivation → nullifier derivation →
//!   public-input bundle assembly → local pre-submission Merkle verification →
//!   double-vote detection → outsider-cannot-forge.
//!
//! Anything that surprised me while writing the tests — missing re-exports,
//! awkward borrow shapes, missing trait derives, documentation gaps — is
//! captured in inline `// FINDING:` comments and rolled up in the report.

use crypto::{
    // NOTE on crate-root surface: PLAN.md / the task brief list
    // `DOMAIN_LEAF`, `DOMAIN_NODE`, `SK_LEN`, `SALT_LEN`, `MAX_LEAVES`, and
    // `verify_proof` as part of the public API, but only some are re-exported
    // from the crate root. The ones below have to be reached through their
    // module paths.
    //
    // FINDING (Annoyance): the crate root re-exports `Hash`, `Hasher`,
    // `Sha256Hasher`, `HASH_LEN`, `Identity`, `IdentityCommitment`,
    // `MerkleTree`, `MerkleProof`, `MerkleError`, `MERKLE_DEPTH`, and
    // `nullifier` — but NOT `DOMAIN_LEAF`, `DOMAIN_NODE`, `SK_LEN`, `SALT_LEN`,
    // `MAX_LEAVES`, or `verify_proof`. Downstream code has to mix
    // `crypto::X` with `crypto::merkle::Y` / `crypto::identity::Z` /
    // `crypto::hash::W`, which reads inconsistently. Suggested fix: add
    // `pub use merkle::{verify_proof, MAX_LEAVES}; pub use identity::{SK_LEN,
    // SALT_LEN}; pub use hash::{DOMAIN_LEAF, DOMAIN_NODE};` to lib.rs.
    hash::{DOMAIN_LEAF, DOMAIN_NODE},
    identity::{SALT_LEN, SK_LEN},
    merkle::{verify_proof, MAX_LEAVES},
    Hash,
    Hasher,
    Identity,
    IdentityCommitment,
    MerkleProof,
    MerkleTree,
    Sha256Hasher,
    HASH_LEN,
    MERKLE_DEPTH,
};

use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};

// ---------------------------------------------------------------------------
// Test helpers — only call into the public API, no internal access.
// ---------------------------------------------------------------------------

/// Generate a random `Identity` from the given RNG. This is the kind of
/// helper every SDK consumer will write on day one; the crate doesn't
/// provide it.
///
/// FINDING (Nit): an `Identity::random<R: Rng>(rng: &mut R)` constructor
/// (gated behind a `std` / `rand` feature so the Risc0 guest stays no-std)
/// would save every consumer from writing this. Not a blocker.
fn random_identity<R: Rng>(rng: &mut R) -> Identity {
    let mut sk = [0u8; SK_LEN];
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut sk);
    rng.fill_bytes(&mut salt);
    Identity::new(sk, salt)
}

/// Derive `proposal_id` the way `private_multisig_core` will (PLAN.md step 2):
///
///   proposal_id = H( chain_id ‖ state_pda_bytes ‖ index_le
///                    ‖ H(action_bytes) ‖ H(target_program) )
///
/// Each inner hash uses `Sha256Hasher::hash` (the only public hashing entry
/// point exposed by the crate via the `Hasher` trait).
fn derive_proposal_id(
    chain_id: &[u8],
    state_pda_bytes: &[u8; 32],
    index: u64,
    action_bytes: &[u8],
    target_program: &[u8],
) -> Hash {
    let action_hash = Sha256Hasher::hash(action_bytes);
    let target_hash = Sha256Hasher::hash(target_program);
    let index_le = index.to_le_bytes();

    let mut buf = Vec::with_capacity(chain_id.len() + 32 + 8 + 32 + 32);
    buf.extend_from_slice(chain_id);
    buf.extend_from_slice(state_pda_bytes);
    buf.extend_from_slice(&index_le);
    buf.extend_from_slice(&action_hash);
    buf.extend_from_slice(&target_hash);
    Sha256Hasher::hash(&buf)
}

/// Pack the 96-byte public-input bundle the verifier program reads
/// (`[members_root ‖ proposal_id ‖ nullifier]`, PLAN.md step 2 layout).
fn pack_public_inputs(members_root: &Hash, proposal_id: &Hash, nullifier: &Hash) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(members_root);
    out[32..64].copy_from_slice(proposal_id);
    out[64..96].copy_from_slice(nullifier);
    out
}

/// Rebuild a root from scratch given only the public leaf set, simulating
/// what any third party (a watcher, the verifier program, a re-syncing
/// member) would do. This is what the "third party with only the public
/// leaf set" check needs.
fn root_from_public_leaves(leaves: &[Hash]) -> Hash {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    for l in leaves {
        t.insert(*l).expect("tree not full in tests");
    }
    t.root()
}

// ---------------------------------------------------------------------------
// 1. Member enrollment
// ---------------------------------------------------------------------------

#[test]
fn sdk_flow_member_enrollment() {
    let mut rng = StdRng::seed_from_u64(0xA11CE);

    // Admin generates N identities, derives commitments, enrolls in order.
    const N: usize = 8;
    let identities: Vec<Identity> = (0..N).map(|_| random_identity(&mut rng)).collect();

    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut stored: Vec<(IdentityCommitment, usize)> = Vec::with_capacity(N);
    let mut public_leaves: Vec<Hash> = Vec::with_capacity(N);

    for id in &identities {
        let commitment = id.commitment::<Sha256Hasher>();
        let leaf_bytes: Hash = *commitment.as_bytes();
        let index = tree.insert(leaf_bytes).expect("enroll");
        stored.push((commitment, index));
        public_leaves.push(leaf_bytes);
    }

    assert_eq!(tree.len(), N);
    let members_root = tree.root();

    // Each member can later re-derive their proof from (commitment, index)
    // and the published leaf set.
    let rebuilt_tree = {
        let mut t = MerkleTree::<Sha256Hasher>::new();
        for l in &public_leaves {
            t.insert(*l).unwrap();
        }
        t
    };
    for (commitment, index) in &stored {
        let proof = rebuilt_tree.proof(*index).expect("proof");
        assert!(
            verify_proof::<Sha256Hasher>(&members_root, commitment.as_bytes(), &proof),
            "rebuilt-tree proof for index {index} must verify against the original root"
        );
    }

    // Any third party with only the public leaf set rebuilds the same root.
    let third_party_root = root_from_public_leaves(&public_leaves);
    assert_eq!(third_party_root, members_root);

    // Sanity: capacity is what the public API advertises.
    assert_eq!(tree.capacity(), MAX_LEAVES);
    assert_eq!(MAX_LEAVES, 1 << MERKLE_DEPTH);
}

// ---------------------------------------------------------------------------
// 2. Full approval cycle (client-side)
// ---------------------------------------------------------------------------

#[test]
fn sdk_flow_full_approval_cycle() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);

    // Enroll 8 members.
    const N: usize = 8;
    let identities: Vec<Identity> = (0..N).map(|_| random_identity(&mut rng)).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let mut leaves: Vec<Hash> = Vec::with_capacity(N);
    for id in &identities {
        let leaf = *id.commitment::<Sha256Hasher>().as_bytes();
        tree.insert(leaf).unwrap();
        leaves.push(leaf);
    }
    let members_root = tree.root();

    // Fixed test vectors for proposal binding (the SDK will pass these in
    // for real; here we just need stable bytes).
    let chain_id: &[u8] = b"lez-devnet-1";
    let state_pda_bytes: [u8; 32] = [0x55; 32];
    let proposal_index: u64 = 7;
    let action_bytes: &[u8] = b"transfer(USDC, 1000, recipient_pubkey)";
    let target_program: &[u8] = b"PRIVATE_MULTISIG_PROGRAM_ID_BYTES";

    let proposal_id = derive_proposal_id(
        chain_id,
        &state_pda_bytes,
        proposal_index,
        action_bytes,
        target_program,
    );

    // The voting member.
    let voter_idx = 3usize;
    let voter = &identities[voter_idx];
    let voter_commitment = voter.commitment::<Sha256Hasher>();

    // Derive nullifier — note `nullifier` takes `&[u8; SK_LEN]` and `&Hash`,
    // which is the right shape (no clone needed on hot paths).
    let nullifier_value = crypto::nullifier::<Sha256Hasher>(&voter.sk, &proposal_id);

    // Pack the 96-byte public-input bundle.
    let bundle = pack_public_inputs(&members_root, &proposal_id, &nullifier_value);
    assert_eq!(bundle.len(), 96);
    assert_eq!(&bundle[..32], &members_root[..]);
    assert_eq!(&bundle[32..64], &proposal_id[..]);
    assert_eq!(&bundle[64..96], &nullifier_value[..]);

    // Local pre-submission Merkle check — what the SDK should do before
    // shelling out to the Risc0 guest.
    let proof = tree.proof(voter_idx).expect("proof");
    assert!(verify_proof::<Sha256Hasher>(
        &members_root,
        voter_commitment.as_bytes(),
        &proof,
    ));

    // Determinism: running the same flow twice produces byte-identical
    // nullifier and bundle.
    let nullifier_value_2 = crypto::nullifier::<Sha256Hasher>(&voter.sk, &proposal_id);
    let bundle_2 = pack_public_inputs(&members_root, &proposal_id, &nullifier_value_2);
    assert_eq!(nullifier_value, nullifier_value_2);
    assert_eq!(bundle, bundle_2);
}

// ---------------------------------------------------------------------------
// 3. Double-vote detection across proposals
// ---------------------------------------------------------------------------

#[test]
fn sdk_flow_double_vote_detection() {
    let mut rng = StdRng::seed_from_u64(0xD06E);

    let voter = random_identity(&mut rng);
    // Two distinct proposals.
    let proposal_a = derive_proposal_id(b"lez-1", &[0x11; 32], 1, b"action-A", b"target-program-A");
    let proposal_b = derive_proposal_id(b"lez-1", &[0x11; 32], 2, b"action-B", b"target-program-B");
    assert_ne!(
        proposal_a, proposal_b,
        "test vectors must yield distinct proposal_ids"
    );

    // Same member, same proposal, twice → identical nullifier
    // (NullifierEntry PDA `init` will fail on the second attempt).
    let n_a1 = crypto::nullifier::<Sha256Hasher>(&voter.sk, &proposal_a);
    let n_a2 = crypto::nullifier::<Sha256Hasher>(&voter.sk, &proposal_a);
    assert_eq!(n_a1, n_a2, "double-vote on same proposal must collide");

    // Same member, different proposal → different nullifier
    // (the same member must be free to approve independent proposals).
    let n_b = crypto::nullifier::<Sha256Hasher>(&voter.sk, &proposal_b);
    assert_ne!(
        n_a1, n_b,
        "independent proposals must yield independent nullifiers"
    );
}

// ---------------------------------------------------------------------------
// 4. Outsider cannot forge a proof against members_root
// ---------------------------------------------------------------------------

#[test]
fn sdk_flow_non_member_cannot_construct_valid_proof() {
    let mut rng = StdRng::seed_from_u64(0xF00D);

    // Real members.
    const N: usize = 8;
    let members: Vec<Identity> = (0..N).map(|_| random_identity(&mut rng)).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for m in &members {
        tree.insert(*m.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    let members_root = tree.root();

    // Outsider with their own sk / salt.
    let outsider = random_identity(&mut rng);
    let outsider_leaf: Hash = *outsider.commitment::<Sha256Hasher>().as_bytes();

    // Attempt A: all-zero siblings and indices (this is the FINDING-1
    // forgery shape — must be rejected by domain separation).
    let zero_proof = MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    assert!(!verify_proof::<Sha256Hasher>(
        &members_root,
        &outsider_leaf,
        &zero_proof
    ));

    // Attempt B: steal a real member's proof shape, swap in the outsider's
    // commitment as the leaf.
    let real_proof = tree.proof(0).unwrap();
    assert!(!verify_proof::<Sha256Hasher>(
        &members_root,
        &outsider_leaf,
        &real_proof
    ));

    // Attempt C: random siblings, random direction bits.
    for _ in 0..16 {
        let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
        let mut indices = [false; MERKLE_DEPTH];
        for s in siblings.iter_mut() {
            rng.fill_bytes(s);
        }
        for b in indices.iter_mut() {
            *b = rng.random();
        }
        let random_proof = MerkleProof { siblings, indices };
        assert!(!verify_proof::<Sha256Hasher>(
            &members_root,
            &outsider_leaf,
            &random_proof
        ));
    }

    // Attempt D: empty-leaf forgery — outsider tries leaf = [0;32]
    // with all-zero proof to hit an unused slot. This is exactly the
    // FINDING-1 case from red_team.rs.
    let attacker_leaf = [0u8; HASH_LEN];
    let attacker_proof = MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    assert!(!verify_proof::<Sha256Hasher>(
        &members_root,
        &attacker_leaf,
        &attacker_proof
    ));
}

// ---------------------------------------------------------------------------
// 5. Basic serialization compatibility
// ---------------------------------------------------------------------------

#[test]
fn sdk_flow_basic_serialization_compat() {
    // `Hash` is `[u8; 32]`.
    let _h: Hash = [0u8; HASH_LEN];
    assert_eq!(HASH_LEN, 32);
    assert_eq!(core::mem::size_of::<Hash>(), 32);

    // Construct a small tree and a proof so we can poke at the field shape.
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let id = Identity::new([0xAB; SK_LEN], [0xCD; SALT_LEN]);
    let commitment = id.commitment::<Sha256Hasher>();
    tree.insert(*commitment.as_bytes()).unwrap();
    let proof = tree.proof(0).unwrap();

    // `MerkleProof.siblings: [Hash; 20]` and `.indices: [bool; 20]`.
    let siblings: [Hash; MERKLE_DEPTH] = proof.siblings;
    let indices: [bool; MERKLE_DEPTH] = proof.indices;
    assert_eq!(siblings.len(), MERKLE_DEPTH);
    assert_eq!(indices.len(), MERKLE_DEPTH);
    // The fields are reachable as public (no private wrappers).
    let _: Hash = siblings[0];
    let _: bool = indices[0];

    // `IdentityCommitment.as_bytes()` returns `&[u8; 32]`.
    let as_bytes_ref: &[u8; HASH_LEN] = commitment.as_bytes();
    assert_eq!(as_bytes_ref.len(), 32);

    // `IdentityCommitment.0` is also reachable (tuple-struct access).
    let inner: Hash = commitment.0;
    assert_eq!(&inner, as_bytes_ref);

    // Domain constants are exactly the bytes the verifier on-chain will use.
    assert_eq!(DOMAIN_LEAF, 0x00);
    assert_eq!(DOMAIN_NODE, 0x01);

    // `MerkleProof` derives PartialEq/Eq/Clone/Debug — exercise them so a
    // future regression that drops a derive shows up here.
    let cloned = proof.clone();
    assert_eq!(proof, cloned);
    let _ = format!("{:?}", proof);

    // FINDING (Annoyance): `MerkleProof` does NOT derive `Hash` or
    // `Default`. Consumers building HashMaps keyed by proofs (e.g. for
    // dedup in test harnesses) or constructing a "blank" proof for fuzz
    // setup have to roll their own. `Default` is straightforward
    // (`[[0;32]; 20]` / `[false; 20]`); `Hash` may be deferred because the
    // proof type is large.
    //
    // FINDING (Nit): `Identity` does NOT derive `Default`, which would let
    // the SDK do `Identity { sk, ..Default::default() }`. Not load-bearing
    // since secrets shouldn't have a default anyway. Arguably correct as-is.
    //
    // FINDING (Annoyance): `MerkleTree<H>` does NOT derive or implement
    // `Debug` or `PartialEq`. Asserting tree equality in tests has to go
    // through `tree.root()` and `tree.len()` manually. A `#[derive(Debug)]`
    // on the struct (the `PhantomData<H>` will be `Debug` as long as `H` is
    // `Sized`, which it is) would be cheap.

    // `IdentityCommitment` does derive Eq + Hash — confirm it works in a
    // HashSet, which is how an on-chain indexer might dedup members.
    use std::collections::HashSet;
    let mut set: HashSet<IdentityCommitment> = HashSet::new();
    set.insert(commitment);
    assert!(set.contains(&commitment));
}

// ---------------------------------------------------------------------------
// 6. No panics on realistic-but-odd inputs
// ---------------------------------------------------------------------------

#[test]
fn sdk_flow_no_panics_on_realistic_inputs() {
    // Empty action_bytes — perfectly valid for a no-op proposal.
    let pid_empty = derive_proposal_id(b"chain", &[0; 32], 0, b"", b"");
    let sk = [0xAA; SK_LEN];
    let _ = crypto::nullifier::<Sha256Hasher>(&sk, &pid_empty);

    // Max-length-ish proposal-id-preimage components: throw 4 KiB at each
    // hashable input. SHA-256 swallows arbitrary lengths.
    let big = vec![0x5Au8; 4096];
    let pid_big = derive_proposal_id(&big, &[0xFF; 32], u64::MAX, &big, &big);
    let _ = crypto::nullifier::<Sha256Hasher>(&sk, &pid_big);

    // Single-member tree: proof for index 0 must verify.
    {
        let mut tree = MerkleTree::<Sha256Hasher>::new();
        let id = Identity::new([1; SK_LEN], [2; SALT_LEN]);
        let leaf = *id.commitment::<Sha256Hasher>().as_bytes();
        tree.insert(leaf).unwrap();
        let proof = tree.proof(0).unwrap();
        assert!(verify_proof::<Sha256Hasher>(&tree.root(), &leaf, &proof));
        // Out-of-range proof errors instead of panicking.
        assert!(tree.proof(1).is_err());
        // Leaf accessor returns Option, not panic.
        assert!(tree.leaf(99).is_none());
    }

    // 64-member tree: all proofs verify against the same root.
    {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let mut tree = MerkleTree::<Sha256Hasher>::new();
        let mut leaves: Vec<Hash> = Vec::with_capacity(64);
        for _ in 0..64 {
            let id = random_identity(&mut rng);
            let leaf = *id.commitment::<Sha256Hasher>().as_bytes();
            tree.insert(leaf).unwrap();
            leaves.push(leaf);
        }
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(
                verify_proof::<Sha256Hasher>(&root, leaf, &proof),
                "leaf {i} should verify in 64-member tree"
            );
        }
    }

    // Empty-tree root is well-defined and not all-zeros (anti-FINDING-1).
    let empty = MerkleTree::<Sha256Hasher>::new();
    assert_ne!(empty.root(), [0u8; HASH_LEN]);

    // Empty leaf set rebuilds to the same empty-tree root.
    assert_eq!(root_from_public_leaves(&[]), empty.root());
}

// ---------------------------------------------------------------------------
// 7. Zeroize-attempt / minimal-secret-lifetime ergonomics
// ---------------------------------------------------------------------------

/// Take `Identity` by value, derive the commitment, and drop the secret
/// material as early as possible. The point is to verify the API doesn't
/// force the caller to keep `sk` around longer than needed.
fn commit_and_drop(identity: Identity) -> IdentityCommitment {
    // `identity` drops here at end of scope — its `sk` and `salt` arrays
    // are owned by this function and go out of scope on return.
    //
    // FINDING (Annoyance, security-flavored): `Identity` does NOT implement
    // `Drop` to zero out `sk` / `salt`. The crate doc explicitly punts this
    // to the SDK (identity.rs lines 7-10): the SDK is expected to wrap `sk`
    // in `secrecy::Secret`. That's a reasonable scope decision for a
    // no_std-friendly core, but downstream consumers need to know upfront
    // that letting an `Identity` drop on the heap leaves cleartext sk bytes
    // in memory. Suggested fix: add a `zeroize` feature gate that adds a
    // `Drop` impl; document the default behavior more prominently.
    identity.commitment::<Sha256Hasher>()
}

#[test]
fn sdk_flow_zeroize_attempt() {
    let id = Identity::new([0x42; SK_LEN], [0x24; SALT_LEN]);
    // `commitment` takes `&self`, so we don't have to move `id` if we want
    // to keep it; conversely, moving it into `commit_and_drop` works fine
    // because `Identity: Clone` and the function takes ownership.
    let commitment = commit_and_drop(id);

    // FINDING (Nit): `Identity::commitment` takes `&self`, which is the
    // right borrow shape (no clone forced). A consumer who wants the
    // "consume self and yield commitment" path can do
    // `let c = id.commitment::<H>(); drop(id);` — which is exactly the
    // helper above. There is no API issue here, just a documentation
    // opportunity to call out the "drop the identity early" pattern.
    //
    // FINDING (Nit): `nullifier::<H>(&self.sk, &proposal_id)` requires
    // exposing `sk` to the call site. There's no
    // `Identity::nullifier<H>(&self, proposal_id: &Hash) -> Hash` helper
    // that would keep `sk` private at the call site. Adding that helper
    // would let the SDK keep `sk` strictly inside the `Identity` and
    // never expose `&self.sk` directly. Suggested fix: add the helper.

    // Sanity: the commitment came out non-trivially (i.e. the secret was
    // actually consumed before being dropped).
    assert_ne!(commitment.as_bytes(), &[0u8; HASH_LEN]);

    // Confirm we don't need a long-lived `sk` for the nullifier path
    // either: we can build a one-shot helper that signs and discards.
    fn approve_once(sk: [u8; SK_LEN], proposal_id: &Hash) -> Hash {
        // `sk` drops here.
        crypto::nullifier::<Sha256Hasher>(&sk, proposal_id)
    }
    let pid = Sha256Hasher::hash(b"some-proposal");
    let n = approve_once([0x42; SK_LEN], &pid);
    assert_ne!(n, [0u8; HASH_LEN]);
}
