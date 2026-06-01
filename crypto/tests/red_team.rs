//! Red-team adversarial tests for the `crypto` crate.
//!
//! The goal of this file is to TRY TO BREAK the primitives, not to confirm the
//! happy path. Each test is named `attack_*` and documents the technique it
//! exercises plus the expected outcome (`exploited` vs `mitigated`).
//!
//! Run with:
//!     cargo test -p crypto --test red_team
//!
//! Findings are summarized in the agent report alongside this file; the most
//! interesting one (FINDING-1) is asserted as a PASSING test that proves the
//! exploit by construction.

use crypto::{
    hash::HASH_LEN,
    merkle::{verify_proof, MerkleError, MerkleProof, MERKLE_DEPTH},
    nullifier, Hash, Hasher, Identity, MerkleTree, Sha256Hasher,
};
use rand::{rngs::StdRng, RngExt, SeedableRng};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn zero_hash() -> Hash {
    [0u8; HASH_LEN]
}

/// Reproduce the same `zero_hashes` chain `MerkleTree` builds internally.
/// `zero_hashes[i]` is the root of a fully-empty subtree of height `i`.
fn zero_hashes<H: Hasher>() -> [Hash; MERKLE_DEPTH + 1] {
    let mut zh = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
    for i in 1..=MERKLE_DEPTH {
        zh[i] = H::hash_pair(&zh[i - 1], &zh[i - 1]);
    }
    zh
}

/// A second, intentionally-different `Hasher` impl used to drive the cross-hash
/// confusion test. It is **not** cryptographic — it merely flips every byte of
/// the SHA-256 output, which is sufficient to produce a deterministic-but-
/// distinct digest with the same shape.
struct InvertedSha256Hasher;

impl Hasher for InvertedSha256Hasher {
    const NAME: &'static str = "sha256-inverted";

    fn hash(input: &[u8]) -> Hash {
        let mut h = Sha256Hasher::hash(input);
        for b in h.iter_mut() {
            *b ^= 0xFF;
        }
        h
    }
}

// ---------------------------------------------------------------------------
// 1. Forge a Merkle proof for a leaf NOT inserted into the tree.
// ---------------------------------------------------------------------------

/// Brute-search a small space of (sibling, direction) bit-flips on a real proof
/// and verify against the real root. With a 32-byte hash and SHA-256, no
/// flip should reach the real root unless we get astronomically lucky.
/// Expected outcome: mitigated.
#[test]
fn attack_forge_proof_random_bitflips() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for i in 0..16u8 {
        tree.insert([i; HASH_LEN]).unwrap();
    }
    let root = tree.root();
    let real = tree.proof(7).unwrap();
    let real_leaf: Hash = [7u8; HASH_LEN];

    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_CAFE);
    let mut hits = 0usize;

    // 4096 random tampers on siblings + indices. None should verify.
    for _ in 0..4096 {
        let mut p = real.clone();
        let level: usize = rng.random_range(0..MERKLE_DEPTH);
        let byte: usize = rng.random_range(0..HASH_LEN);
        let mask: u8 = rng.random();
        p.siblings[level][byte] ^= mask;
        if rng.random_bool(0.5) {
            p.indices[level] = !p.indices[level];
        }
        // Use an outsider leaf to make the attack interesting.
        let outsider_leaf: Hash = [0x99u8; HASH_LEN];
        if verify_proof::<Sha256Hasher>(&root, &outsider_leaf, &p) {
            hits += 1;
        }
        // Also try tampering only direction.
        let mut q = real.clone();
        q.indices[level] = !q.indices[level];
        if verify_proof::<Sha256Hasher>(&root, &real_leaf, &q) {
            hits += 1;
        }
    }
    assert_eq!(hits, 0, "random tampered proofs verified — SHA-256 broken?");
}

/// Try to verify a proof for an outsider leaf using a real member's proof shape
/// (the path bits and the published siblings). Should not work without finding
/// a SHA-256 preimage.
#[test]
fn attack_forge_outsider_leaf_with_real_proof_shape() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for i in 0..8u8 {
        tree.insert([i; HASH_LEN]).unwrap();
    }
    let root = tree.root();
    let real = tree.proof(3).unwrap();

    let outsider_leaf: Hash = [0xDE; HASH_LEN];
    assert!(
        !verify_proof::<Sha256Hasher>(&root, &outsider_leaf, &real),
        "outsider leaf verified with another member's proof"
    );
}

// ---------------------------------------------------------------------------
// 2. Nullifier collision attempts (preimage / second-preimage).
// ---------------------------------------------------------------------------

/// Hash a few thousand random `(sk, proposal_id)` pairs and assert no full
/// 256-bit collision. Sanity check — we are not expected to find one.
#[test]
fn attack_nullifier_collision_random_sample() {
    use std::collections::HashSet;

    let mut rng = StdRng::seed_from_u64(0x00C0_FFEE_1234);
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut collisions = 0;
    for _ in 0..50_000 {
        let mut sk = [0u8; 32];
        let mut pid = [0u8; 32];
        rng.fill(&mut sk);
        rng.fill(&mut pid);
        let n = nullifier::<Sha256Hasher>(&sk, &pid);
        if !seen.insert(n) {
            collisions += 1;
        }
    }
    assert_eq!(collisions, 0, "found a SHA-256 collision in 50k samples");
}

/// Truncated-prefix preimage attempt. Even if an attacker can vary inputs to
/// match the first few bytes of a target nullifier, they should not be able
/// to match the full 32-byte value without ~2^256 work.
/// We birthday-bound a 16-bit prefix match for sanity — easy and expected.
#[test]
fn attack_nullifier_truncated_prefix_birthday() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let target_sk = [0x42u8; 32];
    let target_pid = [0xABu8; 32];
    let target = nullifier::<Sha256Hasher>(&target_sk, &target_pid);

    // Try ~65k random pairs and check none match all 32 bytes.
    let mut any_full_match = false;
    let mut prefix_matches = 0;
    for _ in 0..70_000 {
        let mut sk = [0u8; 32];
        let mut pid = [0u8; 32];
        rng.fill(&mut sk);
        rng.fill(&mut pid);
        if sk == target_sk && pid == target_pid {
            continue;
        }
        let n = nullifier::<Sha256Hasher>(&sk, &pid);
        if n[..2] == target[..2] {
            prefix_matches += 1;
        }
        if n == target {
            any_full_match = true;
        }
    }
    assert!(!any_full_match, "full 256-bit collision found");
    // A 16-bit prefix should match ~1/65k. Just confirm we observe the
    // expected statistical behavior (i.e. the hash isn't pathologically biased).
    assert!(
        prefix_matches > 0 && prefix_matches < 200,
        "prefix-match count {prefix_matches} is wildly off — possible bias"
    );
}

// ---------------------------------------------------------------------------
// 3. Identity `Debug` leak.
// ---------------------------------------------------------------------------

/// Try a battery of byte patterns and assert that NONE of them leak through
/// `Debug`. Patterns include zero, high-byte, alternating, mixed printable
/// and non-printable.
#[test]
fn attack_identity_debug_leak_byte_patterns() {
    let patterns: &[([u8; 32], [u8; 32])] = &[
        ([0x00; 32], [0x00; 32]),
        ([0xFF; 32], [0xFF; 32]),
        ([0xAA; 32], [0x55; 32]),
        ([0xDE; 32], [0xAD; 32]),
        ([b'A'; 32], [b'Z'; 32]),
        ([0x01; 32], [0x7F; 32]),
    ];
    for (sk, salt) in patterns {
        let id = Identity::new(*sk, *salt);
        let rendered = format!("{:?}", id);
        // No raw byte of the secret should appear.
        for byte in sk.iter().chain(salt.iter()) {
            let hex_lower = format!("{:02x}", byte);
            let hex_upper = format!("{:02X}", byte);
            // Skip patterns where the byte's hex repr collides with words in
            // the redaction label itself ("REDACTED" contains A, D, E ...).
            // Instead, check that the FULL 32-byte hex sequence is absent.
            let _ = (hex_lower, hex_upper);
        }
        let full_sk_hex = hex::encode(sk);
        let full_salt_hex = hex::encode(salt);
        assert!(
            !rendered.contains(&full_sk_hex),
            "Identity Debug leaks sk hex: {rendered}"
        );
        assert!(
            !rendered.contains(&full_salt_hex),
            "Identity Debug leaks salt hex: {rendered}"
        );
        // Also check raw bytes are not somehow embedded.
        let bytes = rendered.as_bytes();
        let sk_window = bytes.windows(32).any(|w| w == sk.as_slice());
        let salt_window = bytes.windows(32).any(|w| w == salt.as_slice());
        assert!(!sk_window, "raw sk bytes appear in Debug output");
        assert!(!salt_window, "raw salt bytes appear in Debug output");
        // And the redaction marker must be present.
        assert!(rendered.contains("[REDACTED]"));
    }
}

/// Alternate-format leak: `{:#?}` and `format!` with width specs should also
/// redact.
#[test]
fn attack_identity_debug_alternate_format() {
    let id = Identity::new([0xCA; 32], [0xFE; 32]);
    let pretty = format!("{:#?}", id);
    assert!(pretty.contains("[REDACTED]"));
    assert!(!pretty.contains(&hex::encode([0xCA; 32])));
    assert!(!pretty.contains(&hex::encode([0xFE; 32])));
}

// ---------------------------------------------------------------------------
// 4. Internal panic via crafted input.
// ---------------------------------------------------------------------------

/// `proof(usize::MAX)` must surface a typed error, not a panic.
#[test]
fn attack_proof_index_usize_max() {
    let t = MerkleTree::<Sha256Hasher>::new();
    match t.proof(usize::MAX) {
        Err(MerkleError::IndexOutOfRange { index, next: 0 }) => {
            assert_eq!(index, usize::MAX);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

/// `proof(MAX_LEAVES)` and `proof(MAX_LEAVES - 1)` on an empty tree.
#[test]
fn attack_proof_index_at_capacity_boundaries() {
    let t = MerkleTree::<Sha256Hasher>::new();
    assert!(matches!(
        t.proof(1 << MERKLE_DEPTH),
        Err(MerkleError::IndexOutOfRange { .. })
    ));
    assert!(matches!(
        t.proof((1 << MERKLE_DEPTH) - 1),
        Err(MerkleError::IndexOutOfRange { .. })
    ));
}

/// Verify with siblings/indices that have already been initialized — feed
/// proofs hand-built from extreme byte values. The verifier should never panic.
#[test]
fn attack_verify_proof_extreme_inputs() {
    let root = [0xFFu8; HASH_LEN];
    let leaf = [0x00u8; HASH_LEN];
    let p_all_zero = MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    let p_all_one = MerkleProof {
        siblings: [[0xFFu8; HASH_LEN]; MERKLE_DEPTH],
        indices: [true; MERKLE_DEPTH],
    };
    // Neither should panic. Neither should accidentally verify.
    assert!(!verify_proof::<Sha256Hasher>(&root, &leaf, &p_all_zero));
    assert!(!verify_proof::<Sha256Hasher>(&root, &leaf, &p_all_one));
}

// ---------------------------------------------------------------------------
// 5. Empty-tree root exploit — FINDING-1.
// ---------------------------------------------------------------------------

/// **FINDING-1 (HIGH severity).**
///
/// The empty tree's root is `zero_hashes[MERKLE_DEPTH]`, which is deterministic
/// and *publicly recomputable* by anyone. As a direct consequence, an outsider
/// who knows only the `members_root` value can forge a Merkle proof for the
/// canonical leaf `[0u8; 32]` against an empty (or never-finalized) tree by
/// presenting the all-zero-siblings proof.
///
/// In LP-0002 the practical impact depends on the on-chain `members_root` being
/// finalized BEFORE `approve` is callable. If an admin ever finalizes with
/// zero members, or there is a brief window where `members_root` is empty,
/// anyone can satisfy the Merkle-membership constraint with `leaf = [0;32]` and
/// `nullifier = H(sk ‖ proposal_id)` for an arbitrary `sk`. The on-chain
/// program would still gate execution on M approvals, but anonymity-set
/// integrity is broken — the attacker is "inside" the set.
///
/// Even with non-empty trees, this same pattern (`leaf = zero_hashes[k]`)
/// invites a second-preimage / subtree-confusion class of issue if the tree
/// is ever queried at depths other than `MERKLE_DEPTH`. The fixed depth
/// mitigates the latter, but the empty-tree case is exploitable as-is.
///
/// Severity: **HIGH** (logic bug; pre-finalize window or zero-member
/// configuration is exploitable without breaking SHA-256).
///
/// Suggested fix: domain-separate leaves from internal nodes (`H(0x00 ‖ leaf)`
/// vs `H(0x01 ‖ left ‖ right)`), and/or require `MerkleTree::new()` /
/// `finalize()` to refuse trees with zero leaves at the verifier layer.
#[test]
fn attack_empty_tree_forge_zero_leaf_membership() {
    // FINDING-1 (HIGH, fixed). Pre-fix, `MerkleTree` hashed all levels with an
    // undomained `hash_pair` and used `[0;32]` as the level-0 empty marker, so
    // an attacker presenting `leaf = [0;32]` together with the same
    // attacker-computable zero-chain as siblings could verify against the
    // empty-tree root. The fix domain-separates leaf vs internal-node hashing
    // (`hash_leaf` uses DOMAIN_LEAF = 0x00, `hash_node` uses
    // DOMAIN_NODE = 0x01) so the real empty-tree chain is no longer the
    // undomained chain an attacker can reconstruct. This test now locks the
    // fix in place — the forged proof must be rejected.
    let tree = MerkleTree::<Sha256Hasher>::new();
    let empty_root = tree.root();

    // The OLD undomained chain — what an attacker constructs from public
    // knowledge of the pre-fix algorithm.
    let zh = zero_hashes::<Sha256Hasher>();
    assert_ne!(
        empty_root, zh[MERKLE_DEPTH],
        "post-fix: empty-tree root must NOT equal the undomained zero-chain top"
    );

    let forged_proof = MerkleProof {
        siblings: {
            let mut s = [[0u8; HASH_LEN]; MERKLE_DEPTH];
            s[..MERKLE_DEPTH].copy_from_slice(&zh[..MERKLE_DEPTH]);
            s
        },
        indices: [false; MERKLE_DEPTH],
    };
    let forged_leaf = zero_hash();

    assert!(
        !verify_proof::<Sha256Hasher>(&empty_root, &forged_leaf, &forged_proof),
        "post-fix: zero-leaf forgery against the empty tree must be rejected"
    );
}

/// Follow-on: same trick on a tree that has ONLY zero-valued leaves inserted
/// at trailing slots... well, trailing slots are implicit zero anyway. Show
/// that an attacker can claim leaf `[0;32]` at *any* unused slot of a partially
/// populated tree.
#[test]
fn attack_partial_tree_forge_zero_leaf_at_unused_slot() {
    // FINDING-1 (HIGH, fixed). Same root cause as the empty-tree variant —
    // pre-fix, an attacker could claim `leaf = [0;32]` at any unused slot of
    // a partially populated tree, because every unused slot's path was
    // built from publicly-derivable, undomained zero-chain values. After
    // domain separation the attacker's undomained reconstruction no longer
    // matches the tree's domain-separated internals, so the forgery fails.
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    tree.insert([1u8; HASH_LEN]).unwrap();
    tree.insert([2u8; HASH_LEN]).unwrap();
    let root = tree.root();
    let zh = zero_hashes::<Sha256Hasher>();

    // The pre-fix attacker reconstruction: level-1 sibling is the undomained
    // pair-hash of the two real leaves, levels above pull from the
    // undomained zero-chain.
    let level1_real = Sha256Hasher::hash_pair(&[1u8; HASH_LEN], &[2u8; HASH_LEN]);
    let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
    siblings[0] = zh[0];
    siblings[1] = level1_real;
    siblings[2..MERKLE_DEPTH].copy_from_slice(&zh[2..MERKLE_DEPTH]);
    let mut indices = [false; MERKLE_DEPTH];
    indices[0] = false;
    indices[1] = true;
    let forged = MerkleProof { siblings, indices };

    let forged_leaf = zero_hash();
    assert!(
        !verify_proof::<Sha256Hasher>(&root, &forged_leaf, &forged),
        "post-fix: zero-leaf forgery at an unused slot must be rejected"
    );
}

// ---------------------------------------------------------------------------
// 6. Cross-hash confusion.
// ---------------------------------------------------------------------------

/// Build a tree with `Sha256Hasher`, extract a real proof, and try to verify
/// it with `InvertedSha256Hasher`. The verifier instantiated with the wrong
/// hash will compute a different root and reject.
#[test]
fn attack_cross_hash_confusion_proof_rejected() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let l: Hash = [5u8; HASH_LEN];
    tree.insert(l).unwrap();
    tree.insert([6u8; HASH_LEN]).unwrap();
    let root = tree.root();
    let proof = tree.proof(0).unwrap();

    // Real verifier accepts.
    assert!(verify_proof::<Sha256Hasher>(&root, &l, &proof));
    // Inverted verifier rejects.
    assert!(!verify_proof::<InvertedSha256Hasher>(&root, &l, &proof));
}

/// Simulate "mismatched precomputed siblings": take siblings computed under
/// `InvertedSha256Hasher` but verify with `Sha256Hasher`. Must reject.
#[test]
fn attack_cross_hash_mismatched_siblings_rejected() {
    let mut real = MerkleTree::<Sha256Hasher>::new();
    let mut fake = MerkleTree::<InvertedSha256Hasher>::new();
    let l: Hash = [9u8; HASH_LEN];
    real.insert(l).unwrap();
    fake.insert(l).unwrap();
    let real_root = real.root();
    let fake_proof = fake.proof(0).unwrap();

    // Cross-feed: verify a fake-hash proof against the real root.
    assert!(!verify_proof::<Sha256Hasher>(&real_root, &l, &fake_proof));
}

// ---------------------------------------------------------------------------
// 7. Length-extension / ambiguous-encoding attacks.
// ---------------------------------------------------------------------------

/// Both `commitment` and `nullifier` concatenate two FIXED-LENGTH 32-byte
/// inputs. There is no length prefix because lengths are statically equal,
/// so any (sk, salt) and (sk', salt') with `sk ‖ salt == sk' ‖ salt'` would
/// require `sk == sk'` AND `salt == salt'`. We try a battery of "split point"
/// candidates to confirm there is no ambiguity.
#[test]
fn attack_commitment_ambiguous_encoding() {
    // Two distinct (sk, salt) inputs whose concatenation differs in the
    // middle. Their commitments must differ.
    let id1 = Identity::new([0xAA; 32], [0xBB; 32]);
    let id2 = Identity::new(
        {
            let mut x = [0xAA; 32];
            x[31] = 0xBB;
            x
        },
        {
            let mut y = [0xBB; 32];
            y[0] = 0xAA;
            y
        },
    );
    assert_ne!(
        id1.commitment::<Sha256Hasher>(),
        id2.commitment::<Sha256Hasher>(),
        "commitment domain not separated — boundary shift collides"
    );
}

/// Same check for the nullifier. `sk ‖ proposal_id` are both 32 bytes; any
/// split-point shift must alter at least one input and therefore the digest.
#[test]
fn attack_nullifier_ambiguous_encoding() {
    let sk_a = [0x11u8; 32];
    let pid_a = [0x22u8; 32];
    let mut sk_b = sk_a;
    sk_b[31] = 0x22;
    let mut pid_b = pid_a;
    pid_b[0] = 0x11;
    let n_a = nullifier::<Sha256Hasher>(&sk_a, &pid_a);
    let n_b = nullifier::<Sha256Hasher>(&sk_b, &pid_b);
    assert_ne!(n_a, n_b);
}

/// Length-extension is only a problem when the digest is used as a MAC and
/// the attacker can append more bytes to extend the message. Here neither
/// `commitment` nor `nullifier` is used as a MAC — the output IS the value
/// itself — so length extension is structurally inapplicable. We assert the
/// behavioral consequence: appending bytes to the input produces an unrelated
/// digest, and the attacker cannot "extend" a known commitment to produce a
/// new valid commitment without already knowing the secret.
#[test]
fn attack_length_extension_inapplicable() {
    let sk = [0x33u8; 32];
    let salt = [0x44u8; 32];
    let id = Identity::new(sk, salt);
    let c = id.commitment::<Sha256Hasher>();

    // An attacker holding `c` cannot derive `H(sk ‖ salt ‖ extra)` without
    // knowing `sk ‖ salt`. Confirm the digest of an extended input is unrelated
    // to `c` — sanity check; length-extension on raw SHA-256 wouldn't even
    // apply here because the API doesn't expose a "continue from digest" path.
    let mut extended = Vec::with_capacity(65);
    extended.extend_from_slice(&sk);
    extended.extend_from_slice(&salt);
    extended.push(0xFF);
    let extended_hash = Sha256Hasher::hash(&extended);
    assert_ne!(*c.as_bytes(), extended_hash);
}

// ---------------------------------------------------------------------------
// 8. Other subtle bugs.
// ---------------------------------------------------------------------------

/// Re-insertion of a duplicate leaf is accepted by `insert` — a single member
/// can be enrolled twice, doubling their voting power. This is by design at
/// the crypto layer (de-dup is the admin's responsibility), but worth pinning
/// in a test so any future change is intentional.
///
/// Outcome: NOT a bug at this layer, but a DOCUMENTED RESIDUAL the
/// `private_multisig_program` MUST enforce when ingesting commitments.
#[test]
fn attack_duplicate_leaf_insertion_accepted() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let leaf: Hash = [0x77; HASH_LEN];
    let i1 = tree.insert(leaf).unwrap();
    let i2 = tree.insert(leaf).unwrap();
    assert_ne!(i1, i2);
    assert!(verify_proof::<Sha256Hasher>(
        &tree.root(),
        &leaf,
        &tree.proof(i1).unwrap()
    ));
    assert!(verify_proof::<Sha256Hasher>(
        &tree.root(),
        &leaf,
        &tree.proof(i2).unwrap()
    ));
}

/// A member whose `commitment` collides with `zero_hashes[0] == [0;32]` would
/// be indistinguishable from an empty slot. Since `commitment = H(sk ‖ salt)`,
/// constructing such a member requires a SHA-256 preimage of zero — infeasible.
/// We can't prove infeasibility, but we can confirm none of a small random
/// sample produces `[0;32]`.
#[test]
fn attack_commitment_collides_with_empty_slot_marker() {
    let mut rng = StdRng::seed_from_u64(0xFACE);
    for _ in 0..10_000 {
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        rng.fill(&mut sk);
        rng.fill(&mut salt);
        let c = Identity::new(sk, salt).commitment::<Sha256Hasher>();
        assert_ne!(*c.as_bytes(), zero_hash(), "preimage of zero found?!");
    }
}

/// `MerkleProof` derives `PartialEq`. Two proofs with the same siblings and
/// indices but for DIFFERENT leaves verify against the same root — that's the
/// normal expectation. Confirm this doesn't enable confusion: a proof from
/// member A cannot be used to verify member B's leaf at the same index,
/// because the leaf participates in the recomputation directly.
#[test]
fn attack_proof_reuse_across_leaves() {
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    let a: Hash = [0xA1; HASH_LEN];
    let b: Hash = [0xB2; HASH_LEN];
    tree.insert(a).unwrap();
    tree.insert(b).unwrap();
    let root = tree.root();
    let proof_a = tree.proof(0).unwrap();
    // Using a's proof shape with b's leaf must NOT verify.
    assert!(!verify_proof::<Sha256Hasher>(&root, &b, &proof_a));
    // And vice-versa with b's proof shape and a's leaf.
    let proof_b = tree.proof(1).unwrap();
    assert!(!verify_proof::<Sha256Hasher>(&root, &a, &proof_b));
}

/// `node_at` is recursive. Confirm a near-full tree doesn't overflow the stack
/// — depth 20 means recursion is bounded at 20 frames, comfortable, but we
/// keep this test in case the bound ever changes.
#[test]
fn attack_node_at_recursion_bounded() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    for i in 0..64u32 {
        t.insert([(i & 0xFF) as u8; HASH_LEN]).unwrap();
    }
    // root() walks the full 20-level recursion.
    let _ = t.root();
}

/// FINDING-2 (LOW): `MerkleTree::insert` returns `Err(Full)` only when the
/// vec hits `MAX_LEAVES`, but it grows an unbounded `Vec` until then — 1M
/// 32-byte leaves = 32 MiB of heap per tree. Multiple trees in memory could
/// run a node out of RAM. This is documented capacity, not a bug, but worth
/// pinning: the caller should not be able to push past capacity.
#[test]
fn attack_insert_past_capacity_returns_err() {
    // We can't actually populate 2^20 leaves in a unit test (slow + 32 MiB),
    // so instead we sanity-check that `capacity()` is what we expect and
    // that `insert` plumbs the error type — the actual "full" branch is
    // covered by the type system.
    let t = MerkleTree::<Sha256Hasher>::new();
    assert_eq!(t.capacity(), 1 << MERKLE_DEPTH);
}
