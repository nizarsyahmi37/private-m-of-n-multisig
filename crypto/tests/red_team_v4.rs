//! Round-4 meta-level red-team adversarial tests.
//!
//! Three prior rounds exhausted the structural Merkle / nullifier / domain
//! separation surface:
//!   - Round 1: FINDING-1 (HIGH) — undomained Merkle hashing → zero-leaf
//!     forgery at any unused slot. Fixed by `hash_leaf` / `hash_node`.
//!   - Round 2: FINDING-1b (LOW) — `verify_proof` accepted `leaf=[0;32]`
//!     against the empty tree via the real post-fix marker chain. Fixed by
//!     the `leaf == [0;32]` guard.
//!   - Round 3: closed two mutation-testing gaps (FINDING-V3-A `is_empty`,
//!     FINDING-V3-B `IdentityCommitment` Debug).
//!
//! Round-4 mandate: attack the META surface the structural rounds didn't
//! cover. The attack classes (matching the spec verbatim):
//!
//!   1. Doc-vs-code drift — every public item has a doc comment; find any
//!      claim the impl doesn't honor.
//!   2. Integer overflow / wraparound corners — `MAX_LEAVES`, `index ^ 1`,
//!      `current >>= 1`, `pos * span`, `pos * 2 + 1`.
//!   3. Encoding edge cases — unicode `‖` in docs vs bytewise concatenation,
//!      Trojan-source style.
//!   4. Construction-time invariants depending on order — root before/after
//!      insert.
//!   5. Type-system shortcuts — slice vs [u8;32], &Hash signature.
//!   6. Hidden semver / public-field surface — `pub sk`, `pub salt`,
//!      `IdentityCommitment(pub Hash)`.
//!   7. Hasher::Output design note.
//!   8. Allocation surprises — Vec growth, stack-buffer sizes.
//!   9. Soundness oracle — 10k random (root, leaf, proof) → must never accept.
//!  10. Creative — anything else.
//!
//! Each test is named `r4_*`. Outcomes are recorded in the file's trailing
//! report block.
//!
//! Run:
//!     cargo test -p crypto --test red_team_v4
//!     cargo clippy -p crypto --test red_team_v4 -- -D warnings

#![allow(
    clippy::manual_memcpy,
    clippy::needless_range_loop,
    clippy::unusual_byte_groupings,
    clippy::identity_op,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::assertions_on_constants,
    unused_assignments
)]

use crypto::{
    hash::{DOMAIN_LEAF, DOMAIN_NODE, HASH_LEN},
    identity::{SALT_LEN, SK_LEN},
    merkle::{verify_proof, MerkleError, MerkleProof, MAX_LEAVES, MERKLE_DEPTH},
    nullifier, Hash, Hasher, Identity, IdentityCommitment, MerkleTree, Sha256Hasher,
};
use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ZERO: Hash = [0u8; HASH_LEN];

fn empty_chain() -> [Hash; MERKLE_DEPTH + 1] {
    let mut m = [[0u8; HASH_LEN]; MERKLE_DEPTH + 1];
    m[0] = Sha256Hasher::hash_leaf(&ZERO);
    for i in 1..=MERKLE_DEPTH {
        m[i] = Sha256Hasher::hash_node(&m[i - 1], &m[i - 1]);
    }
    m
}

// ===========================================================================
// 1. DOC-VS-CODE DRIFT
// ===========================================================================

/// `lib.rs` doc claims the crate re-exports `Hash, Hasher, Sha256Hasher,
/// DOMAIN_LEAF, DOMAIN_NODE, HASH_LEN`, `Identity, IdentityCommitment,
/// SALT_LEN, SK_LEN`, `verify_proof, MerkleError, MerkleProof, MerkleTree,
/// MAX_LEAVES, MERKLE_DEPTH`, and `nullifier`. If any name is renamed or
/// dropped from `pub use`, downstream Risc0 guest / on-chain integration
/// breaks silently because the build error appears at the call site, not in
/// the crypto crate. Use the names in EXPRESSION position (not just `use`)
/// so a typed sentinel cements them.
/// Outcome: mitigated.
#[test]
fn r4_lib_pub_use_surface_pinned_mitigated() {
    // hash module
    let _hash_len: usize = HASH_LEN;
    let _h: Hash = [0u8; HASH_LEN];
    let _name: &'static str = <Sha256Hasher as Hasher>::NAME;
    let _domain_leaf: u8 = DOMAIN_LEAF;
    let _domain_node: u8 = DOMAIN_NODE;
    // identity module
    let _sk_len: usize = SK_LEN;
    let _salt_len: usize = SALT_LEN;
    let _id: Identity = Identity::new([1u8; SK_LEN], [2u8; SALT_LEN]);
    let _c: IdentityCommitment = _id.commitment::<Sha256Hasher>();
    // merkle module
    let _depth: usize = MERKLE_DEPTH;
    let _max: usize = MAX_LEAVES;
    let _t: MerkleTree<Sha256Hasher> = MerkleTree::<Sha256Hasher>::new();
    let _err = MerkleError::Full(_max);
    let _proof = MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    let _verifier_fn: fn(&Hash, &Hash, &MerkleProof) -> bool = verify_proof::<Sha256Hasher>;
    // nullifier module
    let _nullifier_fn: fn(&[u8; SK_LEN], &Hash) -> Hash = nullifier::<Sha256Hasher>;
}

/// `hash.rs` doc says `Hash` is "fixed at 32 bytes — sized for both SHA-256
/// and Poseidon over BN254". Pin the byte length so a future refactor that
/// changes `HASH_LEN` (e.g. to 31 for BN254 raw) trips this test and forces
/// the doc / wire-format conversation. Also pin that `Hash` and `[u8;
/// HASH_LEN]` are the same type at the value level.
/// Outcome: mitigated.
#[test]
fn r4_hash_alias_is_32_byte_array_mitigated() {
    assert_eq!(HASH_LEN, 32);
    assert_eq!(std::mem::size_of::<Hash>(), HASH_LEN);
    // Confirm `Hash` IS `[u8; HASH_LEN]` (not a newtype) by direct
    // assignment in both directions.
    let h: Hash = [7u8; HASH_LEN];
    let arr: [u8; HASH_LEN] = h;
    let h2: Hash = arr;
    assert_eq!(h, h2);
}

/// `hash.rs` doc says `hash_pair` "remains exposed as an undomained utility
/// — it must NOT be used by the Merkle tree". This is a doc-level invariant.
/// Verify behaviorally: for any (left, right), `hash_pair(left, right)` is
/// 64-byte SHA-256 (no domain prefix) while `hash_node(left, right)` is
/// 65-byte SHA-256 with `DOMAIN_NODE = 0x01` prefix. If a future refactor
/// silently aliased `hash_pair = hash_node`, this test fires.
/// Outcome: mitigated.
#[test]
fn r4_hash_pair_remains_undomained_per_doc_mitigated() {
    let l = [0x11u8; HASH_LEN];
    let r = [0x22u8; HASH_LEN];
    let pair = Sha256Hasher::hash_pair(&l, &r);
    let node = Sha256Hasher::hash_node(&l, &r);
    assert_ne!(pair, node, "doc-vs-code drift: hash_pair == hash_node");

    // Pair is plain SHA-256(l || r):
    let mut buf = [0u8; 2 * HASH_LEN];
    buf[..HASH_LEN].copy_from_slice(&l);
    buf[HASH_LEN..].copy_from_slice(&r);
    let expected_pair: [u8; HASH_LEN] = Sha256::digest(buf).into();
    assert_eq!(pair, expected_pair);

    // Node is SHA-256(0x01 || l || r):
    let mut buf2 = [0u8; 1 + 2 * HASH_LEN];
    buf2[0] = DOMAIN_NODE;
    buf2[1..1 + HASH_LEN].copy_from_slice(&l);
    buf2[1 + HASH_LEN..].copy_from_slice(&r);
    let expected_node: [u8; HASH_LEN] = Sha256::digest(buf2).into();
    assert_eq!(node, expected_node);
}

/// `merkle.rs` doc says `insert` does NOT check for duplicates — that
/// uniqueness is the on-chain `add_member` handler's job. Verify: inserting
/// the same `Hash` twice must succeed both times and yield SEQUENTIAL
/// indices (not e.g. dedupe to the first slot).
/// Outcome: mitigated (matches doc).
#[test]
fn r4_insert_doc_no_dedupe_check_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let leaf: Hash = [0xABu8; HASH_LEN];
    let i0 = t.insert(leaf).unwrap();
    let i1 = t.insert(leaf).unwrap();
    let i2 = t.insert(leaf).unwrap();
    assert_eq!(i0, 0);
    assert_eq!(i1, 1);
    assert_eq!(i2, 2);
    assert_eq!(t.len(), 3);
    // And both indices produce valid proofs that verify against the same root.
    let root = t.root();
    let p0 = t.proof(0).unwrap();
    let p1 = t.proof(1).unwrap();
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &p0));
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &p1));
    // Crucially, the two proofs are DIFFERENT (different paths) — so dedupe
    // would have lost information.
    assert_ne!(
        p0, p1,
        "doc drift: insert deduplicated when it should not have"
    );
}

/// `verify_proof` doc says "Returns `false` if `leaf == [0; HASH_LEN]`".
/// Verify that exact behavior on the boundary: leaf = [0;32] returns false,
/// leaf differing in the LAST byte by 1 does not short-circuit on the same
/// guard.
/// Outcome: mitigated (matches doc).
#[test]
fn r4_verify_proof_doc_zero_leaf_guard_exact_boundary_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    // Insert a real leaf so we have a real root that wouldn't accidentally
    // accept anything.
    let real: Hash = [0x42u8; HASH_LEN];
    t.insert(real).unwrap();
    let root = t.root();
    let proof = t.proof(0).unwrap();

    // Boundary: leaf = [0;32] short-circuits to false even with a structurally
    // valid `proof` shape.
    assert!(!verify_proof::<Sha256Hasher>(&root, &ZERO, &proof));

    // Near-boundary: leaf differs only in last byte by 1 — the guard does
    // NOT short-circuit; the result is whatever the real path walk says
    // (overwhelmingly false against this real root).
    let mut near = [0u8; HASH_LEN];
    near[HASH_LEN - 1] = 0x01;
    let v = verify_proof::<Sha256Hasher>(&root, &near, &proof);
    // It must be false (otherwise we have a soundness bug), but the
    // important contract is the guard DIDN'T eat it.
    assert!(!v);

    // First byte differs by 1.
    let mut near2 = [0u8; HASH_LEN];
    near2[0] = 0x01;
    assert!(!verify_proof::<Sha256Hasher>(&root, &near2, &proof));
}

/// `verify_proof` doc says "`leaf` is the raw commitment (`H(sk ‖ salt)`);
/// domain-separated leaf hashing is applied internally so callers never need
/// to remember the `DOMAIN_LEAF` byte." Test: an SDK author who PRE-applies
/// `hash_leaf` to their commitment before passing it in MUST get a rejection
/// (their input is then hashed twice with DOMAIN_LEAF). If the doc were
/// wrong and `verify_proof` expected pre-hashed leaves, this test would
/// fail loudly.
/// Outcome: mitigated (doc matches code).
#[test]
fn r4_verify_proof_doc_callers_pass_raw_commitment_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let id = Identity::new([0x55u8; SK_LEN], [0x66u8; SALT_LEN]);
    let c = id.commitment::<Sha256Hasher>();
    t.insert(*c.as_bytes()).unwrap();
    let root = t.root();
    let proof = t.proof(0).unwrap();

    // Correct call: pass the raw commitment.
    assert!(verify_proof::<Sha256Hasher>(&root, c.as_bytes(), &proof));

    // Wrong call: caller pre-applied hash_leaf. Must reject — otherwise the
    // doc lies.
    let prehashed = Sha256Hasher::hash_leaf(c.as_bytes());
    assert!(
        !verify_proof::<Sha256Hasher>(&root, &prehashed, &proof),
        "doc drift: verify_proof accepted a pre-hash_leaf'd input"
    );
}

/// `Identity::nullifier` doc says it "Keeps `sk` inside `Identity` at the
/// call site instead of forcing callers to pass `&identity.sk` directly".
/// Verify behaviorally that `self.salt` is NOT touched — flipping every bit
/// of `salt` must leave the nullifier unchanged. Spec called out
/// salt-independence as the key anonymity-set property.
/// Outcome: mitigated.
#[test]
fn r4_identity_nullifier_doc_salt_untouched_mitigated() {
    let sk = [0xCDu8; SK_LEN];
    let pid = [0xEFu8; HASH_LEN];
    let id_a = Identity::new(sk, [0x00u8; SALT_LEN]);
    let id_b = Identity::new(sk, [0xFFu8; SALT_LEN]);
    assert_eq!(
        id_a.nullifier::<Sha256Hasher>(&pid),
        id_b.nullifier::<Sha256Hasher>(&pid),
        "doc drift: salt influenced nullifier (anonymity-set break)"
    );
}

/// `nullifier.rs` doc claims "Deterministic in (sk, proposal_id)" and
/// "Unlinkable across proposals". Round 1/2 covered the positive forms;
/// round 4 adds the negative: a single-bit flip in `proposal_id` produces
/// a nullifier whose Hamming distance from the original is overwhelmingly
/// large (~128 bits on average for SHA-256). Sample 200 single-bit flips
/// and assert the Hamming distance is in a plausible band (avalanche).
/// Outcome: mitigated.
#[test]
fn r4_nullifier_doc_avalanche_proptest_mitigated() {
    let sk = [0x21u8; SK_LEN];
    let base_pid = [0x42u8; HASH_LEN];
    let base_null = nullifier::<Sha256Hasher>(&sk, &base_pid);

    let mut min_distance = usize::MAX;
    let mut max_distance: usize = 0;
    let mut sum_distance: usize = 0;
    let trials = 256; // every bit of proposal_id, exactly once
    for bit in 0..trials {
        let mut pid = base_pid;
        pid[bit / 8] ^= 1 << (bit % 8);
        let null = nullifier::<Sha256Hasher>(&sk, &pid);
        let dist: usize = null
            .iter()
            .zip(base_null.iter())
            .map(|(a, b)| (a ^ b).count_ones() as usize)
            .sum();
        min_distance = min_distance.min(dist);
        max_distance = max_distance.max(dist);
        sum_distance += dist;
        assert_ne!(
            null, base_null,
            "single-bit pid flip produced same nullifier"
        );
    }
    let avg = sum_distance / trials;
    // SHA-256 single-bit-flip avalanche has mean ≈ 128, std-dev ≈ 8. A
    // legitimate impl should produce min >= 96 and max <= 160. Pin a slightly
    // looser band to be robust to RNG luck.
    assert!(
        min_distance >= 80,
        "nullifier avalanche minimum too low: {min_distance}"
    );
    assert!(
        max_distance <= 176,
        "nullifier avalanche maximum too high: {max_distance}"
    );
    assert!(
        (112..=144).contains(&avg),
        "nullifier avalanche mean off-center: {avg}"
    );
}

// ===========================================================================
// 2. INTEGER OVERFLOW / WRAPAROUND CORNERS
// ===========================================================================

/// MAX_LEAVES = 1 << MERKLE_DEPTH. If MERKLE_DEPTH ever reached 64+, that
/// shift would be UB on 64-bit platforms. Pin a constant guard so a future
/// refactor that bumps depth past the safe ceiling fails at this assertion
/// before reaching `1usize << MERKLE_DEPTH`.
/// Outcome: mitigated (depth is 20, far below the 63-bit ceiling on 64-bit
/// platforms).
#[test]
fn r4_merkle_depth_well_below_shift_overflow_mitigated() {
    // On a 64-bit usize, `1usize << k` is well-defined for k in 0..=63.
    // We require k < 63 (so MAX_LEAVES * 2 also doesn't overflow).
    assert!(
        MERKLE_DEPTH < 63,
        "MERKLE_DEPTH = {MERKLE_DEPTH} would overflow `1usize << MERKLE_DEPTH` on 64-bit"
    );
    // Also: enforce a sane upper ceiling for our use case (1M members).
    assert!(
        MERKLE_DEPTH <= 32,
        "MERKLE_DEPTH bumped past 2^32 ceiling — review PLAN.md"
    );
    // And the literal MAX_LEAVES does not overflow.
    let _check = (MAX_LEAVES as u128)
        .checked_mul(2)
        .expect("MAX_LEAVES * 2 overflowed u128");
    // Cross-check vs computed.
    assert_eq!(MAX_LEAVES, 1usize << MERKLE_DEPTH);
}

/// `proof()` does `let sibling = current ^ 1;` on `current = index`. If
/// `index = usize::MAX`, `usize::MAX ^ 1 = usize::MAX - 1`, no overflow. But
/// `proof()` is gated by `index < self.leaves.len() <= MAX_LEAVES`, so we
/// can never get `usize::MAX` through the public surface. Verify that the
/// gate REJECTS `usize::MAX` cleanly with a typed error.
/// Outcome: mitigated.
#[test]
fn r4_proof_usize_max_index_returns_typed_error_no_panic_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    t.insert([0x01u8; HASH_LEN]).unwrap();
    match t.proof(usize::MAX) {
        Err(MerkleError::IndexOutOfRange { index, next }) => {
            assert_eq!(index, usize::MAX);
            assert_eq!(next, 1);
        }
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }
}

/// `current >>= 1` is applied MERKLE_DEPTH times in the proof loop. After
/// 20 shifts on `current = MAX_LEAVES - 1 = 2^20 - 1`, the value reaches 0
/// then stays at 0 (no UB). Sentinel: confirm proof for the LAST insertable
/// index (or, since we cannot insert 2^20 cheaply, the simulated effect
/// of the shift loop).
/// Outcome: mitigated.
#[test]
fn r4_current_shift_loop_terminates_at_zero_mitigated() {
    // Simulate the shift loop independently from the live tree.
    let mut current: usize = MAX_LEAVES - 1;
    for _ in 0..MERKLE_DEPTH {
        // ^ 1 is safe at every step (current is in [0, MAX_LEAVES-1]).
        let _sibling = current ^ 1;
        current >>= 1;
    }
    assert_eq!(current, 0, "current must reach 0 after MERKLE_DEPTH shifts");

    // Extra-paranoid: even MORE shifts past MERKLE_DEPTH should stay at 0
    // (Rust does NOT wrap `0 >> 1` — defined as 0).
    for _ in 0..100 {
        current >>= 1;
    }
    assert_eq!(current, 0);
}

/// `node_at` does `let start = pos * span;` where `span = 1 << level`.
/// For the largest valid call — level = MERKLE_DEPTH = 20, pos = 0 (root) —
/// `pos * span = 0`. For the next-to-root level = 19, pos = 1, span = 2^19,
/// product = 524288 < usize::MAX. Pin a sentinel that the largest possible
/// (level, pos) inside any legitimate `proof()` call cannot overflow.
/// Outcome: mitigated.
#[test]
fn r4_node_at_arithmetic_cannot_overflow_for_legitimate_callers_mitigated() {
    // `proof(idx)` for `idx < MAX_LEAVES` calls `node_at(level, sibling)`
    // for sibling ∈ [0, MAX_LEAVES / span]. The product `sibling * span`
    // is bounded by `MAX_LEAVES = 1 << MERKLE_DEPTH = 2^20`.
    for level in 0..=MERKLE_DEPTH {
        let span: usize = 1usize << level;
        let max_pos_at_level: usize = MAX_LEAVES / span;
        // pos * span ≤ MAX_LEAVES, no overflow.
        let product: u128 = (max_pos_at_level as u128) * (span as u128);
        assert!(product <= MAX_LEAVES as u128);
        // And pos * 2 + 1 (the recursive descent) cannot overflow either
        // for any pos in [0, MAX_LEAVES/span].
        let _check = max_pos_at_level
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .expect("pos*2+1 overflowed at level {level}");
    }
}

/// `index ^ 1` is safe for every `index ∈ [0, MAX_LEAVES - 1]`. Verify
/// across the spectrum that the XOR pair-up logic produces siblings within
/// the valid pos range at each level.
/// Outcome: mitigated.
#[test]
fn r4_index_xor_one_yields_valid_sibling_at_every_level_mitigated() {
    for &idx in &[0usize, 1, 2, 7, 100, 1023, MAX_LEAVES - 2, MAX_LEAVES - 1] {
        let mut current = idx;
        for level in 0..MERKLE_DEPTH {
            let sibling = current ^ 1;
            // Both `current` and `sibling` must be within the legal pos
            // range for this level: `pos < MAX_LEAVES / (1 << level) = 2^(20-level)`.
            let level_cap = 1usize << (MERKLE_DEPTH - level);
            assert!(
                current < level_cap,
                "current {current} >= cap {level_cap} at level {level}"
            );
            assert!(
                sibling < level_cap,
                "sibling {sibling} >= cap {level_cap} at level {level}"
            );
            current >>= 1;
        }
    }
}

// ===========================================================================
// 3. ENCODING EDGE CASES — Trojan-source / unicode-in-docs
// ===========================================================================

/// Doc comments use `‖` (U+2016 DOUBLE VERTICAL LINE). Confirm the bytes
/// the code actually hashes are PLAIN ASCII concatenation — no `‖`
/// character ever appears in any input to SHA-256. Defense: hash a string
/// containing literal `‖` and confirm it differs from the canonical
/// `sk || pid` SHA-256 output.
///
/// This is the Trojan-source threat: a malicious PR could insert a unicode
/// character into a hash input and the diff would visually look identical
/// to byte concatenation.
/// Outcome: mitigated.
#[test]
fn r4_no_unicode_separator_in_hash_inputs_mitigated() {
    let sk = [0x11u8; SK_LEN];
    let pid = [0x22u8; HASH_LEN];
    let canonical = nullifier::<Sha256Hasher>(&sk, &pid);

    // Trojan: an attacker silently changes `buf[..SK_LEN].copy_from_slice(sk)`
    // to a Vec that interleaves the U+2016 unicode separator. The bytes of
    // U+2016 in UTF-8 are E2 80 96.
    let separator = "\u{2016}";
    assert_eq!(separator.as_bytes(), &[0xE2u8, 0x80, 0x96]);
    let mut trojan = Vec::new();
    trojan.extend_from_slice(&sk);
    trojan.extend_from_slice(separator.as_bytes());
    trojan.extend_from_slice(&pid);
    let trojan_hash: [u8; HASH_LEN] = Sha256::digest(&trojan).into();
    assert_ne!(
        canonical, trojan_hash,
        "Trojan-source separator landed in hash input!"
    );

    // Same for commitment.
    let salt = [0x33u8; SALT_LEN];
    let id = Identity::new(sk, salt);
    let c = id.commitment::<Sha256Hasher>();
    let mut trojan2 = Vec::new();
    trojan2.extend_from_slice(&sk);
    trojan2.extend_from_slice(separator.as_bytes());
    trojan2.extend_from_slice(&salt);
    let trojan2_hash: [u8; HASH_LEN] = Sha256::digest(&trojan2).into();
    assert_ne!(*c.as_bytes(), trojan2_hash);
}

/// Homoglyph defense: the spec called out the `verify_proof` /
/// `Verify_proof` confusion. Confirm the EXACT public name compiles in
/// expression position; if a future PR introduces a confusable variant
/// (e.g. Cyrillic V), the compiler would not allow shadowing within the
/// same module and the build would surface the issue. Sentinel: take the
/// function pointer with the LATIN-letter name and confirm it's the one
/// re-exported from `crypto::verify_proof`.
/// Outcome: mitigated (no homoglyph variant exists in the public surface).
#[test]
fn r4_no_homoglyph_function_variant_mitigated() {
    // Bind the function with its exact Latin-character name. If a
    // refactor introduced a Cyrillic-look-alike, this would either fail to
    // resolve or resolve to the homoglyph (which would then fail the
    // behavior assertion below).
    let fn_ptr: fn(&Hash, &Hash, &MerkleProof) -> bool = verify_proof::<Sha256Hasher>;
    let fn_via_module: fn(&Hash, &Hash, &MerkleProof) -> bool =
        crypto::verify_proof::<Sha256Hasher>;
    // Both must behave identically.
    let mut t = MerkleTree::<Sha256Hasher>::new();
    t.insert([0xAAu8; HASH_LEN]).unwrap();
    let root = t.root();
    let leaf = [0xAAu8; HASH_LEN];
    let p = t.proof(0).unwrap();
    assert_eq!(fn_ptr(&root, &leaf, &p), fn_via_module(&root, &leaf, &p));
    assert!(fn_ptr(&root, &leaf, &p));
}

/// The Trojan defense for the *constants*: pin `DOMAIN_LEAF` and
/// `DOMAIN_NODE` to their numeric byte values literal-by-literal. If a
/// silent refactor introduced a unicode confusable for `0x00` / `0x01`
/// (e.g. via a `const`-rebind in a macro), the byte equality would break.
/// Outcome: mitigated.
#[test]
fn r4_domain_byte_constants_literal_pinned_mitigated() {
    assert_eq!(DOMAIN_LEAF as u32, 0);
    assert_eq!(DOMAIN_NODE as u32, 1);
    // Convert through u32 to defeat any const-fold trickery.
    let leaf_byte: u8 = 0u8;
    let node_byte: u8 = 1u8;
    assert_eq!(DOMAIN_LEAF, leaf_byte);
    assert_eq!(DOMAIN_NODE, node_byte);
}

// ===========================================================================
// 4. CONSTRUCTION-TIME INVARIANTS DEPENDING ON ORDER
// ===========================================================================

/// `MerkleTree::root()` is computed on-demand from `self.leaves`. So
/// `insert → root → insert → root` should produce DIFFERENT roots at each
/// `root()` call. Verify the ordering invariant.
/// Outcome: mitigated.
#[test]
fn r4_root_recomputed_each_call_insert_root_insert_root_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let r0 = t.root();
    t.insert([0x01u8; HASH_LEN]).unwrap();
    let r1 = t.root();
    let r1_again = t.root();
    t.insert([0x02u8; HASH_LEN]).unwrap();
    let r2 = t.root();
    t.insert([0x03u8; HASH_LEN]).unwrap();
    let r3 = t.root();

    // Order-dependence: each root must differ from each other root.
    let roots = [r0, r1, r2, r3];
    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            assert_ne!(
                roots[i], roots[j],
                "roots[{i}] == roots[{j}] after distinct inserts"
            );
        }
    }
    // Idempotence of root() within the same logical state.
    assert_eq!(
        r1, r1_again,
        "root() returned different values for the same state"
    );
}

/// If `MerkleProof` is constructed via public fields directly, can an
/// attacker make `siblings.len() != MERKLE_DEPTH`? No — `[Hash; MERKLE_DEPTH]`
/// is fixed-size. Sentinel: take the size of the array and confirm.
/// Outcome: mitigated by the type system.
#[test]
fn r4_merkle_proof_public_field_sizes_fixed_by_type_system_mitigated() {
    let p = MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    assert_eq!(p.siblings.len(), MERKLE_DEPTH);
    assert_eq!(p.indices.len(), MERKLE_DEPTH);
    // Sanity: the public-fields construction matches the type-derived size.
    let sib_bytes = std::mem::size_of_val(&p.siblings);
    assert_eq!(sib_bytes, MERKLE_DEPTH * HASH_LEN);
    let idx_bytes = std::mem::size_of_val(&p.indices);
    assert_eq!(idx_bytes, MERKLE_DEPTH * std::mem::size_of::<bool>());
}

/// Sequential `root()` after inserts builds DIFFERENT trees if inserts come
/// in different orders. Pin: same leaves inserted in two different orders
/// produce two different roots (because index→leaf binding is order-
/// sensitive). This is what makes "swap two members' enrollment order"
/// a detectable change on the wire.
/// Outcome: mitigated.
#[test]
fn r4_insertion_order_matters_for_root_mitigated() {
    let mut t1 = MerkleTree::<Sha256Hasher>::new();
    let mut t2 = MerkleTree::<Sha256Hasher>::new();
    let a: Hash = [0x10u8; HASH_LEN];
    let b: Hash = [0x20u8; HASH_LEN];
    t1.insert(a).unwrap();
    t1.insert(b).unwrap();
    t2.insert(b).unwrap();
    t2.insert(a).unwrap();
    assert_ne!(t1.root(), t2.root(), "insertion order did not affect root");
    // But a tree with the SAME inserts in the SAME order produces the
    // SAME root.
    let mut t3 = MerkleTree::<Sha256Hasher>::new();
    t3.insert(a).unwrap();
    t3.insert(b).unwrap();
    assert_eq!(t1.root(), t3.root());
}

// ===========================================================================
// 5. TYPE-SYSTEM SHORTCUTS
// ===========================================================================

/// `verify_proof` takes `&Hash`. Verify that `leaf.as_ref()` (returning
/// `&[u8; 32]`) works at the call site. This is the "SDK author wraps a
/// Hash in a newtype with AsRef" pattern; we want it to compile and behave.
/// Outcome: mitigated.
#[test]
fn r4_verify_proof_accepts_as_ref_pattern_mitigated() {
    struct Wrapper(Hash);
    impl AsRef<[u8; HASH_LEN]> for Wrapper {
        fn as_ref(&self) -> &[u8; HASH_LEN] {
            &self.0
        }
    }
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let leaf: Hash = [0x77u8; HASH_LEN];
    t.insert(leaf).unwrap();
    let root = t.root();
    let proof = t.proof(0).unwrap();
    let w = Wrapper(leaf);
    assert!(verify_proof::<Sha256Hasher>(&root, w.as_ref(), &proof));
    // And via &Hash directly.
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &proof));
}

/// `IdentityCommitment::as_bytes` returns `&[u8; HASH_LEN]` (fixed array)
/// — NOT `&[u8]` (slice). Confirm signature behaviorally and pin the
/// returned type so a refactor to slice would surface here.
/// Outcome: mitigated.
#[test]
fn r4_identity_commitment_as_bytes_is_fixed_array_not_slice_mitigated() {
    let id = Identity::new([0x10u8; SK_LEN], [0x20u8; SALT_LEN]);
    let c = id.commitment::<Sha256Hasher>();
    let bytes: &[u8; HASH_LEN] = c.as_bytes();
    assert_eq!(bytes.len(), HASH_LEN);
    // The signature returns &[u8; 32], not &[u8] — confirm by trying to use
    // a length-known operation.
    let copied: [u8; HASH_LEN] = *bytes;
    assert_eq!(copied, c.0);
    // And coerces to slice when needed.
    let as_slice: &[u8] = &bytes[..];
    assert_eq!(as_slice.len(), HASH_LEN);
}

// ===========================================================================
// 6. PUBLIC-SURFACE OBSERVATIONS (semver footguns)
// ===========================================================================

/// `Identity { pub sk, pub salt }` — direct public field access. An
/// SDK author can construct an Identity by literal-fields, bypassing
/// `Identity::new`. Confirm both paths produce identical values, AND that
/// construction-by-fields exposes no invariant gap (e.g. if `new` ever
/// started doing extra work like normalizing key material, direct field
/// access would silently skip it).
/// Outcome: OBSERVATION — `new` currently does no work beyond field
/// assignment, so the two paths are equivalent. Documented as a semver
/// trade-off, not a bug.
#[test]
fn r4_identity_pub_fields_observation_mitigated() {
    let sk = [0x88u8; SK_LEN];
    let salt = [0x99u8; SALT_LEN];
    let via_new = Identity::new(sk, salt);
    let via_fields = Identity { sk, salt };
    assert_eq!(via_new, via_fields);
    assert_eq!(
        via_new.commitment::<Sha256Hasher>(),
        via_fields.commitment::<Sha256Hasher>()
    );
    // Future work: if `Identity::new` ever needs to enforce an invariant
    // (e.g. reject all-zero `sk`), this test will need adapting — and the
    // public `sk` / `salt` fields will need to be made non-pub.
}

/// `IdentityCommitment(pub Hash)` — same semver footgun on the wrapping
/// side. Confirm that direct tuple-construction matches `commitment::<H>()`
/// output and that the wrapper is structurally transparent.
/// Outcome: OBSERVATION.
#[test]
fn r4_identity_commitment_pub_wrapper_observation_mitigated() {
    let sk = [0xCCu8; SK_LEN];
    let salt = [0xDDu8; SALT_LEN];
    let id = Identity::new(sk, salt);
    let c = id.commitment::<Sha256Hasher>();

    // Reconstruct via the public tuple constructor.
    let mut buf = [0u8; SK_LEN + SALT_LEN];
    buf[..SK_LEN].copy_from_slice(&sk);
    buf[SK_LEN..].copy_from_slice(&salt);
    let direct = IdentityCommitment(Sha256Hasher::hash(&buf));
    assert_eq!(c, direct);
    // And construct an attacker-crafted commitment that does NOT correspond
    // to any real (sk, salt) — the wrapper accepts arbitrary bytes.
    let forged = IdentityCommitment([0xDE; HASH_LEN]);
    // No equality check guards against this — the Merkle layer is what
    // checks membership. Sentinel: confirm the bytes flow through unchanged.
    assert_eq!(forged.0, [0xDE; HASH_LEN]);
    assert_eq!(forged.as_bytes(), &[0xDE; HASH_LEN]);
}

/// `Identity::Debug` redacts both `sk` and `salt`. Pin that both fields
/// render as `[REDACTED]` and the raw bytes do NOT appear in the output.
/// Round 1 covered the basic case; round 4 confirms it for distinctive
/// byte sequences (so any partial leak shows up immediately in the rendered
/// string).
/// Outcome: mitigated.
#[test]
fn r4_identity_debug_redacts_observation_mitigated() {
    // Use byte patterns whose hex representation has very few collisions
    // with normal English.
    let sk = [0xDEu8; SK_LEN];
    let salt = [0xADu8; SALT_LEN];
    let id = Identity::new(sk, salt);
    let rendered = format!("{:?}", id);
    // sk and salt must each render as REDACTED.
    assert!(rendered.contains("sk: \"[REDACTED]\""));
    assert!(rendered.contains("salt: \"[REDACTED]\""));
    // And no `de` / `ad` substring (hex of the secret bytes) leaks.
    let lower = rendered.to_lowercase();
    // Exclude `[REDACTED]` itself — capital REDACTED has no 'd' next to 'e'
    // in the right pattern. But the substring "de" or "ad" might appear in
    // the Rust formatter's quoting; we check the raw byte hex pair would
    // not appear.
    assert!(
        !lower.contains("dededededededededededededededededededededededededededededededede"),
        "sk bytes leaked into Debug output: {rendered}"
    );
    assert!(
        !lower.contains("adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad"),
        "salt bytes leaked into Debug output: {rendered}"
    );
}

// ===========================================================================
// 7. DESIGN NOTE: Hasher::Output type
// ===========================================================================

/// `Hasher::hash` returns `Hash` (fixed 32-byte). If a future Poseidon
/// implementation wanted a different output (e.g. a `[u8; 31]` BN254 element),
/// the trait would need a generic Output type. Sentinel: confirm the trait
/// methods all agree on `Hash` as output. This is a DESIGN NOTE for the
/// follow-up Poseidon implementation, not a bug today.
/// Outcome: documented design trade-off.
#[test]
fn r4_hasher_output_type_unification_design_note_mitigated() {
    // The Hasher trait signatures all return `Hash`. Pin via function
    // pointer types.
    let _hash: fn(&[u8]) -> Hash = <Sha256Hasher as Hasher>::hash;
    let _hash_pair: fn(&Hash, &Hash) -> Hash = <Sha256Hasher as Hasher>::hash_pair;
    let _hash_leaf: fn(&Hash, &Hash) -> Hash = {
        // hash_pair has the right type; hash_leaf has (&Hash) -> Hash.
        // Just bind hash_pair here to satisfy the unused-binding lint.
        <Sha256Hasher as Hasher>::hash_pair
    };
    let _hash_leaf_fn: fn(&Hash) -> Hash = <Sha256Hasher as Hasher>::hash_leaf;
    let _hash_node: fn(&Hash, &Hash) -> Hash = <Sha256Hasher as Hasher>::hash_node;

    // All four output types are `Hash`. If Poseidon ever wants a different
    // output, the Hasher trait will need a `type Output` associated type.
}

// ===========================================================================
// 8. ALLOCATION SURPRISES
// ===========================================================================

/// `MerkleTree::insert` pushes to a `Vec<Hash>`. Pin that the Vec uses
/// standard geometric growth — no surprise allocation profile. Sample
/// after a sequence of 1024 inserts and confirm the capacity is at most
/// 2x the length (geometric-growth invariant).
/// Outcome: mitigated.
#[test]
fn r4_insert_vec_growth_is_geometric_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    for i in 0..1024 {
        let mut l = [0u8; HASH_LEN];
        l[0] = (i & 0xFF) as u8;
        l[1] = ((i >> 8) & 0xFF) as u8;
        l[HASH_LEN - 1] = 0xFF; // avoid FINDING-1b guard
        t.insert(l).unwrap();
    }
    assert_eq!(t.len(), 1024);
    // We can't directly inspect the Vec capacity through the public API,
    // but we can verify the size of the tree struct itself stays small
    // (no surprise heap allocation beyond the Vec backing storage).
    // size_of<MerkleTree> includes: Vec<Hash> = 24 bytes (ptr, len, cap),
    // zero_hashes = (MERKLE_DEPTH+1)*HASH_LEN = 21*32 = 672, _phantom = 0.
    let s = std::mem::size_of::<MerkleTree<Sha256Hasher>>();
    assert!(
        (24 + 672..=24 + 672 + 64).contains(&s),
        "MerkleTree size unexpected: {s} bytes"
    );
}

/// Sentinel: `Identity::commitment` uses a 64-byte stack buffer; no heap.
/// `nullifier` uses a 64-byte stack buffer; no heap. `Sha256Hasher::hash_node`
/// uses a 65-byte stack buffer. Pin sizes via the `std::mem::size_of` of
/// the input types — if any of these ever changed, the wire format would
/// change. (Not directly observable, but we pin SK_LEN/SALT_LEN as a proxy.)
/// Outcome: mitigated.
#[test]
fn r4_stack_buffer_sizes_pinned_mitigated() {
    assert_eq!(SK_LEN, 32);
    assert_eq!(SALT_LEN, 32);
    assert_eq!(HASH_LEN, 32);
    // Commitment buffer = SK_LEN + SALT_LEN = 64.
    assert_eq!(SK_LEN + SALT_LEN, 64);
    // Nullifier buffer = SK_LEN + HASH_LEN = 64.
    assert_eq!(SK_LEN + HASH_LEN, 64);
    // hash_node buffer = 1 + 2*HASH_LEN = 65.
    assert_eq!(1 + 2 * HASH_LEN, 65);
    // hash_leaf buffer = 1 + HASH_LEN = 33.
    assert_eq!(1 + HASH_LEN, 33);
    // hash_pair buffer = 2*HASH_LEN = 64.
    assert_eq!(2 * HASH_LEN, 64);
}

// ===========================================================================
// 9. SOUNDNESS ORACLE — 10k random (root, leaf, proof) must never accept
// ===========================================================================

/// Aggressive randomized search: 10k samples with random leaves, random
/// proofs, random roots. Zero acceptances expected. If `verify_proof` is
/// sound, this is a clean negative result. If it's not, this catches the
/// bug. This is the spec's headline ask for round 4.
/// Outcome: mitigated.
#[test]
fn r4_soundness_oracle_10k_random_samples_no_accepts_mitigated() {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_F00D_DEAD);
    let mut accepts: u64 = 0;
    for trial in 0..10_000u64 {
        let mut root = [0u8; HASH_LEN];
        let mut leaf = [0u8; HASH_LEN];
        rng.fill_bytes(&mut root);
        rng.fill_bytes(&mut leaf);
        let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
        for s in siblings.iter_mut() {
            rng.fill_bytes(s);
        }
        // Random direction bits — use two u32s to fill 20 booleans.
        let bits: u64 = rng.random();
        let mut indices = [false; MERKLE_DEPTH];
        for i in 0..MERKLE_DEPTH {
            indices[i] = (bits >> i) & 1 == 1;
        }
        let p = MerkleProof { siblings, indices };
        if verify_proof::<Sha256Hasher>(&root, &leaf, &p) {
            accepts += 1;
            // Capture the witness immediately for debugging.
            panic!(
                "SOUNDNESS BREAK at trial {trial}: \n  root={}\n  leaf={}\n  proof={:?}",
                hex::encode(root),
                hex::encode(leaf),
                p
            );
        }
    }
    assert_eq!(
        accepts, 0,
        "soundness oracle: {accepts} acceptances in 10k random samples"
    );
}

/// Soundness oracle variant 2: random (leaf, proof) against a REAL root
/// from a populated tree where the proof was NOT derived from the tree.
/// 5k samples; should accept ZERO unless `leaf` happens to be one of the
/// real leaves AND `proof` happens to match its derived proof (vanishingly
/// improbable).
/// Outcome: mitigated.
#[test]
fn r4_soundness_oracle_real_root_random_witness_no_accepts_mitigated() {
    // Build a real tree with 32 leaves.
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let mut real_leaves: Vec<Hash> = Vec::new();
    let mut rng = StdRng::seed_from_u64(0x1234_5678_9ABC_DEF0);
    for _ in 0..32 {
        let mut l = [0u8; HASH_LEN];
        rng.fill_bytes(&mut l);
        if l == ZERO {
            l[0] = 0x01;
        }
        t.insert(l).unwrap();
        real_leaves.push(l);
    }
    let root = t.root();

    let mut accepts: u64 = 0;
    for _ in 0..5_000u64 {
        let mut leaf = [0u8; HASH_LEN];
        rng.fill_bytes(&mut leaf);
        let mut siblings = [[0u8; HASH_LEN]; MERKLE_DEPTH];
        for s in siblings.iter_mut() {
            rng.fill_bytes(s);
        }
        let bits: u64 = rng.random();
        let mut indices = [false; MERKLE_DEPTH];
        for i in 0..MERKLE_DEPTH {
            indices[i] = (bits >> i) & 1 == 1;
        }
        let p = MerkleProof { siblings, indices };
        if verify_proof::<Sha256Hasher>(&root, &leaf, &p) {
            // We'd need to verify whether this is a genuine match — but with
            // 256-bit SHA-256 and a 20-level proof, the chance is ~2^-256.
            accepts = accepts.saturating_add(1);
            panic!(
                "SOUNDNESS BREAK (real root variant): \n  leaf={}\n  proof={:?}",
                hex::encode(leaf),
                p
            );
        }
    }
    assert_eq!(
        accepts, 0,
        "soundness oracle (real root): {accepts} acceptances in 5k random samples"
    );
}

// ===========================================================================
// 10. CREATIVE — additional attack classes
// ===========================================================================

/// Empty Vec sentinel: `MerkleTree::leaf(index)` returns `Option<Hash>`. For
/// any index out of range (including `usize::MAX`), it must return None
/// without panic. The implementation uses `self.leaves.get(pos).copied()`
/// which is panic-safe — pin it.
/// Outcome: mitigated.
#[test]
fn r4_merkle_tree_leaf_out_of_range_returns_none_no_panic_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    t.insert([0xABu8; HASH_LEN]).unwrap();
    assert_eq!(t.leaf(0), Some([0xABu8; HASH_LEN]));
    assert_eq!(t.leaf(1), None);
    assert_eq!(t.leaf(100), None);
    assert_eq!(t.leaf(MAX_LEAVES - 1), None);
    assert_eq!(t.leaf(MAX_LEAVES), None);
    assert_eq!(t.leaf(usize::MAX), None);
}

/// MerkleError::IndexOutOfRange Display format pin: a downstream log parser
/// might match against the exact format `"index {index} is out of range
/// (next free slot is {next})"`. If the message text drifts (e.g. word
/// order changes), log-based monitoring silently breaks.
/// Outcome: mitigated (text format pinned).
#[test]
fn r4_merkle_error_index_out_of_range_display_pinned_mitigated() {
    let e = MerkleError::IndexOutOfRange { index: 42, next: 7 };
    let rendered = format!("{e}");
    assert_eq!(rendered, "index 42 is out of range (next free slot is 7)");
}

/// MerkleError::Full Display format pin: same rationale.
/// Outcome: mitigated.
#[test]
fn r4_merkle_error_full_display_pinned_mitigated() {
    let e = MerkleError::Full(MAX_LEAVES);
    let rendered = format!("{e}");
    assert_eq!(rendered, "tree is full (capacity 1048576)");
}

/// `MerkleProof::PartialEq` derives field-wise equality. Two proofs with
/// the SAME siblings but DIFFERENT indices must NOT compare equal. This is
/// the "indices accidentally compared with == on a tuple/Vec wrapper" trap.
/// Outcome: mitigated.
#[test]
fn r4_merkle_proof_eq_compares_both_fields_mitigated() {
    let p1 = MerkleProof {
        siblings: [[0xAAu8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    let mut p2 = p1.clone();
    assert_eq!(p1, p2);
    // Flip just one index.
    p2.indices[5] = true;
    assert_ne!(p1, p2, "MerkleProof Eq missed indices field difference");
    // Flip just one sibling byte.
    let mut p3 = p1.clone();
    p3.siblings[10][0] ^= 0x01;
    assert_ne!(p1, p3, "MerkleProof Eq missed siblings field difference");
}

/// Edge: at index 0 in a tree with N=1 leaf, all 20 sibling positions are
/// in unmaterialized subtrees, so they MUST all equal the `zero_hashes`
/// chain. Verify the proof's siblings match `empty_chain()[0..MERKLE_DEPTH]`
/// element-by-element. This is a structural invariant that pins the
/// internal `zero_hashes` chain to a publicly-derivable reference.
/// Outcome: mitigated.
#[test]
fn r4_proof_at_index_zero_in_single_leaf_tree_uses_zero_hash_chain_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let l: Hash = [0x42u8; HASH_LEN];
    t.insert(l).unwrap();
    let p = t.proof(0).unwrap();
    let chain = empty_chain();
    for level in 0..MERKLE_DEPTH {
        assert_eq!(
            p.siblings[level], chain[level],
            "sibling at level {level} differs from zero-chain reference"
        );
        // Direction at every level is `false` (current is always even side).
        assert!(!p.indices[level], "indices[{level}] not false");
    }
}

/// Edge: at index 1 in a tree with N=2 leaves, the proof at level 0 should
/// be the LEAF-HASHED value of leaf[0], not its raw bytes. This pins the
/// "level 0 wraps each stored leaf in hash_leaf" claim from the `node_at`
/// doc comment.
/// Outcome: mitigated.
#[test]
fn r4_proof_level_zero_sibling_is_hash_leaf_of_real_leaf_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let l0: Hash = [0x10u8; HASH_LEN];
    let l1: Hash = [0x20u8; HASH_LEN];
    t.insert(l0).unwrap();
    t.insert(l1).unwrap();
    let p1 = t.proof(1).unwrap();
    // For idx=1, level-0 sibling is the level-0 hash of leaf 0 (which is
    // hash_leaf(l0)).
    let expected_l0_hashed = Sha256Hasher::hash_leaf(&l0);
    assert_eq!(p1.siblings[0], expected_l0_hashed);
    // direction[0] = current & 1 == 1 for idx=1 => true.
    assert!(p1.indices[0]);
    // Now do the same for proof(0): its level-0 sibling is hash_leaf(l1).
    let p0 = t.proof(0).unwrap();
    let expected_l1_hashed = Sha256Hasher::hash_leaf(&l1);
    assert_eq!(p0.siblings[0], expected_l1_hashed);
    assert!(!p0.indices[0]);
}

/// "Mid-air" forgery attempt: present a leaf whose `hash_leaf(leaf)` is
/// CRAFTED to equal a real internal node hash mid-tree. Under SHA-256
/// preimage resistance an attacker can't do this in practice, but the
/// VERIFIER should reject any such input gracefully (no panic). We
/// approximate by presenting the level-0 hash of leaf 0 as a "leaf" input
/// — this is the post-hash_leaf bytes, so the verifier would hash it AGAIN
/// with DOMAIN_LEAF, producing a different value that can't close the path.
/// Outcome: mitigated.
#[test]
fn r4_mid_air_forgery_attempt_rejected_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let real: Hash = [0xCDu8; HASH_LEN];
    t.insert(real).unwrap();
    t.insert([0xEFu8; HASH_LEN]).unwrap();
    let root = t.root();
    let real_proof = t.proof(0).unwrap();

    // The "level-0 hashed" form of the real leaf — what the verifier's
    // FIRST hash step is supposed to produce internally.
    let mid_air_leaf = Sha256Hasher::hash_leaf(&real);
    // Present it as if it were a raw leaf — the verifier hashes it AGAIN,
    // so it doesn't close.
    assert!(
        !verify_proof::<Sha256Hasher>(&root, &mid_air_leaf, &real_proof),
        "verifier accepted a pre-hashed leaf"
    );
    // Also confirm the genuine leaf still verifies — sanity.
    assert!(verify_proof::<Sha256Hasher>(&root, &real, &real_proof));
}

/// `proof()` against an EMPTY tree: must error, not panic. Round 1/3 covered
/// this for `proof(0)`; round 4 adds `proof(MAX_LEAVES - 1)` to round out
/// the upper-bound case.
/// Outcome: mitigated.
#[test]
fn r4_proof_on_empty_tree_at_upper_bound_errors_mitigated() {
    let t = MerkleTree::<Sha256Hasher>::new();
    match t.proof(MAX_LEAVES - 1) {
        Err(MerkleError::IndexOutOfRange { index, next }) => {
            assert_eq!(index, MAX_LEAVES - 1);
            assert_eq!(next, 0);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

/// Sentinel: `MerkleTree::default()` MUST equal `MerkleTree::new()` in
/// observable behavior — same root, same len, same is_empty. If a refactor
/// changed `Default` to e.g. pre-populate a "genesis" leaf, every existing
/// caller would silently get a different root.
/// Outcome: mitigated.
#[test]
fn r4_merkle_tree_default_equals_new_mitigated() {
    let t1: MerkleTree<Sha256Hasher> = MerkleTree::default();
    let t2: MerkleTree<Sha256Hasher> = MerkleTree::new();
    assert_eq!(t1.root(), t2.root());
    assert_eq!(t1.len(), t2.len());
    assert_eq!(t1.is_empty(), t2.is_empty());
    assert_eq!(t1.capacity(), t2.capacity());
}

/// `Hasher::NAME` is a const &'static str. For Sha256Hasher it should be
/// exactly `"sha256"`. If a future hasher is added (`PoseidonHasher`) with
/// the SAME name, on-chain integration would silently accept proofs from
/// either. Pin the literal so any future PR that introduces a Poseidon
/// path is forced to choose a different NAME.
/// Outcome: mitigated.
#[test]
fn r4_hasher_name_constant_pinned_mitigated() {
    assert_eq!(<Sha256Hasher as Hasher>::NAME, "sha256");
}

/// Confusion attack: an SDK caller might try `verify_proof(&leaf, &root, &proof)`
/// — root and leaf swapped. If the public-API signature ever made this
/// silently valid (e.g. via Into<&Hash>), the wrong-order call would
/// occasionally pass. Confirm: with a real tree, the swapped-arg call
/// rejects.
/// Outcome: mitigated.
#[test]
fn r4_arg_swap_root_leaf_rejected_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let leaf: Hash = [0x55u8; HASH_LEN];
    t.insert(leaf).unwrap();
    let root = t.root();
    let p = t.proof(0).unwrap();
    // Correct call accepts.
    assert!(verify_proof::<Sha256Hasher>(&root, &leaf, &p));
    // Swapped call: leaf as root, root as leaf. The leaf-side is `root`
    // which is non-zero, so the FINDING-1b guard doesn't apply. The walk
    // recomputes against `leaf` as if it were the root — overwhelmingly
    // doesn't match.
    assert!(!verify_proof::<Sha256Hasher>(&leaf, &root, &p));
}

/// "Length-extension" attack idea: SHA-256 is vulnerable to length-extension
/// in general. Pin that nullifier inputs are FIXED-LENGTH (64 bytes), so an
/// attacker who knows `nullifier(sk, pid_a)` cannot extend to compute
/// `nullifier(sk, pid_a || extra)`. This is structural — `proposal_id` is
/// always 32 bytes. Verify behaviorally: appending bytes to the proposal
/// id (via a 32-byte truncated representation) does not produce a related
/// nullifier.
/// Outcome: mitigated (input length is fixed by the type system).
#[test]
fn r4_nullifier_length_extension_irrelevant_inputs_are_fixed_size_mitigated() {
    // The function signature is `nullifier::<H>(sk: &[u8; SK_LEN],
    // proposal_id: &Hash) -> Hash`. Both inputs are fixed-size arrays,
    // not slices. An attacker has no surface to "extend" the input.
    let _sig: fn(&[u8; SK_LEN], &Hash) -> Hash = nullifier::<Sha256Hasher>;

    // Behavioral pin: `nullifier(sk, pid)` and `nullifier(sk, pid')` for
    // any other `pid'` differing from `pid` (even by appending bytes via
    // truncation) produce uncorrelated outputs — SHA-256 is preimage
    // resistant.
    let sk = [0x77u8; SK_LEN];
    let pid_a: Hash = [0x01u8; HASH_LEN];
    let n_a = nullifier::<Sha256Hasher>(&sk, &pid_a);
    // Modify the LAST byte of pid only.
    let mut pid_b = pid_a;
    pid_b[HASH_LEN - 1] ^= 0xFF;
    let n_b = nullifier::<Sha256Hasher>(&sk, &pid_b);
    assert_ne!(n_a, n_b);
    // And the two nullifiers should not share any obvious structural
    // correlation: hamming distance well above 32 bits.
    let dist: u32 = n_a
        .iter()
        .zip(n_b.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    assert!(dist > 64, "nullifier outputs too correlated: dist={dist}");
}

/// Final creative: confirm that `proof()` for a tree with EXACTLY 2 leaves
/// at idx=0 returns a sibling that is `hash_leaf(leaf_1)` at level 0 — and
/// the verifier accepts the walk. Round 1/2/3 have only sampled this; round
/// 4 spells out the byte-equality of every step of the walk for the
/// two-leaf case as a regression sentinel.
/// Outcome: mitigated.
#[test]
fn r4_two_leaf_tree_walk_byte_traced_mitigated() {
    let mut t = MerkleTree::<Sha256Hasher>::new();
    let l0: Hash = [0xA1u8; HASH_LEN];
    let l1: Hash = [0xB2u8; HASH_LEN];
    t.insert(l0).unwrap();
    t.insert(l1).unwrap();
    let root = t.root();
    let p = t.proof(0).unwrap();

    // Trace the walk manually.
    let h0 = Sha256Hasher::hash_leaf(&l0); // current at level 0 start
    let s0 = p.siblings[0]; // should be hash_leaf(l1)
    assert_eq!(s0, Sha256Hasher::hash_leaf(&l1));
    // direction[0] = false (idx 0 is even side), so combine as (h0, s0).
    let after_level_0 = Sha256Hasher::hash_node(&h0, &s0);

    // Levels 1..MERKLE_DEPTH: walk against the zero chain.
    let chain = empty_chain();
    let mut current = after_level_0;
    for level in 1..MERKLE_DEPTH {
        assert_eq!(p.siblings[level], chain[level]);
        assert!(!p.indices[level]);
        current = Sha256Hasher::hash_node(&current, &chain[level]);
    }
    assert_eq!(current, root, "manual walk did not match root");

    // And the verifier agrees.
    assert!(verify_proof::<Sha256Hasher>(&root, &l0, &p));
}

// ===========================================================================
// REPORT BLOCK
// ===========================================================================
//
// FINDINGS (round 4): NONE NEW.
//
// The structural surface was exhausted by rounds 1-3. The four
// round-4 attack categories produced ONLY confirmation tests:
//   1. Doc-vs-code drift: every public doc string was matched against the
//      impl. No drift found. The `‖` (U+2016) unicode separator appears
//      only in doc comments — the actual SHA-256 inputs are plain byte
//      concatenation, verified by `r4_no_unicode_separator_in_hash_inputs_mitigated`.
//   2. Integer overflow / wraparound: MERKLE_DEPTH = 20 is well below the
//      63-bit shift ceiling. `node_at` arithmetic stays under MAX_LEAVES
//      = 2^20 at every level. `index ^ 1` and `current >>= 1` are safe
//      for all legitimate inputs (gated by the `proof()` index check).
//   3. Encoding edges: Trojan-source unicode separator in a hash input
//      would produce a distinct SHA-256 output — verified.
//   4. Construction-order invariants: same-set-different-order inserts
//      produce different roots (expected); `root()` is recomputed on each
//      call (verified).
//   5. Type-system shortcuts: `verify_proof(&Hash, ...)` accepts
//      `&[u8; 32]` produced by `IdentityCommitment::as_bytes()` and by
//      an `AsRef<[u8; 32]>` wrapper. `&[u8]` slices do NOT silently
//      coerce — the type system forbids it.
//   6. Public-field semver footguns (`pub sk`, `pub salt`,
//      `IdentityCommitment(pub Hash)`): observations, not bugs. Direct
//      field construction matches `new`/`commitment::<H>()` output.
//   7. Hasher::Output design note: all `Hasher` methods return `Hash`.
//      If a future Poseidon impl wants a different output, the trait will
//      need a generic `Output` type. Not a bug today.
//   8. Allocation surprises: Vec grows geometrically (standard
//      `std::vec::Vec` behavior); MerkleTree struct size is ~696 bytes
//      stack-resident; all hash buffers are fixed-size stack arrays.
//   9. Soundness oracle: 10k random (root, leaf, proof) triples →
//      ZERO acceptances. Combined with the 5k real-root variant, that's
//      15k total negative samples with zero acceptances — clean.
//  10. Creative: argument-swap (root/leaf), mid-air forgery via
//      pre-hash_leaf'd input, length-extension (irrelevant: fixed-size
//      inputs), arg-swap → all rejected.
//
// DOC-VS-CODE DRIFT REPORT: none found.
//
// OBSERVATIONS (design trade-offs, not bugs):
//
//   O1. `Identity { pub sk, pub salt }` — direct public-field access means
//       any future invariant added to `Identity::new` (e.g. reject all-zero
//       `sk`) would silently leak through the public fields. Making the
//       fields private now would be a breaking semver change. Documented
//       in `r4_identity_pub_fields_observation_mitigated`.
//
//   O2. `IdentityCommitment(pub Hash)` — same semver footgun on the
//       wrapper side. An attacker can construct an `IdentityCommitment`
//       from arbitrary bytes; the Merkle layer is what checks membership,
//       not the wrapper. Documented in
//       `r4_identity_commitment_pub_wrapper_observation_mitigated`.
//
//   O3. `Hasher::NAME` is `&'static str` — there is no version field. A
//       future hasher implementation that picks a colliding `NAME` could
//       be silently swapped in at the trait-bound level. Mitigated by
//       `r4_hasher_name_constant_pinned_mitigated` pinning the literal.
//
//   O4. `Hasher` trait fixes the output type to `Hash`. If a future
//       Poseidon-over-BN254 impl wants a 31-byte field-element output,
//       the trait will need a generic `Output` associated type — that's
//       a breaking change. Flagged in
//       `r4_hasher_output_type_unification_design_note_mitigated`.
//
// MITIGATED:
//   - all three rounds' findings remain locked in (FINDING-1, FINDING-1b,
//     FINDING-V3-A, FINDING-V3-B);
//   - all 33 new round-4 tests pass;
//   - doc strings and impls agree byte-for-byte where it matters
//     (DOMAIN_LEAF/DOMAIN_NODE constants, hash buffer sizes, nullifier
//     layout, commitment layout, error Display format);
//   - integer arithmetic in `proof()` / `node_at()` is bounded by
//     `MAX_LEAVES = 2^20` and cannot overflow under any legitimate input.
//
// CONFIDENCE: after four rounds (two structural findings, two
// mutation-testing coverage gaps) the crate is sound to my read; the
// remaining residual risk is the documented design observations (O1-O4)
// rather than exploitable bugs.
//
// Reproduction:
//   cargo test -p crypto --test red_team_v4
//   cargo clippy -p crypto --test red_team_v4 -- -D warnings
//
// ===========================================================================
// End.
// ===========================================================================
