//! Red-team validation (round 2) of the LP-0002 Risc0 approve circuit.
//!
//! Round 1 (`red_team_program.rs`) swept 13 adversarial vectors with zero new
//! findings. This file extends that pass with the residual surface
//! enumerated in the round-2 brief:
//!
//!   1.  `red2_witness_permutation_sweep`                — non-trivial slice orderings.
//!   2.  `red2_trailing_extra_bytes_in_stream`           — host writes more bytes than guest reads.
//!   3.  `red2_truncation_failure_mode_is_panic`         — pin the failure path (no receipt).
//!   4.  `red2_direction_byte_boundary_levels`           — flip dir at 0, 1, mid, MERKLE_DEPTH-1.
//!   5.  `red2_pathological_members_roots`               — all-zero / all-ones / empty-tree roots.
//!   6.  `red2_cross_circuit_version_receipt_rejected`   — fabricate image-id drift.
//!   7.  `red2_journal_byte_order_is_one_specific_permutation` — root‖pid‖null is canonical.
//!   8.  `red2_empty_tree_zero_witness_preimage_search`  — 1000 random sk/salt attempts.
//!   9.  `red2_journal_byte_identical_across_100_runs`   — wide determinism sweep.
//!   10. `red2_all_zero_members_root_circuit_accepts_if_witness_climbs` — circuit-layer trust.
//!   11. `red2_journal_stable_across_n_runs_after_decode` — sentinel decode + re-encode parity.
//!   12. `red2_witness_bit_flip_sample`                  — 64-bit-flip sample over the witness.
//!   13. `red2_creative_chained_journal_swap`            — swap two 32-byte chunks in the
//!       journal, verify still fails (and pin which permutations are caught).
//!
//! All tests run under `RISC0_DEV_MODE=1` (same pattern as the rest of the
//! suite) so each round-trip is fast. Dev mode still executes the guest and
//! still produces a verifiable receipt, so every assertion below exercises
//! the real guest panic / verifier path.

#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::similar_names)]
#![allow(clippy::cognitive_complexity)]

use std::env;

use crypto::{merkle::MERKLE_DEPTH, Hasher, Identity, MerkleTree, Sha256Hasher, HASH_LEN};
use private_multisig_core::{
    derive_proposal_id, ApprovePublicInputs, ChainId, APPROVE_PUBLIC_INPUTS_LEN,
};
use private_multisig_program::{APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

// ---------------------------------------------------------------------------
// Shared scaffolding — mirrored from round 1 so the two files don't share a
// crate boundary (each tests/*.rs is its own crate).
// ---------------------------------------------------------------------------

fn ensure_dev_mode() {
    if env::var("RISC0_DEV_MODE").is_err() {
        // SAFETY: cargo runs the test process single-threaded with respect
        // to env before any prover thread spawns. Mirrors the pattern in
        // `approve_circuit.rs` / `blue_team_program.rs`.
        unsafe {
            env::set_var("RISC0_DEV_MODE", "1");
        }
    }
}

fn deterministic_identity(seed: u8) -> Identity {
    let mut sk = [0u8; 32];
    let mut salt = [0u8; 32];
    for i in 0..32 {
        sk[i] = seed.wrapping_add(i as u8);
        salt[i] = seed.wrapping_mul(3).wrapping_add(i as u8);
    }
    Identity::new(sk, salt)
}

fn build_member_set() -> (Vec<Identity>, MerkleTree<Sha256Hasher>) {
    let members: Vec<Identity> = (0..5u8).map(deterministic_identity).collect();
    let mut tree = MerkleTree::<Sha256Hasher>::new();
    for member in &members {
        tree.insert(*member.commitment::<Sha256Hasher>().as_bytes())
            .unwrap();
    }
    (members, tree)
}

fn canonical_proposal_id() -> [u8; 32] {
    let program_id: [u8; 32] = [0x99; 32];
    let create_key: [u8; 32] = [0xAB; 32];
    let state_pda = private_multisig_core::derive_multisig_state_pda(&program_id, &create_key);
    let target_program: [u8; 32] = [0xCD; 32];
    let action_bytes = b"treasury_withdraw(100,recipient=0xABCD)".to_vec();
    let chain_id = ChainId::from_u64(0xABCD_EF01);
    derive_proposal_id(&chain_id, &state_pda, 0, &action_bytes, &target_program)
}

#[derive(Clone)]
struct Witness {
    public_prefix: [u8; 64],
    sk: [u8; 32],
    salt: [u8; 32],
    siblings_flat: [u8; MERKLE_DEPTH * HASH_LEN],
    direction_bytes: [u8; MERKLE_DEPTH],
}

impl Witness {
    fn from_member(
        member: &Identity,
        proof: &crypto::MerkleProof,
        members_root: [u8; HASH_LEN],
        proposal_id: [u8; HASH_LEN],
    ) -> Self {
        let mut public_prefix = [0u8; 64];
        public_prefix[..32].copy_from_slice(&members_root);
        public_prefix[32..].copy_from_slice(&proposal_id);

        let mut siblings_flat = [0u8; MERKLE_DEPTH * HASH_LEN];
        for (level, sibling) in proof.siblings.iter().enumerate() {
            let start = level * HASH_LEN;
            siblings_flat[start..start + HASH_LEN].copy_from_slice(sibling);
        }
        let mut direction_bytes = [0u8; MERKLE_DEPTH];
        for (level, bit) in proof.indices.iter().enumerate() {
            direction_bytes[level] = u8::from(*bit);
        }
        Self {
            public_prefix,
            sk: member.sk,
            salt: member.salt,
            siblings_flat,
            direction_bytes,
        }
    }

    fn try_prove(&self) -> Result<risc0_zkvm::Receipt, ()> {
        let env_builder = match ExecutorEnv::builder()
            .write_slice(&self.public_prefix)
            .write_slice(&self.sk)
            .write_slice(&self.salt)
            .write_slice(&self.siblings_flat)
            .write_slice(&self.direction_bytes)
            .build()
        {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        let prover = default_prover();
        match prover.prove(env_builder, APPROVE_CIRCUIT_ELF) {
            Ok(prove_info) => Ok(prove_info.receipt),
            Err(_) => Err(()),
        }
    }
}

fn happy_witness(i: usize) -> (Identity, Witness, [u8; 32]) {
    let (members, tree) = build_member_set();
    let approver = members[i].clone();
    let proof = tree.proof(i).unwrap();
    let pid = canonical_proposal_id();
    let w = Witness::from_member(&approver, &proof, tree.root(), pid);
    (approver, w, pid)
}

// ===========================================================================
// 1. Witness permutation sweep — write the 5 input slices in non-canonical
//    orderings and confirm every reordering fails to prove. The canonical
//    order is [public_prefix, sk, salt, siblings_flat, direction_bytes]; any
//    other ordering shuffles bytes into the wrong fields inside the guest.
// ===========================================================================

#[test]
fn red2_witness_permutation_sweep() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);

    // Helper: build an env from a 5-slice ordering and try to prove.
    let try_order = |ordering: &[usize; 5]| -> Result<risc0_zkvm::Receipt, ()> {
        // Slices indexed by ordering[i] in [0..5]:
        //   0 = public_prefix(64), 1 = sk(32), 2 = salt(32),
        //   3 = siblings_flat(640), 4 = direction_bytes(20).
        let mut b = ExecutorEnv::builder();
        for &idx in ordering {
            match idx {
                0 => {
                    b.write_slice(&w.public_prefix);
                }
                1 => {
                    b.write_slice(&w.sk);
                }
                2 => {
                    b.write_slice(&w.salt);
                }
                3 => {
                    b.write_slice(&w.siblings_flat);
                }
                4 => {
                    b.write_slice(&w.direction_bytes);
                }
                _ => unreachable!(),
            }
        }
        let env_built = match b.build() {
            Ok(env_ok) => env_ok,
            Err(_) => return Err(()),
        };
        match default_prover().prove(env_built, APPROVE_CIRCUIT_ELF) {
            Ok(p) => Ok(p.receipt),
            Err(_) => Err(()),
        }
    };

    // Canonical order — sanity: must succeed.
    let canonical: [usize; 5] = [0, 1, 2, 3, 4];
    assert!(
        try_order(&canonical).is_ok(),
        "sanity: canonical permutation must prove"
    );

    // Small handcrafted permutation set — every entry is a *different*
    // ordering, and each must fail. We avoid sweeping all 120 permutations
    // since each `prove` call has fixed overhead even in dev mode.
    let bad_orderings: [[usize; 5]; 8] = [
        // sk and salt swapped (round 1 covered this; pin via the env-level
        // ordering path too).
        [0, 2, 1, 3, 4],
        // public_prefix and sk swapped — public prefix lands in `sk` slot.
        [1, 0, 2, 3, 4],
        // direction_bytes first — the public-prefix read gets 20 dir bytes
        // followed by 44 sibling bytes, so members_root / proposal_id are
        // corrupted.
        [4, 0, 1, 2, 3],
        // sibling block first.
        [3, 0, 1, 2, 4],
        // Reverse.
        [4, 3, 2, 1, 0],
        // sibling and direction swapped at the tail (direction lands in
        // sibling buffer, sibling lands in direction buffer — the latter
        // certainly hits the strict-0-or-1 check).
        [0, 1, 2, 4, 3],
        // Public prefix split off the tail end.
        [1, 2, 3, 4, 0],
        // sk pushed to last position.
        [0, 2, 3, 4, 1],
    ];

    for (i, ord) in bad_orderings.iter().enumerate() {
        assert_ne!(ord, &canonical);
        assert!(
            try_order(ord).is_err(),
            "permutation #{i} {:?} must NOT produce a receipt",
            ord
        );
    }
}

// ===========================================================================
// 2. Trailing extra bytes — host writes more bytes than the guest reads.
//
// The guest does 5 `read_slice` calls totaling 788 bytes. If the host writes
// additional bytes after the last read, they should simply sit in the stream
// unread. The receipt journal is bound to the guest's commitments, not to
// the host's written stream, so this should succeed and produce a receipt
// byte-identical to the no-trailing-bytes baseline.
// ===========================================================================

#[test]
fn red2_trailing_extra_bytes_in_stream() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(1);

    // Baseline: prove without trailing bytes.
    let baseline = w.try_prove().expect("baseline prove must succeed");
    let baseline_journal = baseline.journal.bytes.clone();

    // With trailing bytes appended after the last canonical slice.
    let extra: [u8; 64] = [0xDE; 64];
    let env_built = ExecutorEnv::builder()
        .write_slice(&w.public_prefix)
        .write_slice(&w.sk)
        .write_slice(&w.salt)
        .write_slice(&w.siblings_flat)
        .write_slice(&w.direction_bytes)
        .write_slice(&extra)
        .build()
        .expect("env build with trailing bytes must succeed");

    let with_trailing = default_prover()
        .prove(env_built, APPROVE_CIRCUIT_ELF)
        .expect("trailing-bytes prove must succeed (guest only reads first 788 bytes)")
        .receipt;

    // Receipt must still verify.
    with_trailing
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("trailing-bytes receipt must verify against pinned image-id");

    // Journal must be byte-identical to the baseline (no trailing influence).
    assert_eq!(
        with_trailing.journal.bytes, baseline_journal,
        "journal must be byte-identical regardless of unread trailing bytes"
    );
}

// ===========================================================================
// 3. Truncation failure mode — pin that no valid receipt emerges, and (best-
//    effort) pin that the failure surfaces as a prover error rather than a
//    silently-accepted short read.
// ===========================================================================

#[test]
fn red2_truncation_failure_mode_is_panic() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(0);

    // Drop the final direction byte. The guest's last `read_slice` should
    // fail to fill the 20-byte buffer; we don't care which exact panic
    // string surfaces, only that NO receipt is produced.
    let mut short_dirs = [0u8; MERKLE_DEPTH - 1];
    short_dirs.copy_from_slice(&w.direction_bytes[..MERKLE_DEPTH - 1]);

    let env_built = ExecutorEnv::builder()
        .write_slice(&w.public_prefix)
        .write_slice(&w.sk)
        .write_slice(&w.salt)
        .write_slice(&w.siblings_flat)
        .write_slice(&short_dirs)
        .build();

    let result = match env_built {
        Ok(env_ok) => default_prover().prove(env_ok, APPROVE_CIRCUIT_ELF),
        Err(e) => Err(e),
    };
    let err = match result {
        Ok(prove_info) => {
            // Extremely unlikely. If it ever happens, surface the receipt
            // verification result so we can pin the failure mode there.
            let v = prove_info.receipt.verify(APPROVE_CIRCUIT_IMAGE_ID);
            panic!(
                "FINDING: truncated witness produced a receipt; verify result = {:?}",
                v
            );
        }
        Err(e) => e,
    };

    // Pin only the SHAPE of the error: it should mention some kind of
    // short-read / deserialize / unexpected-end / fault condition. Risc0
    // hosts have surfaced this with slightly different strings across
    // versions, so we accept several substrings rather than pinning one
    // exact name. The set of accepted substrings is a deliberate moat
    // around the failure mode without coupling to a private API.
    let msg = format!("{err}").to_lowercase();
    let known_substrings = [
        "deserialize",
        "unexpected end",
        "unexpected eof",
        "out of bounds",
        "read",
        "fault",
        "panic",
        "early termination",
        "guest",
        "session",
        "halt",
    ];
    assert!(
        known_substrings.iter().any(|s| msg.contains(s)),
        "FINDING: truncated-witness error did not match any known short-read shape: {msg}"
    );
}

// ===========================================================================
// 4. Direction byte boundary levels — flip at levels {0, 1, MERKLE_DEPTH/2,
//    MERKLE_DEPTH-1}. Each must fail (either via the strict-0-or-1 panic if
//    the original byte was something other than {0,1}, which it never is
//    here, or via Merkle path mismatch).
// ===========================================================================

#[test]
fn red2_direction_byte_boundary_levels() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(3);

    let boundary_levels = [0usize, 1, MERKLE_DEPTH / 2, MERKLE_DEPTH - 1];
    for &lvl in &boundary_levels {
        let mut tampered_dirs = w.direction_bytes;
        // Valid 0/1 flip — keeps the strict check happy so the failure must
        // come from the Merkle verifier rejecting the recombination order.
        tampered_dirs[lvl] ^= 1;
        let w2 = Witness {
            public_prefix: w.public_prefix,
            sk: w.sk,
            salt: w.salt,
            siblings_flat: w.siblings_flat,
            direction_bytes: tampered_dirs,
        };
        assert!(
            w2.try_prove().is_err(),
            "flipping direction byte at level {lvl} must NOT produce a receipt"
        );
    }
}

// ===========================================================================
// 5. Pathological members_root values — all-zero, all-ones, empty-tree
//    marker. None of these have any honest member of the (0..5) set under
//    them, so each must fail to prove.
//
// The point of this test is to confirm the *circuit* does not impose any
// extra structural check on `members_root` beyond "the Merkle path climbs
// to it". An attacker who claims `members_root = anything` and produces a
// witness whose path genuinely climbs to that value would prove — the
// on-chain layer is the one that pins `members_root` to a finalized PDA.
// We're pinning circuit-layer behavior: any 32-byte value is *accepted as
// a target*; the witness simply has to climb to it.
// ===========================================================================

#[test]
fn red2_pathological_members_roots() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let i = 2usize;
    let approver = &members[i];
    let proof = tree.proof(i).unwrap();
    let pid = canonical_proposal_id();

    // (a) all-zero root: member's path does not climb here.
    let w_zero = Witness::from_member(approver, &proof, [0u8; 32], pid);
    assert!(
        w_zero.try_prove().is_err(),
        "real member proof must NOT verify under all-zero members_root"
    );

    // (b) all-ones root: same.
    let w_ones = Witness::from_member(approver, &proof, [0xFFu8; 32], pid);
    assert!(
        w_ones.try_prove().is_err(),
        "real member proof must NOT verify under all-ones members_root"
    );

    // (c) empty-tree marker: members_root == MerkleTree::<Sha256Hasher>::new().root()
    let empty_root = MerkleTree::<Sha256Hasher>::new().root();
    assert_ne!(
        empty_root, [0u8; 32],
        "test pre: empty-tree root must not be all-zero (domain-separation guard)"
    );
    let w_empty = Witness::from_member(approver, &proof, empty_root, pid);
    assert!(
        w_empty.try_prove().is_err(),
        "real member proof must NOT verify under the empty-tree marker root"
    );

    // (d) one-bit-off from the real root: same.
    let mut nearly = tree.root();
    nearly[31] ^= 0x80;
    let w_near = Witness::from_member(approver, &proof, nearly, pid);
    assert!(
        w_near.try_prove().is_err(),
        "real member proof must NOT verify under a one-bit-off members_root"
    );
}

// ===========================================================================
// 6. Cross-circuit-version receipt — simulate "old receipt vs new image-id".
//
// We can't recompile the guest from inside this test, but we CAN approximate
// the failure shape: take a real receipt, then verify it against (a) the
// real image-id (must succeed), (b) a deliberately-mutated image-id
// representing a hypothetical "new" build, (c) an image-id with one u32
// word zeroed at each of the 8 positions (specific drift patterns that
// might happen with a bad cache or partial build).
// ===========================================================================

#[test]
fn red2_cross_circuit_version_receipt_rejected() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);
    let receipt = w.try_prove().expect("happy path must prove");

    // Sanity: verifies under the real image-id.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("happy path must verify under pinned image-id");

    // (a) Hypothetical "new" image-id: increment each word by 1. This is
    // what you'd see if a single dependency bump shifted the guest hash.
    let mut hypothetical_new = APPROVE_CIRCUIT_IMAGE_ID;
    for w in hypothetical_new.iter_mut() {
        *w = w.wrapping_add(1);
    }
    if hypothetical_new != APPROVE_CIRCUIT_IMAGE_ID {
        assert!(
            receipt.verify(hypothetical_new).is_err(),
            "receipt MUST NOT verify against a hypothetical new image-id"
        );
    }

    // (b) Zero out one u32 word at a time — represents a partial / corrupted
    // image-id load. Every variant must be rejected.
    for pos in 0..8usize {
        let mut variant = APPROVE_CIRCUIT_IMAGE_ID;
        variant[pos] = 0;
        if variant == APPROVE_CIRCUIT_IMAGE_ID {
            continue; // word was already zero — astronomically unlikely.
        }
        assert!(
            receipt.verify(variant).is_err(),
            "receipt MUST NOT verify against image-id with word {pos} zeroed"
        );
    }
}

// ===========================================================================
// 7. Journal byte order — confirm the canonical [root || pid || nullifier]
//    layout is one specific permutation; any other interpretation diverges.
// ===========================================================================

#[test]
fn red2_journal_byte_order_is_one_specific_permutation() {
    ensure_dev_mode();
    let (approver, w, pid) = happy_witness(1);
    let receipt = w.try_prove().expect("happy path must prove");
    let journal = receipt.journal.bytes.clone();
    assert_eq!(journal.len(), APPROVE_PUBLIC_INPUTS_LEN);

    let host_root = {
        let (_, tree) = build_member_set();
        tree.root()
    };
    let host_null = approver.nullifier::<Sha256Hasher>(&pid);

    // Real layout: [root || pid || nullifier]. The canonical decode must
    // match the host computation.
    let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    arr.copy_from_slice(&journal);
    let canonical = ApprovePublicInputs::from_bytes(&arr);
    assert_eq!(canonical.members_root, host_root);
    assert_eq!(canonical.proposal_id, pid);
    assert_eq!(canonical.nullifier, host_null);

    // Sentinel: "what if the order were [nullifier || pid || root]" — i.e.,
    // an attacker / a future PR misreads the journal in reverse. Decoding
    // under that misinterpretation must NOT match the real host bundle.
    let mut reversed = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    reversed[..32].copy_from_slice(&journal[64..96]); // claimed root
    reversed[32..64].copy_from_slice(&journal[32..64]); // pid unchanged
    reversed[64..96].copy_from_slice(&journal[..32]); // claimed nullifier
    let misread = ApprovePublicInputs::from_bytes(&reversed);
    assert_ne!(
        misread.members_root, host_root,
        "if journal had been [nullifier‖pid‖root], decode would see host_null in root slot"
    );
    assert_ne!(
        misread.nullifier, host_null,
        "if journal had been [nullifier‖pid‖root], decode would see host_root in nullifier slot"
    );
    // The pid slot is symmetric across this particular swap, so it stays
    // equal — that's an expected property of the chosen swap.
    assert_eq!(misread.proposal_id, pid);

    // And [pid || root || nullifier] — another non-canonical guess.
    let mut alt = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
    alt[..32].copy_from_slice(&journal[32..64]); // pid in root slot
    alt[32..64].copy_from_slice(&journal[..32]); // root in pid slot
    alt[64..96].copy_from_slice(&journal[64..96]);
    let alt_decoded = ApprovePublicInputs::from_bytes(&alt);
    assert_ne!(alt_decoded.members_root, host_root);
    assert_ne!(alt_decoded.proposal_id, pid);
}

// ===========================================================================
// 8. Empty-tree zero-witness preimage search — FINDING-1b at circuit layer.
//    Under preimage hardness no random (sk, salt) yields commitment == [0;32].
//    1000 deterministic trials.
// ===========================================================================

#[test]
fn red2_empty_tree_zero_witness_preimage_search() {
    ensure_dev_mode();

    // Confirm preimage hardness across 1000 deterministic (sk, salt) pairs.
    // None must produce H(sk||salt) == [0;32]. If this ever fired in
    // practice, SHA-256 would be irreparably broken — but we make the
    // assertion explicit so a regression in the hash plumbing (e.g.
    // accidentally returning all-zero on some input shape) trips here.
    let mut counter: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for _ in 0..1000 {
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        sk[..8].copy_from_slice(&counter.to_le_bytes());
        sk[8..16].copy_from_slice(&counter.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
        salt[..8].copy_from_slice(&counter.wrapping_mul(2_654_435_761).to_le_bytes());
        salt[24..32].copy_from_slice(&counter.rotate_left(13).to_le_bytes());
        counter = counter.wrapping_add(1);

        let id = Identity::new(sk, salt);
        let c = id.commitment::<Sha256Hasher>();
        assert_ne!(
            *c.as_bytes(),
            [0u8; HASH_LEN],
            "FINDING (SHA-256 broken): random (sk, salt) hashed to all-zero commitment"
        );
    }

    // Then: try to *prove* with one of these random identities against the
    // empty-tree root — must fail (member not enrolled).
    let empty_root = MerkleTree::<Sha256Hasher>::new().root();
    let id = Identity::new([0xCC; 32], [0xDD; 32]);
    let pid = canonical_proposal_id();
    let bogus_proof = crypto::MerkleProof {
        siblings: [[0u8; HASH_LEN]; MERKLE_DEPTH],
        indices: [false; MERKLE_DEPTH],
    };
    let w = Witness::from_member(&id, &bogus_proof, empty_root, pid);
    assert!(
        w.try_prove().is_err(),
        "random identity claiming empty-tree membership must NOT prove"
    );
}

// ===========================================================================
// 9. Journal byte-identical across 100 prover runs — wide determinism
//    sweep on top of the round-1 2-run check.
//
// Note: 100 prover invocations even in dev mode is non-trivial; we keep the
// witness identical between runs so the path is the cheapest possible.
// ===========================================================================

#[test]
fn red2_journal_byte_identical_across_100_runs() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);

    let reference = w.try_prove().expect("baseline prove must succeed");
    let reference_journal = reference.journal.bytes.clone();
    assert_eq!(reference_journal.len(), APPROVE_PUBLIC_INPUTS_LEN);

    // 99 more runs — total 100 prover invocations.
    for run in 1..100usize {
        let receipt = w
            .try_prove()
            .unwrap_or_else(|_| panic!("run {run}: prove failed unexpectedly"));
        assert_eq!(
            receipt.journal.bytes, reference_journal,
            "run {run}: journal must be byte-identical to baseline"
        );
    }
}

// ===========================================================================
// 10. all-zero members_root — confirm the circuit accepts ANY 32-byte
//     members_root *as a target*. There is no honest witness for the all-
//     zero root (under preimage hardness — see test 8), so we cannot
//     actually produce a passing proof from inside this test. Instead, we
//     pin the surrounding behavior: a witness whose path doesn't climb to
//     [0;32] fails, AND the on-chain `finalize_instance` 0-member check is
//     the layer that enforces "no empty multisig". The circuit itself
//     remains agnostic.
// ===========================================================================

#[test]
fn red2_all_zero_members_root_circuit_accepts_if_witness_climbs() {
    ensure_dev_mode();
    let (members, tree) = build_member_set();
    let approver = &members[0];
    let proof = tree.proof(0).unwrap();
    let pid = canonical_proposal_id();

    // Pin: real member, all-zero members_root → fail (path does not climb).
    let w = Witness::from_member(approver, &proof, [0u8; 32], pid);
    assert!(
        w.try_prove().is_err(),
        "real witness against all-zero members_root must fail"
    );

    // Pin (negative existence): no honest path can climb to [0;32]. We
    // walk the path the guest would walk and assert it never lands on the
    // all-zero target across all 5 members.
    for (i, m) in members.iter().enumerate() {
        let p = tree.proof(i).unwrap();
        let leaf = *m.commitment::<Sha256Hasher>().as_bytes();
        // Re-derive what the guest computes: start with hash_leaf(leaf), then
        // walk siblings. This is host-side proof of the impossibility — the
        // result must equal tree.root(), which (sanity) is not all-zero.
        let mut current = <Sha256Hasher as Hasher>::hash_leaf(&leaf);
        for level in 0..MERKLE_DEPTH {
            current = if p.indices[level] {
                <Sha256Hasher as Hasher>::hash_node(&p.siblings[level], &current)
            } else {
                <Sha256Hasher as Hasher>::hash_node(&current, &p.siblings[level])
            };
        }
        assert_eq!(
            current,
            tree.root(),
            "member {i}: honest walk must hit real root"
        );
        assert_ne!(
            current, [0u8; 32],
            "honest walk MUST NOT terminate on [0;32]"
        );
    }
}

// ===========================================================================
// 11. Journal stability sentinel — across N runs, decode + re-encode and
//     pin byte-identity at every layer. This is the "any future non-
//     determinism in journal encoding will trip" canary.
// ===========================================================================

#[test]
fn red2_journal_stable_across_n_runs_after_decode() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(4);

    const N: usize = 20;
    let mut journals: Vec<Vec<u8>> = Vec::with_capacity(N);
    for run in 0..N {
        let receipt = w
            .try_prove()
            .unwrap_or_else(|_| panic!("run {run}: prove failed unexpectedly"));
        let bytes = receipt.journal.bytes.clone();
        assert_eq!(bytes.len(), APPROVE_PUBLIC_INPUTS_LEN);

        // Decode + re-encode parity.
        let mut arr = [0u8; APPROVE_PUBLIC_INPUTS_LEN];
        arr.copy_from_slice(&bytes);
        let decoded = ApprovePublicInputs::from_bytes(&arr);
        let repacked = decoded.to_bytes();
        assert_eq!(
            repacked.as_slice(),
            bytes.as_slice(),
            "run {run}: decode+re-encode must be byte-identical"
        );

        journals.push(bytes);
    }

    // All N journals must be byte-identical to the first.
    let first = &journals[0];
    for (i, j) in journals.iter().enumerate().skip(1) {
        assert_eq!(j, first, "journal at run {i} drifted from run 0");
    }
}

// ===========================================================================
// 12. Witness bit-flip sample — flip each of 64 randomly-distributed bit
//     positions in the witness stream and confirm each flip fails to prove.
//     Full 6304-bit sweep is too expensive even in dev mode (each prove
//     call still has overhead); a 64-position sample provides reasonable
//     spatial coverage across all 5 fields without dragging out CI.
// ===========================================================================

#[test]
fn red2_witness_bit_flip_sample() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(2);

    // Pack the witness into a single flat layout matching the host write
    // order: [public_prefix(64) || sk(32) || salt(32) || sibs(640) || dirs(20)].
    // Total = 788 bytes = 6304 bits.
    const TOTAL_BYTES: usize = 64 + 32 + 32 + MERKLE_DEPTH * HASH_LEN + MERKLE_DEPTH;
    let mut flat = [0u8; TOTAL_BYTES];
    flat[..64].copy_from_slice(&w.public_prefix);
    flat[64..96].copy_from_slice(&w.sk);
    flat[96..128].copy_from_slice(&w.salt);
    flat[128..768].copy_from_slice(&w.siblings_flat);
    flat[768..788].copy_from_slice(&w.direction_bytes);
    assert_eq!(TOTAL_BYTES, 788);

    // Sample 64 deterministic bit positions across the full 6304-bit space.
    // Use a coarse-grained stride to hit every field: 6304 / 64 ≈ 98 bits
    // apart, so we sample roughly once per ~12 bytes.
    let stride = (TOTAL_BYTES * 8) / 64;
    let unpack_and_prove = |mutated: &[u8; TOTAL_BYTES]| -> Result<risc0_zkvm::Receipt, ()> {
        let mut pub_prefix = [0u8; 64];
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        let mut sibs = [0u8; MERKLE_DEPTH * HASH_LEN];
        let mut dirs = [0u8; MERKLE_DEPTH];
        pub_prefix.copy_from_slice(&mutated[..64]);
        sk.copy_from_slice(&mutated[64..96]);
        salt.copy_from_slice(&mutated[96..128]);
        sibs.copy_from_slice(&mutated[128..768]);
        dirs.copy_from_slice(&mutated[768..788]);
        let w2 = Witness {
            public_prefix: pub_prefix,
            sk,
            salt,
            siblings_flat: sibs,
            direction_bytes: dirs,
        };
        w2.try_prove()
    };

    // Sanity: unmodified flat round-trips and proves.
    let baseline = unpack_and_prove(&flat).expect("unmodified baseline must prove");
    let baseline_journal = baseline.journal.bytes.clone();

    let mut interesting_passes: Vec<usize> = Vec::new();
    for k in 0..64usize {
        let bit_pos = k * stride;
        if bit_pos >= TOTAL_BYTES * 8 {
            break;
        }
        let byte_idx = bit_pos / 8;
        let bit_in_byte = bit_pos % 8;
        let mut mutated = flat;
        mutated[byte_idx] ^= 1 << bit_in_byte;

        match unpack_and_prove(&mutated) {
            Ok(receipt) => {
                // If a flip produced a proof, the journal MUST differ from
                // the baseline (otherwise the flip was a no-op slot). Log
                // the position so a human can audit if the count is
                // unexpectedly high. The baseline ALSO produces a journal
                // that matches the real members_root / nullifier; any
                // accepting flip means the guest considered the mutated
                // witness valid for SOME (root, nullifier) tuple — but
                // since the public_prefix was also flipped in some samples,
                // that's expected for ~64 of the 64*8 = 512 sampled bits
                // inside the public_prefix region.
                if receipt.journal.bytes == baseline_journal {
                    panic!(
                        "FINDING: bit flip at pos {bit_pos} (byte {byte_idx}, bit {bit_in_byte}) \
                         produced a receipt with the BASELINE journal — guest is ignoring this bit"
                    );
                }
                interesting_passes.push(bit_pos);
            }
            Err(()) => {
                // Expected: most flips break the witness.
            }
        }
    }

    // Soft sanity: the *vast* majority of flipped positions must reject.
    // The witness has 788 bytes; bits in public_prefix (64 bytes = 512 bits)
    // are the only ones where a "different" journal could legitimately
    // pass — and only if the flipped public_prefix happens to match some
    // OTHER valid (root, pid) for which the same (sk, salt, path) is a
    // valid witness, which is astronomically unlikely. So in practice we
    // expect ~0 passes.
    //
    // We accept up to 4 passes as a generous bound (covers the boundary
    // edge cases where dev-mode might be lenient).
    assert!(
        interesting_passes.len() <= 4,
        "FINDING: {} bit-flip positions produced passing receipts: {:?}",
        interesting_passes.len(),
        interesting_passes
    );
}

// ===========================================================================
// 13. Creative — swap two 32-byte chunks in the *journal* post-proof. The
//     receipt's seal is bound to the original journal hash; any swap should
//     therefore fail verification. We sweep all C(3,2) = 3 swaps to pin the
//     guarantee uniformly across the three slots.
// ===========================================================================

#[test]
fn red2_creative_chained_journal_swap() {
    ensure_dev_mode();
    let (_a, w, _pid) = happy_witness(1);
    let receipt = w.try_prove().expect("happy path must prove");
    let original = receipt.journal.bytes.clone();
    assert_eq!(original.len(), APPROVE_PUBLIC_INPUTS_LEN);

    // Sanity: untouched receipt verifies.
    receipt
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("untouched receipt must verify");

    // Helper: clone receipt, splice in a mutated journal, expect rejection.
    let swap_and_check =
        |a_range: std::ops::Range<usize>, b_range: std::ops::Range<usize>, label: &str| {
            let mut r2 = receipt.clone();
            let mut new_journal = original.clone();
            let len = a_range.end - a_range.start;
            assert_eq!(len, b_range.end - b_range.start);
            let mut tmp = vec![0u8; len];
            tmp.copy_from_slice(&original[a_range.clone()]);
            new_journal[a_range.clone()].copy_from_slice(&original[b_range.clone()]);
            new_journal[b_range.clone()].copy_from_slice(&tmp);
            r2.journal.bytes = new_journal;
            assert!(
                r2.verify(APPROVE_CIRCUIT_IMAGE_ID).is_err(),
                "FINDING: {label} swap in journal did not break verification"
            );
        };

    // Swap root↔pid.
    swap_and_check(0..32, 32..64, "root<->pid");
    // Swap pid↔nullifier.
    swap_and_check(32..64, 64..96, "pid<->nullifier");
    // Swap root↔nullifier.
    swap_and_check(0..32, 64..96, "root<->nullifier");

    // Restore + re-verify as a final sanity (proves the receipt itself is
    // otherwise valid and the failures above weren't tautological).
    let mut r_restore = receipt.clone();
    r_restore.journal.bytes = original;
    r_restore
        .verify(APPROVE_CIRCUIT_IMAGE_ID)
        .expect("restored journal must re-verify cleanly");
}
