//! Host-side program crate for LP-0002 Private M-of-N Multisig.
//!
//! ## What this crate exposes
//!
//! - `APPROVE_CIRCUIT_ELF`, `APPROVE_CIRCUIT_IMAGE_ID` — Risc0 artifacts
//!   for the inner ZK approval circuit
//! - `VERIFIER_PROGRAM_ELF`, `VERIFIER_PROGRAM_IMAGE_ID` — Risc0
//!   artifacts for the SPEL verifier program. Used by the step-7 e2e
//!   harness to drive the outer prover in-process so it can discharge
//!   the inner approve receipt's composition assumption.
//! - `image_id_hex()` — release-note / pin-by-string helper
//! - `APPROVE_WITNESS_LEN`, `pack_approve_witness(…)` — the canonical
//!   host → guest wire format helper
//!
//! Re-exports the Risc0 guest image-id and ELF under typed names so the SDK
//! and the verifier program can talk about "the approve circuit" without
//! threading the `methods` crate name everywhere. PLAN.md step 4 references
//! `APPROVE_CIRCUIT_IMAGE_ID` from this crate.
//!
//! The image-id is a build-time constant: `methods/build.rs` invokes
//! `risc0_build::embed_methods()` which compiles `methods/guest/` under the
//! Risc0 RISC-V toolchain and hashes the resulting ELF. Any change to the
//! guest source — or to `crypto` / `private_multisig_core` items the guest
//! pulls in — yields a different image-id. Pinning a hex of the current
//! image-id elsewhere (e.g. in an on-chain `MultisigState` field, in a
//! release-notes table, etc.) is what binds an on-chain instance to one
//! specific circuit version.

/// Compiled RISC-V ELF bytes of the approve circuit. Hand to
/// `risc0_zkvm::default_executor()` / the prover.
pub const APPROVE_CIRCUIT_ELF: &[u8] = methods::APPROVE_CIRCUIT_ELF;

/// Image ID of the approve circuit — 8 little-endian u32 words (256 bits)
/// that uniquely identify this version of the guest binary. The verifier
/// program checks every receipt against this image-id; a receipt produced
/// by any other guest is rejected with `E2001 ImageIdMismatch`.
pub const APPROVE_CIRCUIT_IMAGE_ID: [u32; 8] = methods::APPROVE_CIRCUIT_ID;

/// Compiled RISC-V ELF bytes of the SPEL verifier program. Hand to
/// `risc0_zkvm::default_prover()` when the step-7 e2e harness needs to
/// produce an outer receipt locally — passing `inner_approve_receipt`
/// via `ExecutorEnv::add_assumption` discharges the verifier's
/// `env::verify(APPROVE_CIRCUIT_IMAGE_ID, public_inputs)` composition
/// assumption.
pub const VERIFIER_PROGRAM_ELF: &[u8] = methods::PRIVATE_MULTISIG_ELF;

/// Image ID of the SPEL verifier program. Pin alongside the `approve`
/// circuit's image-id whenever the on-chain ABI is snapshotted — a
/// verifier-source change without a coordinated `APPROVE_CIRCUIT_IMAGE_ID`
/// re-snapshot would silently land a receipt-validation drift.
pub const VERIFIER_PROGRAM_IMAGE_ID: [u32; 8] = methods::PRIVATE_MULTISIG_ID;

/// True iff the guest ELFs above came from a reproducible Docker build
/// (`RISC0_USE_DOCKER=1`). Re-exported from the `methods` crate so the
/// drift-sentinel tests in `tests/image_id_stability.rs` and
/// `tests/blue_team_program_v3.rs` can skip themselves when running against
/// a host build (whose image-id is intentionally path-dependent and won't
/// match the canonical pins).
pub const BUILD_USED_DOCKER: bool = methods::BUILD_USED_DOCKER;

/// Hex-encoded helper: returns the image-id as a 64-char lowercase hex
/// string suitable for embedding in release notes or pinning in
/// integration tests. Stable as long as `APPROVE_CIRCUIT_IMAGE_ID` is.
pub fn image_id_hex() -> String {
    let mut out = String::with_capacity(64);
    for word in APPROVE_CIRCUIT_IMAGE_ID {
        // The image-id words are stored in little-endian on Risc0 host;
        // serialize byte-by-byte from `to_le_bytes` so the hex matches the
        // canonical wire representation.
        for b in word.to_le_bytes() {
            use core::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
    }
    out
}

/// Total wire size of the host → guest witness stream for the approve
/// circuit, in bytes:
///
/// ```text
/// public_prefix(64) ‖ sk(32) ‖ salt(32) ‖ siblings_flat(20×32 = 640) ‖ directions(20) = 788
/// ```
///
/// Pinned here so the SDK can size its buffer once and so any future
/// refactor that grows or shrinks the witness wire breaks loudly.
pub const APPROVE_WITNESS_LEN: usize = 788;

/// Pack a witness for the approve circuit into the canonical 788-byte
/// wire format the guest expects.
///
/// The byte layout is:
///
/// ```text
/// [0..32)    members_root
/// [32..64)   proposal_id
/// [64..96)   sk        ── the approving member's secret
/// [96..128)  salt      ── the approving member's commitment salt
/// [128..768) siblings_flat  ── 20 × 32 bytes, level-0 first
/// [768..788) directions     ── 20 bytes, each 0 or 1, level-0 first
/// ```
///
/// Hand the result to `ExecutorEnv::builder().write_slice(&witness)` once
/// (or write each named slice five times in the same order — both produce
/// identical journals, see `witness_wire_format::wire_round_trip_repack_via_independent_packer`).
///
/// `members_root` and `proposal_id` are typically computed via
/// `private_multisig_core` (`MerkleTree::root` and `derive_proposal_id`
/// respectively).
pub fn pack_approve_witness(
    identity: &crypto::Identity,
    proof: &crypto::MerkleProof,
    members_root: &[u8; 32],
    proposal_id: &[u8; 32],
) -> [u8; APPROVE_WITNESS_LEN] {
    let mut out = [0u8; APPROVE_WITNESS_LEN];
    out[..32].copy_from_slice(members_root);
    out[32..64].copy_from_slice(proposal_id);
    out[64..96].copy_from_slice(&identity.sk);
    out[96..128].copy_from_slice(&identity.salt);
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let start = 128 + level * 32;
        out[start..start + 32].copy_from_slice(sibling);
    }
    for (level, bit) in proof.indices.iter().enumerate() {
        out[768 + level] = u8::from(*bit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_id_is_non_zero() {
        // A freshly-compiled image cannot have an all-zero id without
        // SHA-256 producing a zero digest on the ELF (preimage-hard).
        assert_ne!(APPROVE_CIRCUIT_IMAGE_ID, [0u32; 8]);
    }

    #[test]
    fn image_id_hex_is_64_lowercase_hex_chars() {
        let s = image_id_hex();
        assert_eq!(s.len(), 64);
        for c in s.chars() {
            assert!(
                c.is_ascii_digit() || ('a'..='f').contains(&c),
                "unexpected char {c}"
            );
        }
    }

    #[test]
    fn elf_is_non_empty() {
        assert!(
            !APPROVE_CIRCUIT_ELF.is_empty(),
            "approve_circuit ELF must not be empty"
        );
    }

    #[test]
    fn approve_witness_len_pinned_at_788_bytes() {
        // 64 (prefix) + 32 (sk) + 32 (salt) + 20*32 (siblings) + 20 (directions)
        assert_eq!(APPROVE_WITNESS_LEN, 64 + 32 + 32 + 20 * 32 + 20);
        assert_eq!(APPROVE_WITNESS_LEN, 788);
    }

    #[test]
    fn pack_approve_witness_layout_pins_each_slot() {
        let identity = crypto::Identity::new([0xAA; 32], [0xBB; 32]);
        let mut siblings = [[0u8; 32]; crypto::MERKLE_DEPTH];
        for (i, sib) in siblings.iter_mut().enumerate() {
            sib[0] = i as u8;
        }
        let mut indices = [false; crypto::MERKLE_DEPTH];
        indices[0] = true;
        indices[3] = true;
        let proof = crypto::MerkleProof { siblings, indices };
        let members_root = [0xCC; 32];
        let proposal_id = [0xDD; 32];

        let buf = pack_approve_witness(&identity, &proof, &members_root, &proposal_id);

        assert_eq!(buf.len(), APPROVE_WITNESS_LEN);
        assert_eq!(&buf[..32], &members_root);
        assert_eq!(&buf[32..64], &proposal_id);
        assert_eq!(&buf[64..96], &identity.sk);
        assert_eq!(&buf[96..128], &identity.salt);
        // Level-0 sibling first byte sits at offset 128.
        assert_eq!(buf[128], 0);
        // Level-19 sibling first byte sits at offset 128 + 19*32 = 736.
        assert_eq!(buf[736], 19);
        // Direction bytes are 0 or 1, level-0 first.
        assert_eq!(buf[768], 1);
        assert_eq!(buf[768 + 3], 1);
        assert_eq!(buf[768 + 1], 0);
    }
}
