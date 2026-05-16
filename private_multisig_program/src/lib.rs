//! Host-side program crate for LP-0002 Private M-of-N Multisig.
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
}
