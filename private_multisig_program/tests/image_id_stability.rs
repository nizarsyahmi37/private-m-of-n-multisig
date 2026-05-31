//! On-chain ABI stability sentinel for `APPROVE_CIRCUIT_IMAGE_ID`.
//!
//! # Why this file exists
//!
//! The Risc0 image-id is a 32-byte cryptographic identifier of the compiled
//! guest binary for `methods/guest/src/bin/approve_circuit.rs` (an R0BF
//! container wrapping the RISC-V ELF, in Risc0 v3+). Every on-chain
//! `MultisigState` that has finalized binds itself to *exactly* this value:
//! the verifier program checks each `Receipt` against the pinned image-id and
//! rejects mismatches with `E2001 ImageIdMismatch`. If the image-id drifts
//! between builds, *all* existing receipts stop verifying and the on-chain
//! state for every prior multisig is orphaned. There is no migration path.
//!
//! These tests pin the image-id as a regression sentinel. They are *fast* —
//! they only read the build-time constants exported from
//! `private_multisig_program`; the prover is never invoked.
//!
//! # What can shift the image-id
//!
//! The image-id is a deterministic function of the compiled guest ELF. It
//! changes whenever **any** of the following change:
//!
//! 1. The guest source (`methods/guest/src/bin/approve_circuit.rs`) or any
//!    other file under `methods/guest/`.
//! 2. The Risc0 toolchain version (`rust-toolchain.toml` inside the guest
//!    workspace, or the toolchain `risc0-build` pulls in).
//! 3. Any item in `crypto` or `private_multisig_core` that the guest pulls
//!    in via its `Cargo.toml` (including transitive deps like `sha2`).
//! 4. The `risc0-zkvm` or `risc0-build` crate version, or `risc0-zkvm`'s
//!    guest-side runtime / linker scripts.
//! 5. Compiler flags or profile settings that reach the guest build
//!    (release profile, codegen units, opt-level).
//!
//! # How to update the pins when this test legitimately needs to change
//!
//! If you are intentionally cutting a new circuit version (and have
//! coordinated the on-chain rollout — new instances will pin the new
//! image-id; old instances must stay on the old verifier program ID or
//! migrate explicitly):
//!
//! 1. Audit the change. Make sure no third-party / dependency change is
//!    sneaking in alongside your intentional one.
//! 2. Run:
//!    ```text
//!    cargo test -p private_multisig_program --test image_id_stability -- --nocapture
//!    ```
//!    The failed assertions will print the new hex and `[u32; 8]` array.
//! 3. Paste the new values into the `PINNED_IMAGE_ID_HEX` and
//!    `PINNED_IMAGE_ID_WORDS` constants below.
//! 4. Re-run the test suite; commit the pin update *separately* from the
//!    underlying change so reviewers can spot the ABI break in git history.
//! 5. Update any external pins: release notes, on-chain genesis records,
//!    SDK documentation, the verifier program's hardcoded constant if any.
//!
//! If this test fails and you did *not* intend to change the image-id,
//! **do not update the pins**. Find what drifted (likely a Cargo.lock
//! update or toolchain bump) and revert it.

#![allow(clippy::needless_range_loop)]

use private_multisig_program::{image_id_hex, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};

/// The pinned on-chain ABI: hex form of the approve-circuit image-id.
///
/// This is the canonical lowercase-hex serialization of
/// `APPROVE_CIRCUIT_IMAGE_ID` (each `u32` written little-endian, words
/// concatenated). Any drift here is an on-chain ABI break.
const PINNED_IMAGE_ID_HEX: &str =
    "69f156642ae3e69e7c7517949dcc706172b34db8d967aec5ddfd8879fcbed9ce";

/// The pinned on-chain ABI: `[u32; 8]` form of the approve-circuit image-id.
///
/// Pinned in addition to the hex so a future refactor of `image_id_hex()` or
/// the word ordering cannot silently change the on-chain interpretation
/// while the hex string coincidentally still matches.
const PINNED_IMAGE_ID_WORDS: [u32; 8] = [
    1683419497, 2665931562, 2484565372, 1634782365, 3092099954, 3316541401, 2039021021, 3470376700,
];

/// Drift-sentinel tests below pin against the canonical reproducible-build
/// image-id (i.e. one produced under `RISC0_USE_DOCKER=1`). A plain host
/// build emits an image-id that bakes in source paths, the local
/// `~/.cargo/registry`, and the toolchain version, so its words differ
/// between e.g. macOS and Linux. Skip the comparison rather than fail
/// noisily when the test happens to run against such a build — the
/// canonical pin is meaningless in that mode. Returns `true` when the test
/// should short-circuit.
fn skip_unless_docker_build() -> bool {
    if !private_multisig_program::BUILD_USED_DOCKER {
        eprintln!(
            "SKIP: image-id pin assertion requires a reproducible Docker build. \
             Re-run with `RISC0_USE_DOCKER=1 cargo test -p private_multisig_program \
             --test image_id_stability` to enforce the canonical pin."
        );
        return true;
    }
    false
}

/// Lower bound on a reasonable approve-circuit ELF size. The guest is small
/// (Merkle proof + signature check), so anything under ~100 KB suggests the
/// build produced a stub.
const ELF_MIN_BYTES: usize = 100 * 1024;

/// Upper bound on a reasonable approve-circuit ELF size. A multi-MB ELF
/// would indicate a build regression (e.g. accidentally pulling in
/// `std`, an unrelated heavy dep, or debug symbols).
const ELF_MAX_BYTES: usize = 5 * 1024 * 1024;

/// Offset within an ELF header of the `e_machine` field (2 bytes, LE).
const ELF_E_MACHINE_OFFSET: usize = 18;

/// RISC-V `e_machine` value: 0xF3 = 243.
const ELF_E_MACHINE_RISCV: u16 = 0xF3;

/// ELF magic header: `\x7FELF`.
const ELF_MAGIC: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];

/// Risc0 Binary Format (R0BF) magic header. Risc0 v3+ wraps the raw
/// RISC-V ELF in an R0BF container with a small header carrying a
/// format version and metadata; the actual ELF bytes sit inside.
/// `APPROVE_CIRCUIT_ELF` is the R0BF-wrapped binary, not the raw ELF.
const R0BF_MAGIC: [u8; 4] = [b'R', b'0', b'B', b'F'];

/// Locate the embedded ELF magic inside `APPROVE_CIRCUIT_ELF`. Returns
/// the byte offset of the inner ELF header. The binary is either a
/// bare ELF (offset 0) or an R0BF-wrapped ELF (offset > 0). Anything
/// else means the artifact is corrupt / a stub.
fn find_inner_elf_offset() -> usize {
    APPROVE_CIRCUIT_ELF
        .windows(ELF_MAGIC.len())
        .position(|w| w == ELF_MAGIC)
        .expect("approve_circuit binary must contain an inner ELF header")
}

#[test]
fn image_id_pinned_hex() {
    // Sentinel: pins the canonical hex form of the on-chain image-id.
    //
    // If this fails, the on-chain ABI just changed. See the file-level
    // docs for the audit-and-update procedure. Do NOT just rubber-stamp
    // the new value — verify the source-of-truth change first.
    if skip_unless_docker_build() {
        return;
    }
    let actual = image_id_hex();
    assert_eq!(
        actual, PINNED_IMAGE_ID_HEX,
        "\nAPPROVE_CIRCUIT image-id hex drift!\n  pinned:  {}\n  actual:  {}\n\
         The Risc0 guest ELF hash changed. This breaks every receipt\n\
         produced against the previous image-id. See file-level docs.\n",
        PINNED_IMAGE_ID_HEX, actual,
    );
}

#[test]
fn image_id_word_array_pinned() {
    // Sentinel: pins the `[u32; 8]` form of the on-chain image-id. This
    // catches any refactor that changes how the words are computed even
    // if the hex string would coincidentally still match.
    if skip_unless_docker_build() {
        return;
    }
    assert_eq!(
        APPROVE_CIRCUIT_IMAGE_ID, PINNED_IMAGE_ID_WORDS,
        "\nAPPROVE_CIRCUIT image-id word array drift!\n  pinned:  {:?}\n  actual:  {:?}\n",
        PINNED_IMAGE_ID_WORDS, APPROVE_CIRCUIT_IMAGE_ID,
    );
}

#[test]
fn image_id_word_array_hex_consistency() {
    // Cross-check: the hex returned by `image_id_hex()` must be exactly
    // the concatenation of each pinned word's little-endian bytes in
    // lowercase hex. Computed manually from the pinned `[u32; 8]` so a
    // bug in `image_id_hex()` would surface here independently of the
    // direct hex pin.
    if skip_unless_docker_build() {
        return;
    }
    let mut expected = String::with_capacity(64);
    for word in PINNED_IMAGE_ID_WORDS {
        for b in word.to_le_bytes() {
            // Manual lowercase hex — avoid relying on `image_id_hex()`'s
            // own implementation here; this is meant to be an
            // independent check of its output.
            const HEX: &[u8; 16] = b"0123456789abcdef";
            expected.push(HEX[(b >> 4) as usize] as char);
            expected.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    assert_eq!(expected.len(), 64);
    assert_eq!(image_id_hex(), expected);
    // And the hex pin and the words pin must agree with each other too.
    assert_eq!(expected, PINNED_IMAGE_ID_HEX);
}

#[test]
fn image_id_is_not_a_recognized_dummy() {
    // Sentinel against the build harness ever emitting a stub image-id.
    // None of these "obvious" patterns should ever be the real value.
    assert_ne!(
        APPROVE_CIRCUIT_IMAGE_ID, [0u32; 8],
        "image-id is all-zero — build harness produced a stub",
    );
    assert_ne!(
        APPROVE_CIRCUIT_IMAGE_ID,
        [u32::MAX; 8],
        "image-id is all-ones — build harness produced a stub",
    );
    assert_ne!(
        APPROVE_CIRCUIT_IMAGE_ID,
        [0u32, 1, 2, 3, 4, 5, 6, 7],
        "image-id is the trivial 0..8 sequence — build harness produced a stub",
    );
}

#[test]
fn image_id_hex_round_trips_through_hex_crate() {
    // Bidirectional check: hex(string) -> 32 bytes -> [u32; 8] -> original.
    // This pins both the encoding and the assumption that the words are
    // little-endian on the wire.
    if skip_unless_docker_build() {
        return;
    }
    let s = image_id_hex();
    let bytes = hex::decode(&s).expect("image_id_hex() must be valid hex");
    assert_eq!(bytes.len(), 32, "image-id must decode to exactly 32 bytes");

    let mut reconstructed = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4].try_into().expect("4-byte chunk");
        reconstructed[i] = u32::from_le_bytes(chunk);
    }
    assert_eq!(reconstructed, APPROVE_CIRCUIT_IMAGE_ID);
    assert_eq!(reconstructed, PINNED_IMAGE_ID_WORDS);
}

#[test]
fn elf_size_is_in_a_reasonable_band() {
    // The exact ELF size varies with toolchain version, so we band rather
    // than pin. A size outside this band is almost certainly a build
    // regression (empty stub on the low end; std/debug bloat on the high
    // end). Adjust the band if a Risc0 toolchain upgrade legitimately
    // moves the size — but treat it as a signal worth investigating.
    let len = APPROVE_CIRCUIT_ELF.len();
    assert!(
        len >= ELF_MIN_BYTES,
        "approve_circuit ELF is suspiciously small: {} bytes (min {})",
        len,
        ELF_MIN_BYTES,
    );
    assert!(
        len <= ELF_MAX_BYTES,
        "approve_circuit ELF is suspiciously large: {} bytes (max {})",
        len,
        ELF_MAX_BYTES,
    );
}

#[test]
fn elf_contains_riscv_magic_header() {
    // Confirms the artifact contains a real ELF header (not a stub byte
    // string or a different object format). Risc0 v3+ wraps the RISC-V
    // ELF in an R0BF container, so the magic may not be at offset 0 —
    // we accept either a bare ELF or an R0BF-wrapped ELF and verify
    // the inner ELF magic is present.
    assert!(
        APPROVE_CIRCUIT_ELF.len() >= 4,
        "approve_circuit binary is too short to contain any header",
    );

    let starts_with_elf = APPROVE_CIRCUIT_ELF[0..4] == ELF_MAGIC;
    let starts_with_r0bf = APPROVE_CIRCUIT_ELF[0..4] == R0BF_MAGIC;
    assert!(
        starts_with_elf || starts_with_r0bf,
        "approve_circuit binary starts with {:02x?}, expected either \\x7FELF \
         ({:02x?}) or R0BF ({:02x?})",
        &APPROVE_CIRCUIT_ELF[0..4],
        ELF_MAGIC,
        R0BF_MAGIC,
    );

    // Either way an inner ELF header must be present somewhere in the
    // binary — it carries the actual RISC-V code that the zkVM runs.
    let elf_offset = find_inner_elf_offset();
    assert_eq!(
        &APPROVE_CIRCUIT_ELF[elf_offset..elf_offset + 4],
        &ELF_MAGIC,
        "inner ELF header at offset {} is malformed",
        elf_offset,
    );
}

#[test]
fn elf_marks_riscv_machine_type() {
    // The `e_machine` field at offset 18 within the ELF header is a
    // little-endian u16. For RISC-V it is 0xF3 (243). If this is
    // wrong, the build targeted the wrong architecture and the
    // receipt would never verify on the Risc0 zkVM. Risc0 v3+ wraps
    // the ELF in R0BF, so we locate the inner ELF header first.
    let elf_offset = find_inner_elf_offset();
    let e_machine_offset = elf_offset + ELF_E_MACHINE_OFFSET;
    assert!(
        APPROVE_CIRCUIT_ELF.len() >= e_machine_offset + 2,
        "inner ELF too short to contain e_machine field at offset {}",
        e_machine_offset,
    );
    let e_machine = u16::from_le_bytes([
        APPROVE_CIRCUIT_ELF[e_machine_offset],
        APPROVE_CIRCUIT_ELF[e_machine_offset + 1],
    ]);
    assert_eq!(
        e_machine, ELF_E_MACHINE_RISCV,
        "approve_circuit inner ELF e_machine is 0x{:04x}, expected RISC-V (0x{:04x})",
        e_machine, ELF_E_MACHINE_RISCV,
    );
}

#[test]
fn image_id_hex_format_documentation() {
    // Reproduces the existing in-crate test as a sentinel here: 64 chars,
    // all lowercase hex. Even if someone deletes the in-crate version,
    // this file is the on-chain ABI lock and must keep enforcing the
    // canonical format.
    let s = image_id_hex();
    assert_eq!(s.len(), 64, "image-id hex must be exactly 64 chars");
    for c in s.chars() {
        assert!(
            c.is_ascii_digit() || ('a'..='f').contains(&c),
            "image-id hex contains non-lowercase-hex char: {:?}",
            c,
        );
    }
}

#[test]
fn image_id_documentation_block() {
    // This test exists as an executable pointer at the file-level docs.
    // If you are here because a sibling test failed and you are
    // wondering what to do, scroll to the top of this file and read the
    // "How to update the pins" section. Do not silently bump the
    // constants — an image-id drift is an on-chain ABI break and the
    // procedure exists for a reason.
    //
    // The assertion below is structural: it guarantees the pinned
    // constants in this file are internally consistent. If you've just
    // updated one pin without the other, this fires.
    let mut hex_from_words = String::with_capacity(64);
    for word in PINNED_IMAGE_ID_WORDS {
        for b in word.to_le_bytes() {
            use core::fmt::Write;
            let _ = write!(hex_from_words, "{:02x}", b);
        }
    }
    assert_eq!(
        hex_from_words, PINNED_IMAGE_ID_HEX,
        "\nPinned constants are inconsistent: PINNED_IMAGE_ID_WORDS does\n\
         not serialize to PINNED_IMAGE_ID_HEX. You probably updated one\n\
         pin without the other. Re-read the file-level docs and update\n\
         both from the same `cargo test ... -- --nocapture` run.\n",
    );
}
