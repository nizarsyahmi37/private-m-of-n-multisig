//! Risc0 guest method artifacts for LP-0002 Private M-of-N Multisig.
//!
//! `methods/build.rs` invokes `risc0_build::embed_methods()` which compiles
//! the `methods/guest/` cargo project under the Risc0 RISC-V toolchain and
//! emits two consts per guest binary into `OUT_DIR/methods.rs`:
//!
//! - `<NAME>_ELF: &[u8]` — the compiled RISC-V ELF bytes the host hands to
//!   the prover.
//! - `<NAME>_ID: [u32; 8]` — the image ID (a 32-byte SHA-256-ish digest of
//!   the ELF, in 8-u32 words) the verifier checks the receipt against.
//!
//! For our prize the only guest today is `approve_circuit`, so callers see
//! `APPROVE_CIRCUIT_ELF` and `APPROVE_CIRCUIT_ID`. `private_multisig_program`
//! re-exports those under typed aliases.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
