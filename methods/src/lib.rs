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
//! `methods/guest/Cargo.toml` declares two `[[bin]]` entries:
//! `approve_circuit` (the ZK approval witness circuit) and
//! `private_multisig` (the SPEL verifier program). Both are emitted here
//! as ELF + image-id pairs (`APPROVE_CIRCUIT_ELF`/`APPROVE_CIRCUIT_ID` and
//! `PRIVATE_MULTISIG_ELF`/`PRIVATE_MULTISIG_ID`). `private_multisig_program`
//! re-exports both pairs under typed aliases so callers (SDK prover, step-7
//! e2e harness) can talk about "the approve circuit" and "the verifier
//! program" without threading the `methods` crate name everywhere.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

/// True iff the guest binaries were produced by a reproducible Docker build
/// (`RISC0_USE_DOCKER=1`). The image-id pin assertions across the workspace
/// only enforce against this build mode — a plain host build leaks paths,
/// toolchain, and ~/.cargo/registry into the ELF, so its image-id is
/// host-specific and intentionally doesn't match the canonical pins. Tests
/// that compare against the pinned constants must short-circuit (skip) when
/// this is `false`, otherwise local `cargo test` on a developer machine
/// would fail the drift sentinel even though nothing actually drifted.
///
/// Set by `methods/build.rs` via `cargo:rustc-env=METHODS_BUILD_USED_DOCKER`
/// (emitted only when Docker mode is active). `is_some()` on
/// `Option<&'static str>` is const-stable since Rust 1.66 — `matches!` on a
/// `&str` literal is not allowed in a const context, which is why we just
/// check presence rather than compare the value.
pub const BUILD_USED_DOCKER: bool = option_env!("METHODS_BUILD_USED_DOCKER").is_some();
