//! Build script: compile the bundled `noop` guest into ELF + image-id
//! constants the e2e test deploys as the `ChainedCall` target.
//!
//! Mirrors `methods/build.rs` — `risc0_build::embed_methods()` walks
//! the `[package.metadata.risc0] methods = ["guest"]` list, compiles
//! each entry under the Risc0 RISC-V toolchain, and emits `NOOP_ELF:
//! &[u8]` + `NOOP_ID: [u32; 8]` (one pair per `[[bin]]` in
//! `guest/Cargo.toml`) into `$OUT_DIR/methods.rs`.
//!
//! The `RUSTC_WORKSPACE_WRAPPER` / `RUSTC_WRAPPER` strip mirrors the
//! same defense in `methods/build.rs`. Without it, `cargo clippy
//! --bin quickstart` (or any clippy run touching this crate) leaks
//! `clippy-driver` into the nested guest cross-compile for the
//! `riscv32im-risc0-zkvm-elf` target, and the guest fails to build
//! with `E0463: can't find crate for std/core` because clippy-driver
//! is bound to the stable host sysroot, not Risc0's toolchain.

fn main() {
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");
    risc0_build::embed_methods();
}
