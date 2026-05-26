//! Build script: compile the bundled `noop` guest into ELF + image-id
//! constants the e2e test deploys as the `ChainedCall` target.
//!
//! Mirrors `methods/build.rs` exactly — `risc0_build::embed_methods()`
//! walks the `[package.metadata.risc0] methods = ["guest"]` list,
//! compiles each entry under the Risc0 RISC-V toolchain, and emits
//! `NOOP_ELF: &[u8]` + `NOOP_ID: [u32; 8]` (one pair per `[[bin]]` in
//! `guest/Cargo.toml`) into `$OUT_DIR/methods.rs`.

fn main() {
    risc0_build::embed_methods();
}
