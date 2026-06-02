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
//!
//! # Reproducible (host-independent) image-id
//!
//! Same rationale as `methods/build.rs`: `RISC0_USE_DOCKER=1` builds
//! the guest inside the pinned `risczero/risc0-guest-builder` container,
//! which remaps absolute paths and yields a deterministic image-id.
//! Unlike the verifier guest, `noop_guest` has no path deps escaping
//! its own crate dir, so the Docker context root is `e2e_tests/guest/`
//! itself — keeps the build context tiny.

use std::collections::HashMap;
use std::path::PathBuf;

use risc0_build::{
    embed_methods, embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder,
};

/// Guest package name (`e2e_tests/guest/Cargo.toml`); keys the per-guest options.
const GUEST_PACKAGE: &str = "noop_guest";

/// Reproducible-build container tag. Pinned to the same tag as
/// `methods/build.rs::GUEST_DOCKER_TAG` so both guest builds share
/// the same toolchain. Never follow `latest` — pin the tag.
const GUEST_DOCKER_TAG: &str = "r0.1.91.1";

fn main() {
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");

    let use_docker = matches!(
        std::env::var("RISC0_USE_DOCKER").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );

    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");

    if use_docker {
        // `noop_guest` has no path deps outside its own crate dir, so
        // the docker context root is the guest crate itself.
        let guest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("guest");

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(guest_root)
            .docker_container_tag(GUEST_DOCKER_TAG.to_string())
            .build()
            .expect("DockerOptions build");

        let guest_opts = GuestOptionsBuilder::default()
            .use_docker(docker_opts)
            .build()
            .expect("GuestOptions build");

        embed_methods_with_options(HashMap::from([(GUEST_PACKAGE, guest_opts)]));
    } else {
        embed_methods();
    }
}
