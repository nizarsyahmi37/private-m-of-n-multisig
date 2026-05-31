// Build script that compiles the Risc0 guest binaries in `guest/` and emits
// generated Rust sources to `OUT_DIR/methods.rs` with consts for each guest's
// ELF bytes and image ID. The generated file is `include!`-ed by `src/lib.rs`.
//
// # Reproducible (host-independent) image-id
//
// The guest's image-id IS the on-chain program identity, so it must be
// identical no matter who builds it. A plain host build leaks absolute
// paths (source dir, `~/.cargo/registry`, toolchain) into the ELF, so the
// image-id differs between e.g. macOS and Linux CI. Setting
// `RISC0_USE_DOCKER=1` builds the guest inside the pinned
// `risczero/risc0-guest-builder` container, which remaps paths and yields a
// deterministic image-id. CI sets it; the pinned image-ids in `sdk` and the
// `image_id_*` tests are the Docker-canonical values. The docker root dir is
// the workspace root because the guest has path deps (`../../crypto`,
// `../../private_multisig_core`); a repo-root `.dockerignore` keeps the
// build context small.
//
// # Cross-compile patch for the SPEL verifier guest
//
// The `private_multisig` guest pulls in `spel-framework` which transitively
// drags `nssa_core` (the LEZ runtime) → `hyper-rustls` → `rustls` → `ring`.
// `ring` ships C source compiled via `cc-rs`; when invoked through Risc0's
// `riscv32-unknown-elf-gcc`, `cc-rs` decorates the call with host-detected
// macOS flags (`-arch arm64`, `-mmacosx-version-min=…`, `-gfull`) that the
// RISC-V cross-compiler rejects.
//
// The fix is two-pronged:
//
// 1. `CRATE_CC_NO_DEFAULTS=1` tells `cc-rs` not to add its own default
//    flag set (the source of `-arch`/`-gfull` for darwin hosts).
// 2. `CFLAGS_riscv32im_risc0_zkvm_elf` defines an explicit, minimal,
//    RISC-V-safe CFLAGS string that `cc-rs` uses verbatim for the
//    guest target.
//
// For host builds these are exported into this process's env; for Docker
// builds they are forwarded into the build container via `DockerOptions`.
//
// # Clippy / rustc-wrapper leak guard
//
// `cargo clippy` runs the build by setting `RUSTC_WORKSPACE_WRAPPER` (and
// sometimes `RUSTC_WRAPPER`) to `clippy-driver`. The host build spawns a
// nested cargo to cross-compile the guest for `riscv32im-risc0-zkvm-elf`, and
// risc0-build's own env sanitizer only strips `CARGO*` / `RUSTUP_TOOLCHAIN` —
// so the wrapper leaks through and the nested build invokes `clippy-driver`
// (built against the *stable* host sysroot) for the guest, which then fails
// with `E0463: can't find crate for core/std` for the Risc0-only target.
// Removing the wrapper vars here keeps the guest build on risc0's own rustc,
// so `cargo clippy --workspace` (incl. CI's `-D warnings` gate) succeeds.
use std::collections::HashMap;
use std::path::PathBuf;

use risc0_build::{
    embed_methods, embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder,
};

/// Minimal RISC-V-safe CFLAGS. No `-arch`, no `-mmacosx-version-min`, no
/// `-gfull`. Matches what risc0's own guest builds typically use.
const GUEST_CFLAGS: &str =
    "-march=rv32im -mabi=ilp32 -ffunction-sections -fdata-sections -fPIC -O3";

/// Guest package name (`methods/guest/Cargo.toml`); keys the per-guest options.
const GUEST_PACKAGE: &str = "approve_circuit_guest";

/// Reproducible-build container tag. risc0-build's default is `r0.1.88.0`,
/// which ships rustc 1.88; our guest depends transitively on `ruint 1.18`
/// which requires rustc >= 1.90, so the default tag's nested `cargo build`
/// errors out with `rustc 1.88.0-dev is not supported by ruint`. Bumping to
/// `r0.1.91.1` (rustc 1.91-class) satisfies the MSRV. Pin the tag — never
/// follow `latest` — so the resulting image-id stays stable across builds.
const GUEST_DOCKER_TAG: &str = "r0.1.91.1";

fn main() {
    // Keep the nested guest cross-compile off any clippy/rustc wrapper.
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");

    // Suppress cc-rs's host-platform default flag set globally for guest builds.
    std::env::set_var("CRATE_CC_NO_DEFAULTS", "1");
    std::env::set_var("CFLAGS_riscv32im_risc0_zkvm_elf", GUEST_CFLAGS);
    std::env::set_var("TARGET_CFLAGS", GUEST_CFLAGS);

    let use_docker = matches!(
        std::env::var("RISC0_USE_DOCKER").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );

    // Expose the Docker-vs-host build mode to downstream crates via a
    // `METHODS_BUILD_USED_DOCKER` env var that `methods/src/lib.rs` reads
    // through `option_env!`. The image-id pin assertions in
    // `private_multisig_program/tests/image_id_stability.rs`,
    // `private_multisig_program/tests/blue_team_program_v3.rs`,
    // `sdk/tests/image_id_pin_parity.rs` only match the canonical pin under
    // a reproducible (Docker) build; a host build's image-id is path- and
    // toolchain-dependent, so those tests skip when this flag is unset.
    //
    // Only set the env when use_docker is true, so the `option_env!` read in
    // `methods/src/lib.rs` can be `is_some()` — which is const-stable —
    // rather than a `matches!(_, Some("1"))` string compare (not const-able).
    if use_docker {
        println!("cargo:rustc-env=METHODS_BUILD_USED_DOCKER=1");
    }
    // Trigger a rebuild whenever the env var flips so the const re-evaluates.
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");

    if use_docker {
        // The guest's path deps live at ../../crypto and
        // ../../private_multisig_core, so the docker context root is the
        // workspace root (the parent of this `methods` crate).
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("methods crate has a parent (workspace root)")
            .to_path_buf();

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(workspace_root)
            .docker_container_tag(GUEST_DOCKER_TAG.to_string())
            .env(vec![
                ("CRATE_CC_NO_DEFAULTS".to_string(), "1".to_string()),
                (
                    "CFLAGS_riscv32im_risc0_zkvm_elf".to_string(),
                    GUEST_CFLAGS.to_string(),
                ),
            ])
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
