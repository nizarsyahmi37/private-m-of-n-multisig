// Build script that compiles the Risc0 guest binaries in `guest/` and emits
// generated Rust sources to `OUT_DIR/methods.rs` with consts for each guest's
// ELF bytes and image ID. The generated file is `include!`-ed by `src/lib.rs`.
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
// Both vars are exported here so they're in scope for every transitive
// `cc-rs`-driven build the guest cargo runs.
//
// # Clippy / rustc-wrapper leak guard
//
// `cargo clippy` runs the build by setting `RUSTC_WORKSPACE_WRAPPER` (and
// sometimes `RUSTC_WRAPPER`) to `clippy-driver`. `embed_methods()` spawns a
// nested cargo to cross-compile the guest for `riscv32im-risc0-zkvm-elf`, and
// risc0-build's own env sanitizer only strips `CARGO*` / `RUSTUP_TOOLCHAIN` —
// so the wrapper leaks through and the nested build invokes `clippy-driver`
// (built against the *stable* host sysroot) for the guest, which then fails
// with `E0463: can't find crate for core/std` for the Risc0-only target.
// Removing the wrapper vars here keeps the guest build on risc0's own rustc,
// so `cargo clippy --workspace` (incl. CI's `-D warnings` gate) succeeds.
fn main() {
    // Keep the nested guest cross-compile off any clippy/rustc wrapper.
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");

    // Suppress cc-rs's host-platform default flag set globally for guest builds.
    std::env::set_var("CRATE_CC_NO_DEFAULTS", "1");

    // Minimal RISC-V-safe CFLAGS. No `-arch`, no `-mmacosx-version-min`, no
    // `-gfull`. Matches what risc0's own guest builds typically use.
    std::env::set_var(
        "CFLAGS_riscv32im_risc0_zkvm_elf",
        "-march=rv32im -mabi=ilp32 -ffunction-sections -fdata-sections -fPIC -O3",
    );

    // Same for the target-specific TARGET_CFLAGS_… key that some build
    // scripts prefer.
    std::env::set_var(
        "TARGET_CFLAGS",
        "-march=rv32im -mabi=ilp32 -ffunction-sections -fdata-sections -fPIC -O3",
    );

    risc0_build::embed_methods();
}
