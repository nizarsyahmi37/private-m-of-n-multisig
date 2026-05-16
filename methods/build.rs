// Build script that compiles the Risc0 guest binaries in `guest/` and emits
// generated Rust sources to `OUT_DIR/methods.rs` with consts for each guest's
// ELF bytes and image ID. The generated file is `include!`-ed by `src/lib.rs`.
fn main() {
    risc0_build::embed_methods();
}
