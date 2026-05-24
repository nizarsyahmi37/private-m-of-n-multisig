//! IDL generator for the LP-0002 Private M-of-N Multisig verifier program.
//!
//! Prints the SPEL-generated IDL JSON to stdout. Usage:
//!
//! ```sh
//! cargo run -p private_multisig_idl_gen > private_multisig.idl.json
//! ```
//!
//! The macro parses `methods/guest/src/bin/private_multisig.rs` with `syn`
//! at host-compile time and emits a `main()` that walks the
//! `#[lez_program]` module's `#[instruction]` handlers and the
//! `#[account_type]`-marked state structs, producing the canonical IDL the
//! generic SPEL CLI consumes. Re-run after every change to the verifier
//! handler shape, the `Instruction` enum, or any account-type struct.

spel_framework::generate_idl!("../methods/guest/src/bin/private_multisig.rs");
