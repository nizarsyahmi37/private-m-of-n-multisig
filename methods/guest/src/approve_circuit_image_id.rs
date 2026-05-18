// Pinned image-id of the `approve_circuit` guest, included by the
// SPEL verifier (`private_multisig` guest) so its `env::verify` call has
// a compile-time-known image-id to recognize.
//
// Build order makes this awkward: `risc0_build::embed_methods()` builds
// `approve_circuit` and `private_multisig` in the same cargo invocation,
// so by the time we'd want to look up `APPROVE_CIRCUIT_ID` to feed it
// into the verifier guest, both guests have already been compiled. We
// break the chicken-and-egg by pinning the value here. The host-side
// `image_id_stability::image_id_pinned_hex` test asserts the same words
// against the freshly-built image-id, so any drift fails CI loudly with
// instructions to update both pins together.
//
// The 8 little-endian `u32` words below are identical to
// `private_multisig_program::APPROVE_CIRCUIT_IMAGE_ID` and the
// `PINNED_IMAGE_ID_WORDS` constant in
// `private_multisig_program/tests/image_id_stability.rs`. Updating the
// `approve_circuit` source means updating ALL THREE pins in lockstep.
pub const APPROVE_CIRCUIT_IMAGE_ID: [u32; 8] = [
    763539168, 1016753994, 1524795730, 877238783, 502029817, 1373722446, 3332462251, 4034702986,
];
