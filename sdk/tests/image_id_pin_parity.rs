//! Image-ID pin parity test.
//!
//! The SDK pins the approve-circuit image ID locally in `prover.rs` so the
//! crate compiles without depending on the `methods` crate (whose build
//! invokes the Risc0 RISC-V toolchain). This test, a dev-dep crossing into
//! `private_multisig_program`, verifies the local pin stays in lockstep with
//! the canonical one re-exported from the program crate. Any drift fails CI.
//!
//! Without this test, the SDK could ship receipts that the on-chain verifier
//! rejects with `E2001 ImageIdMismatch` even though both sides "look fine"
//! when audited independently.

#[cfg(feature = "prover")]
#[test]
fn sdk_pinned_image_id_matches_program_canonical() {
    // The SDK's locally pinned image id (private to the crate, exposed here
    // via the `prover` feature for testing).
    let sdk_pin = private_multisig_sdk::prover::__test_only_image_id();

    let canonical = private_multisig_program::APPROVE_CIRCUIT_IMAGE_ID;

    assert_eq!(
        sdk_pin, canonical,
        "SDK's APPROVE_CIRCUIT_IMAGE_ID_PINNED drifted from \
         private_multisig_program::APPROVE_CIRCUIT_IMAGE_ID. \
         Update sdk/src/prover.rs to match the freshly-built image id, \
         then re-run this test."
    );
}
