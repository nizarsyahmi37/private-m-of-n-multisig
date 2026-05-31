//! Image-ID pin parity test.
//!
//! The SDK pins the approve-circuit image ID at the crate root so the crate
//! compiles without depending on the `methods` crate (whose build invokes
//! the Risc0 RISC-V toolchain). This test, a dev-dep crossing into
//! `private_multisig_program`, verifies the local pin stays in lockstep
//! with the canonical one re-exported from the program crate. Any drift
//! fails CI.
//!
//! Without this test, the SDK could ship receipts that the on-chain
//! verifier rejects with `E2001 ImageIdMismatch` even though both sides
//! "look fine" when audited independently.
//!
//! This test runs under default `cargo test` (no feature flags needed) so
//! drift detection is not gated behind the prover feature. It IS gated on
//! the build being a reproducible Docker build (`RISC0_USE_DOCKER=1`): a
//! host build's image-id bakes in source paths and toolchain version and
//! intentionally differs from the canonical pin, so the parity check would
//! report false drift in that mode. CI sets the flag so the assertion runs
//! there.

#[test]
fn sdk_pinned_image_id_matches_program_canonical() {
    if !private_multisig_program::BUILD_USED_DOCKER {
        eprintln!(
            "SKIP: SDK pin parity check requires a reproducible Docker build. \
             Re-run with `RISC0_USE_DOCKER=1 cargo test -p private_multisig_sdk \
             --test image_id_pin_parity` to enforce the canonical pin."
        );
        return;
    }

    let sdk_pin = private_multisig_sdk::APPROVE_CIRCUIT_IMAGE_ID_PINNED;
    let canonical = private_multisig_program::APPROVE_CIRCUIT_IMAGE_ID;

    assert_eq!(
        sdk_pin, canonical,
        "SDK's APPROVE_CIRCUIT_IMAGE_ID_PINNED drifted from \
         private_multisig_program::APPROVE_CIRCUIT_IMAGE_ID. \
         Update sdk/src/lib.rs to match the freshly-built image id, \
         then re-run this test."
    );
}
