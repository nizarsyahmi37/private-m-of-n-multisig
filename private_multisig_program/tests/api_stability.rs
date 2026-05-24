//! API stability sentinels for the `private_multisig_program` crate.
//!
//! The verifier program (PLAN.md step 4) consumes the three public items from
//! this crate (`APPROVE_CIRCUIT_ELF`, `APPROVE_CIRCUIT_IMAGE_ID`,
//! `image_id_hex`). Any silent rename, retyping, or removal would break the
//! verifier build downstream. These tests act as a regression sentinel: they
//! pin the surface at compile time (via type ascriptions and fn-pointer
//! coercions) and at runtime (via parsed source-text counts and equality
//! checks against the `methods` re-export).
//!
//! Touch this file only when you have INTENTIONALLY changed the public API.
//! When you do, update the sentinels here AND add the corresponding rustdoc
//! to the new pub item in `src/lib.rs`.

#![allow(clippy::needless_borrow)]
#![allow(clippy::let_underscore_untyped)]
#![allow(clippy::manual_range_contains)]

use private_multisig_program::{image_id_hex, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID};

/// Embedded snapshot of `src/lib.rs` parsed by the source-scanning sentinels
/// below. `include_str!` is resolved at compile time relative to this file.
const LIB_RS: &str = include_str!("../src/lib.rs");

/// Embedded snapshot of `Cargo.toml`, used by the dep-pin sentinel.
const CARGO_TOML: &str = include_str!("../Cargo.toml");

// ---------------------------------------------------------------------------
// 1. Compile-time type pin: APPROVE_CIRCUIT_ELF must remain `&'static [u8]`.
// ---------------------------------------------------------------------------
#[test]
fn api_apprrove_circuit_elf_type_pin() {
    let _: &'static [u8] = APPROVE_CIRCUIT_ELF;
}

// ---------------------------------------------------------------------------
// 2. Compile-time type pin: APPROVE_CIRCUIT_IMAGE_ID must remain `[u32; 8]`.
// ---------------------------------------------------------------------------
#[test]
fn api_apprrove_circuit_image_id_type_pin() {
    let _: [u32; 8] = APPROVE_CIRCUIT_IMAGE_ID;
}

// ---------------------------------------------------------------------------
// 3. Compile-time signature pin: image_id_hex must remain `fn() -> String`.
// ---------------------------------------------------------------------------
#[test]
fn api_image_id_hex_signature_pin() {
    let f: fn() -> String = image_id_hex;
    // Touch `f` so the binding isn't optimized away by an over-eager lint.
    let _ = f;
}

// ---------------------------------------------------------------------------
// 4. Output format pin: 64 chars, lowercase hex.
// ---------------------------------------------------------------------------
#[test]
fn api_image_id_hex_output_format() {
    let s = image_id_hex();
    assert_eq!(
        s.len(),
        64,
        "image_id_hex must return 64 chars, got {}",
        s.len()
    );
    for c in s.chars() {
        let ok = c.is_ascii_digit() || ('a'..='f').contains(&c);
        assert!(ok, "non-lowercase-hex char in image_id_hex output: {c:?}");
    }
}

// ---------------------------------------------------------------------------
// 5. Public-item count pin: src/lib.rs exposes exactly five `pub ` items
//    (APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID, image_id_hex,
//    APPROVE_WITNESS_LEN, pack_approve_witness). A future PR that adds a
//    new pub item must update this constant AND add a rustdoc block
//    (enforced by the next sentinel).
// ---------------------------------------------------------------------------
const EXPECTED_PUB_ITEM_COUNT: usize = 5;

/// Returns the line indices (0-based) of every line in `lib.rs` that is the
/// *declaration* of a pub item — i.e. starts with `pub ` after trimming
/// leading whitespace, but ignoring `pub use` (re-exports) and `pub(crate)`
/// (non-public). Today the crate has no such excluded items, but the filter
/// keeps the parser honest if any are added later.
fn pub_item_declaration_lines(src: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("pub ") {
            continue;
        }
        // Exclude `pub use ...;` re-exports — they don't count as new surface.
        if trimmed.starts_with("pub use ") {
            continue;
        }
        // Exclude `pub(crate) ...` / `pub(super) ...` — not public.
        if trimmed.starts_with("pub(") {
            continue;
        }
        out.push(i);
    }
    out
}

#[test]
fn api_no_other_pub_items_exist() {
    let lines = pub_item_declaration_lines(LIB_RS);
    assert_eq!(
        lines.len(),
        EXPECTED_PUB_ITEM_COUNT,
        "private_multisig_program::lib pub-item count drifted. \
         Expected {EXPECTED_PUB_ITEM_COUNT}, got {} (lines {:?}). \
         If this is intentional, update EXPECTED_PUB_ITEM_COUNT and add a \
         rustdoc block to the new item.",
        lines.len(),
        lines,
    );
}

// ---------------------------------------------------------------------------
// 6. Doc coverage: every pub item has a rustdoc block immediately above it.
// ---------------------------------------------------------------------------
#[test]
fn api_every_pub_item_has_a_rustdoc_block() {
    let src_lines: Vec<&str> = LIB_RS.lines().collect();
    let pub_lines = pub_item_declaration_lines(LIB_RS);
    assert!(!pub_lines.is_empty(), "no pub items found — parser broken?");

    for &idx in &pub_lines {
        // Walk upward past blank lines and `#[...]` attributes; the first
        // non-blank, non-attribute line must be a `///` rustdoc line.
        let mut found_doc = false;
        let mut j = idx;
        while j > 0 {
            j -= 1;
            let prev = src_lines[j].trim_start();
            if prev.is_empty() {
                continue;
            }
            if prev.starts_with("#[") || prev.starts_with("#![") {
                continue;
            }
            if prev.starts_with("///") {
                found_doc = true;
            }
            break;
        }
        assert!(
            found_doc,
            "pub item at lib.rs:{} has no rustdoc /// block immediately above. \
             Line content: {:?}",
            idx + 1,
            src_lines[idx],
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Crate-level docs (`//!`) describe what the crate is for.
// ---------------------------------------------------------------------------
#[test]
fn api_module_level_docs_describe_what_the_crate_is_for() {
    // Collect contiguous `//!` lines from the top of the file.
    let module_docs: String = LIB_RS
        .lines()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("//!") || t.is_empty()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        module_docs.contains("LP-0002"),
        "crate-level //! docs must mention the prize identifier LP-0002. \
         Got:\n{module_docs}"
    );
    let lc = module_docs.to_lowercase();
    assert!(
        lc.contains("image-id") || lc.contains("image id"),
        "crate-level //! docs must mention image-id (or image id). \
         Got:\n{module_docs}"
    );
}

// ---------------------------------------------------------------------------
// 8. Re-export sentinel: APPROVE_CIRCUIT_ELF points to the same slice as
//    `methods::APPROVE_CIRCUIT_ELF`. We check pointer identity so a stub
//    that copies the bytes into a new static would trip the sentinel.
// ---------------------------------------------------------------------------
#[test]
fn api_apprrove_circuit_elf_is_re_exported_from_methods() {
    assert_eq!(
        APPROVE_CIRCUIT_ELF.as_ptr(),
        methods::APPROVE_CIRCUIT_ELF.as_ptr(),
        "APPROVE_CIRCUIT_ELF must be a direct re-export of methods::APPROVE_CIRCUIT_ELF, \
         not a copy or stub."
    );
    assert_eq!(
        APPROVE_CIRCUIT_ELF.len(),
        methods::APPROVE_CIRCUIT_ELF.len(),
        "APPROVE_CIRCUIT_ELF length must match methods::APPROVE_CIRCUIT_ELF."
    );
}

// ---------------------------------------------------------------------------
// 9. Image-id equality sentinel: the re-exported image-id matches the one
//    that `methods/build.rs` baked in.
// ---------------------------------------------------------------------------
#[test]
fn api_apprrove_circuit_image_id_equals_methods_one() {
    assert_eq!(
        APPROVE_CIRCUIT_IMAGE_ID,
        methods::APPROVE_CIRCUIT_ID,
        "APPROVE_CIRCUIT_IMAGE_ID must equal methods::APPROVE_CIRCUIT_ID. \
         If this fails, someone replaced the re-export with a literal."
    );
}

// ---------------------------------------------------------------------------
// 10. Purity sentinel: image_id_hex is deterministic across many calls.
// ---------------------------------------------------------------------------
#[test]
fn api_image_id_hex_is_pure_no_side_effects() {
    let first = image_id_hex();
    for i in 0..100 {
        let again = image_id_hex();
        assert_eq!(
            again, first,
            "image_id_hex must be pure; call #{i} differed from first call"
        );
    }
}

// ---------------------------------------------------------------------------
// 11. Latency sentinel: image_id_hex must remain a trivial format-loop.
//     1 ms is loose enough to survive a cold CPU and CI noise, but tight
//     enough to flag e.g. switching to a JSON serializer.
// ---------------------------------------------------------------------------
#[test]
fn api_image_id_hex_runs_in_under_1ms() {
    // Warm up once so we don't measure first-call setup (string allocator
    // touching its pool, etc.).
    let _warmup = image_id_hex();

    let start = std::time::Instant::now();
    let _ = image_id_hex();
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(1),
        "image_id_hex took {elapsed:?}, expected < 1ms. \
         If a heavy serializer was added, revisit the API contract."
    );
}

// ---------------------------------------------------------------------------
// 12. Dependency-pin sentinel: risc0-zkvm is pinned exactly to "=3.0.5"
//     in every manifest that consumes it. A silent bump to "3.1" or
//     "4.0" — or a drift where the guest pin and the host pin disagree —
//     can change the image-id and would invalidate every receipt the
//     verifier knows about. We check three pin sites in lockstep:
//       1. `private_multisig_program/Cargo.toml` (this crate; host)
//       2. `methods/guest/Cargo.toml` (the Risc0 guest source of truth)
//       3. `sdk/Cargo.toml` (host-side prover)
// ---------------------------------------------------------------------------
#[test]
fn api_cargo_toml_dep_versions_are_pinned_appropriately() {
    fn assert_risc0_zkvm_pinned(manifest_path: &str, contents: &str) {
        let mut found = false;
        for line in contents.lines() {
            let t = line.trim();
            if !t.starts_with("risc0-zkvm") {
                continue;
            }
            // Accept either bare-string form (`risc0-zkvm = "=3.0.5"`) or
            // table form (`risc0-zkvm = { version = "=3.0.5", ... }`).
            // Both must contain the exact `"=3.0.5"` literal somewhere on
            // the line; anything else is a drift.
            assert!(
                t.contains("\"=3.0.5\""),
                "risc0-zkvm dep in {manifest_path} must contain \"=3.0.5\" \
                 (got line: {t:?}). Bumping minor/major can drift the \
                 image-id; if intentional, update this sentinel AND \
                 re-snapshot the image-id."
            );
            found = true;
            break;
        }
        assert!(
            found,
            "no `risc0-zkvm = ...` line found in {manifest_path} — \
             has the dep been removed?"
        );
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let guest_manifest = format!("{manifest_dir}/../methods/guest/Cargo.toml");
    let sdk_manifest = format!("{manifest_dir}/../sdk/Cargo.toml");

    assert_risc0_zkvm_pinned(
        "private_multisig_program/Cargo.toml",
        CARGO_TOML,
    );
    assert_risc0_zkvm_pinned(
        "methods/guest/Cargo.toml",
        &std::fs::read_to_string(&guest_manifest).unwrap_or_else(|e| {
            panic!("could not read {guest_manifest}: {e}")
        }),
    );
    assert_risc0_zkvm_pinned(
        "sdk/Cargo.toml",
        &std::fs::read_to_string(&sdk_manifest).unwrap_or_else(|e| {
            panic!("could not read {sdk_manifest}: {e}")
        }),
    );
}

// ---------------------------------------------------------------------------
// 13. Unit-test count pin: src/lib.rs has five `#[test]` cases inside its
//     `#[cfg(test)] mod tests` block. Catches accidental deletion or
//     uncontrolled growth of the in-lib smoke tests.
// ---------------------------------------------------------------------------
const EXPECTED_LIB_UNIT_TESTS: usize = 5;
const EXPECTED_LIB_UNIT_TEST_NAMES: &[&str] = &[
    "image_id_is_non_zero",
    "image_id_hex_is_64_lowercase_hex_chars",
    "elf_is_non_empty",
    "approve_witness_len_pinned_at_788_bytes",
    "pack_approve_witness_layout_pins_each_slot",
];

#[test]
fn api_test_count_in_lib_unit_tests_is_5() {
    // Slice from `mod tests` to end-of-file; count `#[test]` occurrences.
    let tests_block_start = LIB_RS
        .find("mod tests")
        .expect("src/lib.rs must contain `mod tests`");
    let tests_block = &LIB_RS[tests_block_start..];

    let count = tests_block.matches("#[test]").count();
    assert_eq!(
        count, EXPECTED_LIB_UNIT_TESTS,
        "lib.rs unit-test count drifted: expected {EXPECTED_LIB_UNIT_TESTS}, got {count}. \
         If intentional, update EXPECTED_LIB_UNIT_TESTS and the names list."
    );

    for name in EXPECTED_LIB_UNIT_TEST_NAMES {
        let needle = format!("fn {name}(");
        assert!(
            tests_block.contains(&needle),
            "expected lib.rs unit test `{name}` not found inside `mod tests`"
        );
    }
}

// ---------------------------------------------------------------------------
// 14. Step-4 consumption note: the crate-level //! docs explicitly mention
//     that PLAN.md step 4 consumes APPROVE_CIRCUIT_IMAGE_ID from this crate.
// ---------------------------------------------------------------------------
#[test]
fn api_module_level_docs_mention_step_4_consumption() {
    let module_docs: String = LIB_RS
        .lines()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("//!") || t.is_empty()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        module_docs.contains("PLAN.md step 4") && module_docs.contains("APPROVE_CIRCUIT_IMAGE_ID"),
        "crate-level //! docs must mention `PLAN.md step 4` AND \
         `APPROVE_CIRCUIT_IMAGE_ID` so future contributors know the verifier \
         program depends on this surface. Got:\n{module_docs}"
    );
}
