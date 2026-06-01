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

use private_multisig_program::{
    image_id_hex, APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID, VERIFIER_PROGRAM_ELF,
    VERIFIER_PROGRAM_IMAGE_ID,
};

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
// 2b. Compile-time type pins for the SPEL verifier program's ELF + image-id.
//     Step-7 e2e harness consumes these to discharge the approve receipt's
//     composition assumption via the outer prover.
// ---------------------------------------------------------------------------
#[test]
fn api_verifier_program_elf_type_pin() {
    let _: &'static [u8] = VERIFIER_PROGRAM_ELF;
    assert!(
        !VERIFIER_PROGRAM_ELF.is_empty(),
        "verifier program ELF must not be empty"
    );
}

#[test]
fn api_verifier_program_image_id_type_pin() {
    let _: [u32; 8] = VERIFIER_PROGRAM_IMAGE_ID;
    // A freshly-compiled image cannot have an all-zero id without SHA-256
    // producing a zero digest on the ELF (preimage-hard).
    assert_ne!(VERIFIER_PROGRAM_IMAGE_ID, [0u32; 8]);
    // The two image-ids must be distinct — same image-id would mean the
    // verifier and approve circuits compiled to byte-identical ELFs,
    // which would be a build-system bug.
    assert_ne!(
        VERIFIER_PROGRAM_IMAGE_ID, APPROVE_CIRCUIT_IMAGE_ID,
        "verifier program and approve circuit must have distinct image-ids"
    );
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
// 5. Public-item count pin: src/lib.rs exposes exactly eight `pub ` items
//    (APPROVE_CIRCUIT_ELF, APPROVE_CIRCUIT_IMAGE_ID, VERIFIER_PROGRAM_ELF,
//    VERIFIER_PROGRAM_IMAGE_ID, BUILD_USED_DOCKER, image_id_hex,
//    APPROVE_WITNESS_LEN, pack_approve_witness). A future PR that adds a
//    new pub item must update this constant AND add a rustdoc block
//    (enforced by the next sentinel).
// ---------------------------------------------------------------------------
const EXPECTED_PUB_ITEM_COUNT: usize = 8;

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
// 12. Dependency-pin sentinel: every risc0 crate the workspace consumes is
//     pinned exactly to "=3.0.5". A silent bump to "3.1" or "4.0" — or a
//     drift where the guest pin and the host pin disagree — can change the
//     image-id and would invalidate every receipt the verifier knows about.
//     We check four pin sites in lockstep:
//       1. `private_multisig_program/Cargo.toml` (this crate; host) — risc0-zkvm
//       2. `methods/guest/Cargo.toml` (the Risc0 guest source of truth) — risc0-zkvm
//       3. `sdk/Cargo.toml` (host-side prover) — risc0-zkvm
//       4. `methods/Cargo.toml` (host build glue) — risc0-build
// ---------------------------------------------------------------------------
#[test]
fn api_cargo_toml_dep_versions_are_pinned_appropriately() {
    fn assert_dep_pinned(manifest_path: &str, dep_name: &str, contents: &str) {
        // Match `^<dep_name>\s*=` exactly. `starts_with(dep_name)` alone
        // would accept `risc0-zkvm-platform = "0.x"` as a hit and then
        // skip the real `risc0-zkvm` line below it.
        let mut match_count = 0usize;
        for line in contents.lines() {
            let t = line.trim();
            if !t.starts_with(dep_name) {
                continue;
            }
            let rest = &t[dep_name.len()..];
            let next = rest.chars().next();
            // The next char after the dep name must be whitespace or `=`
            // — anything else (`-`, alphanumeric, `_`) means we matched a
            // longer dep name (e.g. `risc0-zkvm-platform`).
            if !matches!(next, Some(c) if c == '=' || c.is_whitespace()) {
                continue;
            }
            // Accept either bare-string form (`<dep> = "=3.0.5"`) or
            // table form (`<dep> = { version = "=3.0.5", ... }`). Both
            // must contain the exact `"=3.0.5"` literal somewhere on the
            // line; anything else is a drift. Check EVERY match (not just
            // the first) so a `[dev-dependencies]` re-declaration that
            // drifts is also caught.
            assert!(
                t.contains("\"=3.0.5\""),
                "{dep_name} dep in {manifest_path} must contain \"=3.0.5\" \
                 (got line: {t:?}). Bumping minor/major can drift the \
                 image-id; if intentional, update this sentinel AND \
                 re-snapshot the image-id."
            );
            // Reject same-line `git = ` / `path = ` source overrides.
            // Without this check, `risc0-zkvm = { version = "=3.0.5", git
            // = "https://evil.example/risc0" }` would pass the version
            // assertion while silently redirecting the source. cargo-deny
            // `[sources] allow-git` catches it independently, but
            // belt-and-braces.
            assert!(
                !t.contains("git =") && !t.contains("path ="),
                "{dep_name} dep in {manifest_path} must not redirect to \
                 a git or path source on the same line (got: {t:?}). \
                 risc0 crates ship via crates.io only."
            );
            match_count += 1;
        }
        assert!(
            match_count > 0,
            "no `{dep_name} = ...` line found in {manifest_path} — \
             has the dep been removed?"
        );
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let guest_manifest = format!("{manifest_dir}/../methods/guest/Cargo.toml");
    let sdk_manifest = format!("{manifest_dir}/../sdk/Cargo.toml");
    let methods_manifest = format!("{manifest_dir}/../methods/Cargo.toml");

    assert_dep_pinned(
        "private_multisig_program/Cargo.toml",
        "risc0-zkvm",
        CARGO_TOML,
    );
    assert_dep_pinned(
        "methods/guest/Cargo.toml",
        "risc0-zkvm",
        &std::fs::read_to_string(&guest_manifest)
            .unwrap_or_else(|e| panic!("could not read {guest_manifest}: {e}")),
    );
    assert_dep_pinned(
        "sdk/Cargo.toml",
        "risc0-zkvm",
        &std::fs::read_to_string(&sdk_manifest)
            .unwrap_or_else(|e| panic!("could not read {sdk_manifest}: {e}")),
    );
    assert_dep_pinned(
        "methods/Cargo.toml",
        "risc0-build",
        &std::fs::read_to_string(&methods_manifest)
            .unwrap_or_else(|e| panic!("could not read {methods_manifest}: {e}")),
    );
}

// ---------------------------------------------------------------------------
// 13. nssa_core Cargo.lock SHA sentinel. `nssa_core` is intentionally
//     still tag-pinned at `v0.2.0-rc3` (see methods/guest/Cargo.toml for
//     the unification rationale with SPEL's transitive pin), but a tag
//     can be retagged upstream — `Cargo.lock` is the only place that
//     records the resolved SHA. If LEZ maintainers retag v0.2.0-rc3 to a
//     different commit, the next `cargo update -p nssa_core` would
//     silently swap it. This sentinel asserts the lockfile records the
//     SHA we audited; the same defense the SPEL rev pin provides at the
//     manifest level.
// ---------------------------------------------------------------------------
const NSSA_CORE_AUDITED_SHA: &str = "cf3639d8252040d13b3d4e933feb19b42c76e14a";

#[test]
fn api_nssa_core_lockfile_sha_matches_audited_value() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let lockfile_path = format!("{manifest_dir}/../Cargo.lock");
    let lockfile = std::fs::read_to_string(&lockfile_path)
        .unwrap_or_else(|e| panic!("could not read {lockfile_path}: {e}"));

    // Find the `[[package]]` block whose `name = "nssa_core"` and read
    // the next `source =` line. Anchor on the exact name to avoid a
    // future `nssa_core_extras` etc. matching by prefix.
    let needle = "name = \"nssa_core\"\n";
    let Some(name_pos) = lockfile.find(needle) else {
        panic!(
            "no `[[package]] name = \"nssa_core\"` block found in \
             Cargo.lock — has the dep been removed?"
        );
    };
    let after_name = &lockfile[name_pos + needle.len()..];
    // The `source` line is within a small window of the name line in
    // the [[package]] block (cargo emits ~3-5 lines per package).
    let block = &after_name[..after_name.len().min(400)];
    assert!(
        block.contains(NSSA_CORE_AUDITED_SHA),
        "nssa_core block in Cargo.lock does not reference the audited \
         SHA `{NSSA_CORE_AUDITED_SHA}`. The v0.2.0-rc3 tag may have been \
         retagged upstream. Block window:\n{block}"
    );
}

// ---------------------------------------------------------------------------
// 14. SPEL Cargo.lock rev sentinel. The four consuming manifests
//      (idl-gen, cli, methods/guest, private_multisig_program) all carry
//      `rev = "84f50d4a..."`, but a manifest-only review is the only
//      enforcement — there is no `cargo`-level reject of a rev mismatch
//      between manifests so long as Cargo.lock resolves consistently.
//      §11 schema-gates lists "SPEL rev pin" as a CI gate; this sentinel
//      makes that claim load-bearing by asserting the resolved SHA in
//      Cargo.lock matches the audited value, mirroring the nssa_core
//      defense.
// ---------------------------------------------------------------------------
const SPEL_AUDITED_REV: &str = "84f50d4aa473a70b72a16a7fb468c5618277cdd7";

#[test]
fn api_spel_framework_lockfile_rev_matches_audited_value() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let lockfile_path = format!("{manifest_dir}/../Cargo.lock");
    let lockfile = std::fs::read_to_string(&lockfile_path)
        .unwrap_or_else(|e| panic!("could not read {lockfile_path}: {e}"));

    // SPEL is split into three crates (spel-framework, spel-framework-core,
    // spel-framework-macros), each emitted as its own [[package]] block.
    // We assert each one's source URL references the audited rev SHA.
    for crate_name in [
        "spel-framework",
        "spel-framework-core",
        "spel-framework-macros",
    ] {
        let needle = format!("name = \"{crate_name}\"\n");
        let Some(name_pos) = lockfile.find(&needle) else {
            panic!(
                "no `[[package]] name = \"{crate_name}\"` block found in \
                 Cargo.lock — has the dep been removed?"
            );
        };
        let after_name = &lockfile[name_pos + needle.len()..];
        let block = &after_name[..after_name.len().min(400)];
        assert!(
            block.contains(SPEL_AUDITED_REV),
            "{crate_name} block in Cargo.lock does not reference the audited \
             SPEL rev `{SPEL_AUDITED_REV}`. A consuming manifest may have \
             bumped the rev without going through audit. Block window:\n{block}"
        );
    }
}

// ---------------------------------------------------------------------------
// 15. deny.toml allow-git sentinel. The SPEL license-clarify blocks
//     (deny.toml [[licenses.clarify]] for spel-framework{,-core,-macros})
//     bind by crate name only — cargo-deny 0.19.7's schema does not
//     accept a `version` key. The compensating defense is the
//     `[sources] allow-git` whitelist that limits the SPEL crate name to
//     coming from `github.com/logos-co/spel` only. If a future PR
//     accidentally relaxes that allowlist (adds a wildcard, removes the
//     entry), the clarify becomes a name-only trust grant for any
//     `spel-framework`-named crate from any source. This sentinel
//     ensures the canonical SPEL URL stays in the allowlist.
// ---------------------------------------------------------------------------
#[test]
fn api_deny_toml_keeps_spel_source_in_allowlist() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let deny_path = format!("{manifest_dir}/../deny.toml");
    let deny = std::fs::read_to_string(&deny_path)
        .unwrap_or_else(|e| panic!("could not read {deny_path}: {e}"));

    // Locate the `allow-git = [` opening and the matching `]`. We then
    // assert the SPEL URL is inside that bracket group, with leading
    // whitespace + quote — a comment elsewhere in the file that happens
    // to contain the URL string would NOT satisfy the assertion.
    let open = deny
        .find("allow-git = [")
        .unwrap_or_else(|| panic!("deny.toml does not declare an `allow-git = [` array"));
    let after_open = open + "allow-git = [".len();
    let close = deny[after_open..]
        .find(']')
        .unwrap_or_else(|| panic!("deny.toml `allow-git = [` array is not terminated by `]`"));
    let group = &deny[after_open..after_open + close];

    // Within the array, every URL is on its own line as `    "url",` after
    // optional whitespace. Stripping leading whitespace from each line and
    // matching on the quoted form rejects both bare-string and
    // comment-shadowed mentions.
    let url_quoted = "\"https://github.com/logos-co/spel\"";
    let found = group
        .lines()
        .map(str::trim_start)
        .any(|l| !l.starts_with('#') && l.contains(url_quoted));
    assert!(
        found,
        "deny.toml `[sources] allow-git` must keep the SPEL URL \
         {url_quoted} as a live array entry (comments don't count) — \
         removing it would break the defense-in-depth chain documented \
         at the [[licenses.clarify]] blocks (cargo-deny clarify binds \
         by crate name only; the allow-git URL is what scopes the trust \
         grant to the audited source). Got group:\n{group}"
    );
}

// ---------------------------------------------------------------------------
// 16. PDA-seed shape sentinel for the `approve` handler's NullifierEntry.
//     The double-vote-rejection invariant (THREAT_MODEL T2.2 / T3.x) hinges
//     on the nullifier-entry PDA being seeded by `(proposal, nullifier)` —
//     binding each nullifier to its proposal. A malicious or careless PR
//     that drops `account("proposal")` from the seed list would still pass
//     the golden-IDL diff if the IDL is regenerated alongside the change.
//     This source-text check is the independent semantic guard: it parses
//     out the EXACT `pda = [...]` bracket group surrounding the literal
//     and asserts the seed shape inside that group, so a "historically
//     bound to account(\"proposal\")" decoy comment outside the brackets
//     cannot satisfy the assertion.
// ---------------------------------------------------------------------------
#[test]
fn api_approve_nullifier_entry_pda_seed_shape_is_audited() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let verifier_src_path = format!("{manifest_dir}/../methods/guest/src/bin/private_multisig.rs");
    let verifier_src = std::fs::read_to_string(&verifier_src_path)
        .unwrap_or_else(|e| panic!("could not read {verifier_src_path}: {e}"));

    // Locate the literal that anchors the nullifier-entry seed declaration.
    let nulli = verifier_src
        .find(r#"literal("pmsig_nulli__")"#)
        .expect("nullifier-entry PDA seed list with `literal(\"pmsig_nulli__\")` not found in verifier source");

    // Walk backward from the anchor to the most recent `pda = [` opening,
    // then forward to the matching `]` accounting for nested brackets.
    // We assert the audited substrings appear inside that bracket group
    // and nowhere else — a decoy comment outside the brackets would never
    // satisfy the check.
    let pre = &verifier_src[..nulli];
    let pda_open_rel = pre.rfind("pda = [").unwrap_or_else(|| {
        panic!(
            "no `pda = [` opening found before `literal(\"pmsig_nulli__\")` \
             at byte offset {nulli}"
        )
    });
    let bracket_start = pda_open_rel + "pda = [".len();

    // Find the matching close-bracket starting from bracket_start, tracking
    // nested `[` / `]` so a sub-array (none today, but defensive) wouldn't
    // close the group prematurely.
    let mut depth: i32 = 1;
    let mut close_offset = None;
    for (idx, ch) in verifier_src[bracket_start..].char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    close_offset = Some(bracket_start + idx);
                    break;
                }
            }
            _ => {}
        }
    }
    let bracket_end = close_offset
        .expect("no matching `]` found for the `pda = [` group around the nullifier-entry");
    let seed_group = &verifier_src[bracket_start..bracket_end];

    assert!(
        seed_group.contains(r#"literal("pmsig_nulli__")"#),
        "nullifier-entry `pda = [...]` group must contain `literal(\"pmsig_nulli__\")`. \
         Got:\n{seed_group}"
    );
    assert!(
        seed_group.contains(r#"account("proposal")"#),
        "nullifier-entry `pda = [...]` group must bind to the proposal \
         account via `account(\"proposal\")` — without it, the same \
         nullifier can be replayed across proposals (T2.2 regression). \
         Got:\n{seed_group}"
    );
    assert!(
        seed_group.contains(r#"arg("nullifier")"#),
        "nullifier-entry `pda = [...]` group must include `arg(\"nullifier\")` — \
         without it, a single member can double-vote on the same proposal. \
         Got:\n{seed_group}"
    );
}

// ---------------------------------------------------------------------------
// 17. Unit-test count pin: src/lib.rs has five `#[test]` cases inside its
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
// 18. Step-4 consumption note: the crate-level //! docs explicitly mention
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
