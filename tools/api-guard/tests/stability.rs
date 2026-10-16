//! The stability promise, checked by the thing that checks it.
//!
//! # Why this is a test and not a CI step
//!
//! Because there is no CI step in this repository, and a check nothing runs is a check that passes by being absent.
//! `STABILITY.md` says which crates make a promise and `tools/api-guard` is what reads them for the rules that promise
//! is made of — and until this file existed, the only way either had any effect was somebody remembering to run the
//! tool. Running it here means `cargo test` is what enforces the promise, which is the one command this repository's
//! own instructions already say to run.
//!
//! # What a failure looks like
//!
//! The tool's own output, printed rather than summarised: a violation names the file, the line and the rule, and
//! re-stating that here would be a second wording of the same finding.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::indexing_slicing))]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The workspace root, from this crate's own directory.
fn workspace_root() -> PathBuf {
    // `tools/api-guard` is two levels below the root, and `CARGO_MANIFEST_DIR` is what cargo guarantees rather than a
    // path relative to wherever the test binary happens to run from.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

#[test]
fn no_crate_that_makes_a_promise_breaks_it() {
    // ★ The promise is checked, and the three deviations that remain are named here rather than being suppressed.
    //
    // Suppressing them — an `#[ignore]` on this test — would mean a *new* violation also went unnoticed, which is the
    // failure mode a check like this has: it stops being a check and becomes a comment. Naming them means the check
    // still fires for everything else, and that fixing one of them fires too — because a deviation that has been fixed
    // is a list that is out of date, and a list nobody re-reads is how the next one gets added.
    let root = workspace_root();
    let output = Command::new(env!("CARGO_BIN_EXE_api-guard"))
        .arg(&root)
        .output()
        .expect("api-guard runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reported: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("holds io::Error") || line.contains("exposes BTreeMap"))
        .collect();

    // Each of the three is one line in a file, and each is a deviation: the rule is about a *public* signature, and
    // none of these is one. They are the tool's documented false-positive surface — telling a `pub(crate) fn` at the
    // root of a module from a `pub fn` inside a private module needs the module tree, and this tool reads lines.
    let expected = [
        // A private helper: `fn` with no visibility at all is not public API.
        //
        // ★ The line moved from 467 to 520 when `PeerLink` gained its write deadline. The deviation is the same one — the
        // tool reads lines and cannot tell a private `fn` from a public one without the module tree — so what changed is
        // where it is, and a check that pinned the old number would have failed for a reason that had nothing to do with
        // stability. It is still pinned by line rather than by name, which is the fragile part: two helpers with one
        // signature would be indistinguishable here.
        "crates\\synra-core\\src\\link.rs:520",
        // `pub(crate)`: reachable inside the crate, not by a consumer.
        "crates\\synra-core\\src\\peer\\wire.rs:138",
        // `pub(super)`: reachable by the parent module, not by a consumer.
        "crates\\synra-core\\src\\peer\\wire.rs:160",
    ];
    let mut unexpected: Vec<&str> = reported
        .iter()
        .copied()
        .filter(|line| !expected.iter().any(|known| line.contains(known)))
        .collect();
    unexpected.sort_unstable();
    assert!(
        unexpected.is_empty(),
        "api-guard found violations beyond the three deviations this test records:\n{}\n{stderr}",
        unexpected.join("\n")
    );

    let mut missing: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|known| !reported.iter().any(|line| line.contains(known)))
        .collect();
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "these deviations are gone, so this list is out of date and should be shortened:\n{}",
        missing.join("\n")
    );
}

#[test]
fn the_crates_the_promise_covers_are_the_ones_the_tool_reads() {
    // ★ The join between the document and the tool. `STABILITY.md` names the tiers; `api_guard::CRATES` is what the
    // tool walks. A crate moved between tiers in one and not the other would be a crate whose promise nobody checks —
    // and the failure would be silent, because the tool would report success for a set it was never told about.
    let root = workspace_root();
    let document = std::fs::read_to_string(root.join("STABILITY.md")).expect("STABILITY.md");
    // The stable and semi-stable rows are the ones with a promise; the internal row says "nothing — and that is the
    // point", so those crates are deliberately absent.
    let promised: Vec<&str> = document
        .lines()
        .filter(|line| line.starts_with("| **Stable**") || line.starts_with("| **Semi-stable**"))
        .flat_map(|line| line.split('`').skip(1).step_by(2))
        .filter(|name| name.starts_with("synra-"))
        .collect();
    assert!(promised.len() >= 7, "the document names {} crate(s): {promised:?}", promised.len());

    for name in promised {
        let directory = root.join("crates").join(name).join("src");
        assert!(directory.is_dir(), "{name} is promised by STABILITY.md and has no source directory");
    }
}
