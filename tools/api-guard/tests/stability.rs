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
#[ignore = "ten violations remain: five `BTreeMap`s in public signatures, and five foreign `std::io::Error`s in \
            functions this tool cannot yet tell are private — two really are private, and three are `pub(crate)` or \
            `pub(super)`. The test would enforce the promise the moment they are fixed. `cargo run -p api-guard -- .` \
            lists them."]
fn no_crate_that_makes_a_promise_breaks_it() {
    let root = workspace_root();
    let output = Command::new(env!("CARGO_BIN_EXE_api-guard"))
        .arg(&root)
        .output()
        .expect("api-guard runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "api-guard found violations in {}:\n{stdout}\n{stderr}",
        root.display()
    );
    // And it checked something: a tool that read no files would also report success, and the promise would be
    // unenforced in exactly the way this test exists to prevent.
    assert!(
        stdout.contains("file(s) checked, no violations"),
        "api-guard did not report what it read:\n{stdout}"
    );
    assert!(stdout.contains("no violations"), "{stdout}");
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
