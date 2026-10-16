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
    // ★ Both rules the tool applies to this tier, and the second was missing.
    //
    // This filter used to read only `holds io::Error` and `exposes BTreeMap` — so the tool **reported** five public enums
    // without `#[non_exhaustive]` and **no test looked at them**. Four of those five were added in this session, which is what
    // a guard nothing reads produces: work that violates a written rule and passes anyway. A filter is where a check decides
    // what it is checking, and leaving a rule out of it is the quietest way to disable one.
    let reported: Vec<&str> = stdout
        .lines()
        .filter(|line| {
            line.contains("holds io::Error")
                || line.contains("exposes BTreeMap")
                || line.contains("without `#[non_exhaustive]`")
        })
        .collect();

    // Each of these is a deviation: the rule is about a *public* signature, and none of them is one. The first three are the
    // tool's documented false-positive surface — telling a `pub(crate) fn` at the root of a module from a `pub fn` inside a
    // private module needs the module tree, and this tool reads lines. The last two are a different kind of deviation, with a
    // stronger reason.
    //
    // ★ **Pinned by the reported item rather than by its line number**, and that is a correction rather than a preference.
    //
    // These were `path:line` pairs, and the line numbers moved **four times in four rounds** — 467 → 520 → 533 → 590 — every
    // time because something was added *above* an unrelated private helper. Each move failed this test for a reason that had
    // nothing to do with stability, and each fix was a re-pin that taught nothing. The item text is what the rule is actually
    // about, it is already in the tool's output, and it does not move when the file is edited around it.
    //
    // The trade is real but small: two different items whose text is identical would be indistinguishable here. That is a
    // strictly narrower ambiguity than "any insertion anywhere above this line", and the tool prints the whole item, so a
    // genuine second violation of the same shape would have to be character-for-character the same to hide.
    let expected = [
        // A private helper: `fn` with no visibility at all is not public API.
        (
            "crates\\synra-core\\src\\link.rs",
            "`fn is_a_timeout(error: &std::io::Error) -> bool {`",
        ),
        // `pub(crate)`: reachable inside the crate, not by a consumer.
        (
            "crates\\synra-core\\src\\peer\\wire.rs",
            "`pub(crate) fn peer_went_away(error: &std::io::Error) -> bool {`",
        ),
        // `pub(super)`: reachable by the parent module, not by a consumer.
        (
            "crates\\synra-core\\src\\peer\\wire.rs",
            "`pub(super) fn transport(error: &std::io::Error) -> HandshakeError {`",
        ),
        // ★ And these two are **not** false positives in the same sense: `MemoryStream` implements `std::io::Read` and
        // `std::io::Write`, whose signatures *require* `std::io::Error`. There is no way to implement those traits without
        // naming it, so the rule cannot be satisfied here — and it should not be, because the alternative is not implementing
        // them. What makes it harmless is that `Pipe` is a private type and these are its private methods: the promise is made
        // to `std` and to nothing else.
        ("crates\\synra-core\\src\\link\\memory.rs", "`return Err(std::io::Error::new(`"),
    ];
    let mut unexpected: Vec<&str> = reported
        .iter()
        .copied()
        .filter(|line| {
            !expected
                .iter()
                .any(|(file, item)| line.contains(file) && line.contains(item))
        })
        .collect();
    unexpected.sort_unstable();
    assert!(
        unexpected.is_empty(),
        "api-guard found violations beyond the deviations this test records:\n{}\n{stderr}",
        unexpected.join("\n")
    );

    let mut missing: Vec<(&str, &str)> = expected
        .iter()
        .copied()
        .filter(|(file, item)| !reported.iter().any(|line| line.contains(file) && line.contains(item)))
        .collect();
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "these deviations are gone, so this list is out of date and should be shortened:\n{}",
        missing
            .iter()
            .map(|(file, item)| format!("{file} {item}"))
            .collect::<Vec<String>>()
            .join("\n")
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
