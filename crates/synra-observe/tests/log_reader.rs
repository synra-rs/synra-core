//! Reading the log back: which file, which level, which trace.
//!
//! # Why these live beside the reader
//!
//! They used to live in the daemon's `runtime/tests.rs`, because the reader did. Two of them test a pure function of a
//! line — is this a `DEBUG` line — and a pure function belongs with its definition rather than three crates away in a
//! binary that happens to call it. The daemon's own tests still cover what the daemon adds: the JSON shape it answers
//! with.

// The reader is a fixture-free module, but its tests need a directory and a file, and a test that cannot unwrap a
// temporary directory reports its own bug as a mystery.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::PathBuf;

use synra_observe::logging::{is_debug_or_trace, newest_file, tail};

/// A directory that removes itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-reader-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_level_filter_matches_a_token_in_either_shape() {
    // Moved here from the daemon, which no longer owns this decision.
    assert!(is_debug_or_trace("DEBUG detail"));
    assert!(is_debug_or_trace("2026-01-01T00:00:00Z TRACE detail"));
    assert!(!is_debug_or_trace("INFO started"));
    assert!(!is_debug_or_trace("WARN something"));
}

#[test]
fn the_level_filter_has_a_known_cost_and_it_is_not_hidden() {
    // ★ A text filter over a text log cannot tell a level from a message that names one, and this test says so rather
    // than leaving it to be discovered.
    //
    // The alternatives were worse for this use: keeping only lines that *start* with a level would need the format to be
    // fixed, and the log format belongs to the logger. A user who needs the line passes `--verbose`.
    assert!(
        is_debug_or_trace("INFO turning DEBUG off"),
        "the documented cost of the filter has changed; the doc comment on `is_debug_or_trace` says what it is"
    );
}

#[test]
fn the_newest_file_is_the_one_by_modification_time() {
    // By time rather than by name, because rotation renames: the active file keeps the plain name and the older ones are
    // suffixed, so a name-ordered search finds the right file only by accident of the suffix scheme.
    let dir = TempDir::new("newest");
    std::fs::write(dir.path().join("a-old.log"), "old\n").expect("a log");
    // A sleep, because two writes in one millisecond are ordered by nothing.
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(dir.path().join("b-new.log"), "new\n").expect("a log");

    let newest = newest_file(dir.path()).expect("a file");
    assert!(newest.ends_with("b-new.log"), "{newest:?}");
}

#[test]
fn a_directory_with_no_log_yields_nothing_rather_than_an_error() {
    // The first run of a fresh installation. A reader that failed here would make an empty log look like a fault, and
    // the diagnostic bundle that includes logs would refuse to be built on a machine that has nothing wrong with it.
    let dir = TempDir::new("empty");
    let read = tail(dir.path(), 10, false, None);

    assert!(read.lines.is_empty());
    assert!(read.source.is_none(), "there was no file to name");
    assert_eq!(read.matched, 0);
}

#[test]
fn the_tail_counts_what_matched_and_returns_only_what_was_asked_for() {
    // ★ `matched` and the length of `lines` are different numbers on purpose: one says "this is everything" and the
    // other says "this is the last two of five". A caller that cannot tell them apart will report a truncation as a
    // complete log.
    let dir = TempDir::new("tail");
    let body: String = (1..=5).map(|n| format!("INFO line {n}\n")).collect();
    std::fs::write(dir.path().join("synra.log"), body).expect("a log");

    let read = tail(dir.path(), 2, false, None);
    assert_eq!(read.matched, 5, "five lines matched before the tail was taken");
    assert_eq!(read.lines, ["INFO line 4", "INFO line 5"], "the tail is the newest, oldest first");
}

#[test]
fn a_trace_filter_composes_with_the_level_filter() {
    // The two filters stack rather than override each other: asking for a trace does not by itself reveal debug lines,
    // and asking for debug does not by itself narrow to a trace. The CLI's `--trace` sets both, which is why the
    // combination is the case worth pinning.
    let dir = TempDir::new("compose");
    std::fs::write(
        dir.path().join("synra.log"),
        "INFO a trace_id=t1\nDEBUG b trace_id=t1\nINFO c trace_id=t2\nINFO d\n",
    )
    .expect("a log");

    // Trace only, quiet: one line, because `b` is a debug line.
    let quiet = tail(dir.path(), 10, false, Some("t1"));
    assert_eq!(quiet.lines, ["INFO a trace_id=t1"]);

    // Trace and verbose: both of t1's lines.
    let wide = tail(dir.path(), 10, true, Some("t1"));
    assert_eq!(wide.lines, ["INFO a trace_id=t1", "DEBUG b trace_id=t1"]);

    // Neither: everything, including the lines that belong to no trace.
    let all = tail(dir.path(), 10, true, None);
    assert_eq!(all.matched, 4);
}
