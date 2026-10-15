//! Reading the log back: the tail, filtered by level and by trace.
//!
//! # Why this is here and not in the reader
//!
//! Because there are two readers. The daemon answers `synra logs`; the shell puts an excerpt in a diagnostic bundle. Both
//! need the same three decisions — which file is current, what counts as a debug line, and how a trace filter matches —
//! and the first version of each decision was written in the daemon's `runtime/reports.rs`, where the shell could not
//! reach it. A shell that reimplemented them would drift, and the drift would be invisible: two readers disagreeing
//! about which lines are debug is a bug nobody notices until someone compares two outputs.
//!
//! # Why the log is read as text rather than re-parsed
//!
//! Because the format belongs to the logger, and an index of one's own log is a second source of truth about it. The
//! level is found as a whitespace-separated **token**, which is what the `fmt` subscriber writes and what a hand-written
//! line in a test can reproduce.

use std::path::{Path, PathBuf};

use super::file::LOG_FILE_NAME;

/// Whether a line is a `DEBUG` or `TRACE` line.
///
/// # Why a token and not `contains(" DEBUG ")`
///
/// Because the first version did that and was wrong: a line may begin with the level — `DEBUG detail` — and then there is
/// no space before it. What follows a level is a space or the end of the line, so the level is a whole whitespace-separated
/// word. A `contains` also matches a *message* that happens to name a level, which is the other half of the bug.
#[must_use]
pub fn is_debug_or_trace(line: &str) -> bool {
    line.split_whitespace().any(|word| word == "DEBUG" || word == "TRACE")
}

/// What a caller asked for, and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogTail {
    /// The lines, oldest first.
    pub lines: Vec<String>,
    /// The file they came from, or `None` when there was no log to read.
    pub source: Option<PathBuf>,
    /// How many lines matched **before** the tail was taken.
    ///
    /// Reported separately from the length of `lines` so a caller can tell "this is everything" from "this is the last
    /// hundred of two thousand" — which is the difference between a complete log and a truncation, and a reader that
    /// cannot tell them apart will assume the first.
    pub matched: usize,
}

/// How many lines a caller gets when they do not say.
pub const DEFAULT_TAIL_LINES: usize = 100;

/// The newest file in a directory, if there is one.
///
/// By modification time rather than by name, because rotation renames: the active file keeps the plain name
/// ([`LOG_FILE_NAME`]) and the older ones are suffixed, so a name-ordered search would find the right file only by
/// accident of the suffix scheme.
#[must_use]
pub fn newest_file(directory: &Path) -> Option<PathBuf> {
    std::fs::read_dir(directory)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter_map(|path| {
            let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
            Some((modified, path))
        })
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
}

/// Reads the tail of the current log.
///
/// `verbose` keeps `DEBUG` and `TRACE` lines, which are hidden otherwise; `trace` keeps only lines that mention the id.
///
/// The two compose, and that is deliberate: a trace's lines are usually the debug ones, so a caller asking for a trace
/// without `verbose` gets the intersection it asked for rather than a surprise widening.
#[must_use]
pub fn tail(directory: &Path, lines: usize, verbose: bool, trace: Option<&str>) -> LogTail {
    let Some(source) = newest_file(directory) else {
        return LogTail { lines: Vec::new(), source: None, matched: 0 };
    };
    let Ok(text) = std::fs::read_to_string(&source) else {
        // Unreadable is reported as "nothing to read" rather than as an error, because the caller's next step is the
        // same either way and a diagnostic bundle must not fail over a log it could not include — the omission list is
        // where that gets said.
        return LogTail { lines: Vec::new(), source: Some(source), matched: 0 };
    };

    let wanted: Vec<&str> = text
        .lines()
        .filter(|line| verbose || !is_debug_or_trace(line))
        .filter(|line| trace.is_none_or(|id| line.contains(id)))
        .collect();

    let matched = wanted.len();
    let start = matched.saturating_sub(lines);
    let tail = wanted.get(start..).unwrap_or(&[]).iter().map(|line| (*line).to_owned()).collect();

    LogTail { lines: tail, source: Some(source), matched }
}

/// The path the log is written to in a directory, whether or not it exists yet.
#[must_use]
pub fn path_in(directory: &Path) -> PathBuf {
    directory.join(LOG_FILE_NAME)
}
