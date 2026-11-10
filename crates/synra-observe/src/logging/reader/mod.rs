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

mod follow;
mod tail;

pub use follow::{FOLLOW_POLL, FollowSummary, follow};
pub use tail::{DEFAULT_TAIL_LINES, LogTail, newest_file, tail};

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

/// Whether a line passes the level and trace filters.
///
/// One function for the tail and the follower: two copies would disagree the first time either was touched, and the
/// disagreement would be invisible — a follower showing a `DEBUG` line that `synra logs` hides.
fn keep(line: &str, verbose: bool, trace: Option<&str>) -> bool {
    (verbose || !is_debug_or_trace(line)) && trace.is_none_or(|id| line.contains(id))
}

/// The path the log is written to in a directory, whether or not it exists yet.
#[must_use]
pub fn path_in(directory: &Path) -> PathBuf {
    directory.join(LOG_FILE_NAME)
}

#[cfg(test)]
mod tests;
