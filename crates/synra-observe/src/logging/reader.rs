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
use std::time::Duration;

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
        .filter(|line| keep(line, verbose, trace))
        .collect();

    let matched = wanted.len();
    let start = matched.saturating_sub(lines);
    let tail = wanted.get(start..).unwrap_or(&[]).iter().map(|line| (*line).to_owned()).collect();

    LogTail { lines: tail, source: Some(source), matched }
}

/// Whether a line passes the level and trace filters.
///
/// One function for the tail and the follower: two copies would disagree the first time either was touched, and the
/// disagreement would be invisible — a follower showing a `DEBUG` line that `synra logs` hides.
fn keep(line: &str, verbose: bool, trace: Option<&str>) -> bool {
    (verbose || !is_debug_or_trace(line)) && trace.is_none_or(|id| line.contains(id))
}

/// How often a follower looks for new bytes when nothing has arrived.
pub const FOLLOW_POLL: Duration = Duration::from_millis(200);

/// How a follow ended, and how much it sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowSummary {
    /// How many lines were handed to the sink.
    pub lines: usize,
}

/// Follows the active log from its tail, handing each new line to `sink`.
///
/// Returns when `sink` answers `false` — the shape a disconnected client has, and the shape a test uses to ask for three
/// lines. A missing directory or file is **waited for**, not an error: the daemon starts its log before serving, but a
/// follower started at the same moment can look before the first line exists.
///
/// # Why the bytes rather than a re-read of the whole file
///
/// Because the point of following is a log that grows. Re-reading the file on every poll would send the tail again each
/// time — the "follow" would repeat itself — and would be quadratic in the file's size. The reader keeps an offset and
/// reads what was appended, with one correction: a length **smaller** than the offset means rotation or truncation, and
/// the reader starts again from zero rather than reading past the end of a replaced file.
///
/// # Why a partial line waits
///
/// A writer puts a line down in one call, but a reader can still catch it half-written. The incomplete tail is kept and
/// joined with the next read, so a line is never split into two.
pub fn follow<F>(
    directory: &Path,
    lines: usize,
    verbose: bool,
    trace: Option<&str>,
    poll: Duration,
    mut sink: F,
) -> FollowSummary
where
    F: FnMut(&str) -> bool,
{
    let path = path_in(directory);
    let mut offset = 0u64;
    let mut pending: Vec<u8> = Vec::new();
    let mut collected: Vec<String> = Vec::new();
    let mut initial = true;
    let mut sent = 0usize;

    loop {
        let length = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());
        if length < offset {
            // Rotated or truncated. The old bytes are not ours to read any more, and a partial line from them is gone
            // with them.
            offset = 0;
            pending.clear();
        }
        if length > offset {
            if let Ok(mut file) = std::fs::File::open(&path) {
                use std::io::{Read as _, Seek as _, SeekFrom};
                if file.seek(SeekFrom::Start(offset)).is_ok() {
                    let mut chunk = Vec::new();
                    if file.read_to_end(&mut chunk).is_ok() {
                        offset = offset.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                        pending.extend_from_slice(&chunk);
                    }
                    else {
                        // A read that failed must not spin: take what the metadata said and wait for the next poll.
                        offset = length;
                    }
                }
                else {
                    offset = length;
                }
            }
            else {
                offset = length;
            }
        }

        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end_matches(['\n', '\r']);
            if !keep(text, verbose, trace) {
                continue;
            }
            if initial {
                collected.push(text.to_owned());
            }
            else {
                sent = sent.saturating_add(1);
                if !sink(text) {
                    return FollowSummary { lines: sent };
                }
            }
        }

        if initial {
            let start = collected.len().saturating_sub(lines);
            for line in collected.drain(start..) {
                sent = sent.saturating_add(1);
                if !sink(&line) {
                    return FollowSummary { lines: sent };
                }
            }
            initial = false;
        }

        if length <= offset {
            std::thread::sleep(poll);
        }
    }
}

/// The path the log is written to in a directory, whether or not it exists yet.
#[must_use]
pub fn path_in(directory: &Path) -> PathBuf {
    directory.join(LOG_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn scratch(label: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("synra-follow-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a directory");
        directory
    }

    fn append(path: &Path, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("the log");
        file.write_all(text.as_bytes()).expect("a line");
        file.flush().expect("flushed");
    }

    #[test]
    fn following_sends_the_tail_then_each_appended_line() {
        // ★ The tail is the starting point, not the answer: a follow that returned after its first read would be the
        // snapshot `--follow` used to pretend to be. The sink appends a line to prove the second read happens.
        let directory = scratch("tail");
        let path = path_in(&directory);
        std::fs::write(&path, "one\ntwo\nthree\n").expect("a log");

        let mut seen = Vec::new();
        let summary = follow(&directory, 1, false, None, Duration::from_millis(5), |line| {
            seen.push(line.to_owned());
            if seen.len() == 1 {
                append(&path, "four\n");
                true
            }
            else {
                false
            }
        });

        assert_eq!(seen, vec!["three", "four"]);
        assert_eq!(summary.lines, 2, "both lines were handed over");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn following_hides_debug_lines_unless_asked() {
        // ★ One filter, two readers: the same `keep` that `tail` uses, so a follower cannot show a line `synra logs`
        // hides. `DEBUG` is a level token, not a message word — the reader's own rule.
        let directory = scratch("levels");
        let path = path_in(&directory);
        std::fs::write(&path, "ERROR one\nDEBUG two\n").expect("a log");

        let mut quiet = Vec::new();
        follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
            quiet.push(line.to_owned());
            false
        });
        assert_eq!(quiet, vec!["ERROR one"]);

        let mut verbose = Vec::new();
        follow(&directory, 10, true, None, Duration::from_millis(5), |line| {
            verbose.push(line.to_owned());
            verbose.len() < 2
        });
        assert_eq!(verbose, vec!["ERROR one", "DEBUG two"]);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn following_starts_over_when_the_file_is_truncated() {
        // ★ Rotation and truncation are the same correction: a length smaller than the offset means the bytes the reader
        // was waiting past are gone. Reading on would sit at an offset the new file never reaches.
        let directory = scratch("rotation");
        let path = path_in(&directory);
        std::fs::write(&path, "before\n").expect("a log");

        let mut seen = Vec::new();
        follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
            seen.push(line.to_owned());
            if seen.len() == 1 {
                std::fs::write(&path, "after\n").expect("a truncated log");
                true
            }
            else {
                false
            }
        });

        assert_eq!(seen, vec!["before", "after"]);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_partial_line_waits_for_its_newline() {
        // A reader can catch a writer mid-line. The fragment must not be sent as a line of its own and must not be
        // dropped: it is joined with the next append.
        let directory = scratch("partial");
        let path = path_in(&directory);
        std::fs::write(&path, "complete\nhalf").expect("a log");

        let mut seen = Vec::new();
        follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
            seen.push(line.to_owned());
            if seen.len() == 1 {
                append(&path, "-done\n");
                true
            }
            else {
                false
            }
        });

        assert_eq!(seen, vec!["complete", "half-done"]);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
