//! Finds the active or newest log and reads a filtered tail across rotations.

use std::path::{Path, PathBuf};

use super::super::file::{DEFAULT_KEEP, LOG_FILE_NAME};
use super::{keep, path_in};

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

/// Reads the tail of the current log, and of the rotated files behind it when it is short.
///
/// `verbose` keeps `DEBUG` and `TRACE` lines, which are hidden otherwise; `trace` keeps only lines that mention the id.
///
/// The two compose, and that is deliberate: a trace's lines are usually the debug ones, so a caller asking for a trace
/// without `verbose` gets the intersection it asked for rather than a surprise widening.
///
/// # Why the rotated files are read
///
/// Because rotation renames the whole file, and a reader that only opened the current one would answer a request for the
/// last hundred lines with the three lines written since the rename — the moment a user is most likely to be reading the
/// log. The files are `synra.log.1` (the newest rotated) through `.N` (the oldest), so the reader takes what it still
/// needs from `.1`, then `.2`, and puts them in front of the current file's lines. Only the files it needs are read: a
/// current file with enough lines costs no extra open.
#[must_use]
pub fn tail(directory: &Path, lines: usize, verbose: bool, trace: Option<&str>) -> LogTail {
    // ★ The active file wins over modification time. A directory's newest entry is *usually* the active log, but the two
    // are written within the same clock tick at a rotation, and on a tie the reader could pick `.1` — answering "the last
    // hundred lines" with a file that is no longer being written. The plain name is not a heuristic: rotation renames the
    // old file away, so a file called `synra.log` **is** the active one. Modification time stays for a directory that has
    // no active file, such as a copied or rotated-only log.
    let active = path_in(directory);
    let source = if active.is_file() {
        active
    }
    else {
        let Some(newest) = newest_file(directory) else {
            return LogTail { lines: Vec::new(), source: None, matched: 0 };
        };
        newest
    };
    let Ok(text) = std::fs::read_to_string(&source) else {
        // Unreadable is reported as "nothing to read" rather than as an error, because the caller's next step is the
        // same either way and a diagnostic bundle must not fail over a log it could not include — the omission list is
        // where that gets said.
        return LogTail { lines: Vec::new(), source: Some(source), matched: 0 };
    };

    let current: Vec<&str> = text.lines().filter(|line| keep(line, verbose, trace)).collect();
    let mut matched = current.len();
    let start = current.len().saturating_sub(lines);
    let mut chosen: Vec<String> =
        current.get(start..).unwrap_or(&[]).iter().map(|line| (*line).to_owned()).collect();
    let mut needed = lines.saturating_sub(chosen.len());

    // ★ Only when the newest file is the active one: if `newest_file` selected a rotated file (the current one is absent
    // or older by clock), reading `.<n>` siblings by name would put them in a guessed order relative to it.
    let rotated = source.file_name().and_then(|name| name.to_str()) == Some(LOG_FILE_NAME);
    let mut index = 1usize;
    while rotated && needed > 0 && index <= DEFAULT_KEEP {
        let older = directory.join(format!("{LOG_FILE_NAME}.{index}"));
        let Ok(text) = std::fs::read_to_string(&older) else {
            // A gap in the numbering is the ordinary case for a young installation: nothing older to read.
            break;
        };
        let older_lines: Vec<&str> = text.lines().filter(|line| keep(line, verbose, trace)).collect();
        matched = matched.saturating_add(older_lines.len());
        let take = older_lines.len().min(needed);
        let from = older_lines.len().saturating_sub(take);
        let mut older_chosen: Vec<String> =
            older_lines.get(from..).unwrap_or(&[]).iter().map(|line| (*line).to_owned()).collect();
        // Older lines go in front: `.2` precedes `.1`, and both precede the active file.
        older_chosen.append(&mut chosen);
        chosen = older_chosen;
        needed = needed.saturating_sub(take);
        index = index.saturating_add(1);
    }

    LogTail { lines: chosen, source: Some(source), matched }
}
