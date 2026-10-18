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

use super::file::{DEFAULT_KEEP, LOG_FILE_NAME};

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

/// How many opening bytes of a log identify it where the platform reports no file id.
///
/// 256 is long enough that two different logs do not share it — every line begins with a timestamp, and a quarter of a
/// kilobyte spans several lines — and short enough that comparing it on every poll is a read of a few cache lines.
const HEAD_BYTES: usize = 256;

/// The first `count` bytes of a file, or fewer when it is shorter.
fn head_of(path: &Path, count: usize) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).ok()?;
    let mut buffer = vec![0u8; count];
    let mut read = 0;
    while read < count {
        match file.read(buffer.get_mut(read..)?) {
            Ok(0) => break,
            Ok(size) => read += size,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    buffer.truncate(read);
    Some(buffer)
}

/// A file's identity, when the platform reports one.
///
/// # Why identity rather than length
///
/// Because a rotation can replace the log with a **longer** file before the next poll: the length would then look like
/// "the same file grew", and the follower would read the new file from the old offset — emitting bytes from the middle of
/// a line as if they were new. The inode is what actually distinguishes "this file grew" from "a different file has the
/// same name".
///
/// # Why Windows has none
///
/// Because neither stable fact identifies a file there. `std::os::windows::fs::MetadataExt::file_index` is still behind
/// `windows_by_handle` on this toolchain, and the creation time is **tunneled**: a new file created under a name that just
/// existed inherits the old file's creation time (measured: the two are equal), so it would answer "same file" for a
/// rotation. Windows therefore compares the file's opening bytes instead — see [`head_of`] — which is the identity that
/// does not depend on the filesystem.
#[allow(clippy::missing_const_for_fn)] // On unix the body reads the inode, which is not a const operation.
fn file_id(metadata: &std::fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some(metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Sends every complete line in `pending`, collecting them while the tail is still being taken.
///
/// Returns `Some` when the sink asked to stop; a partial line is left in `pending`.
fn drain_lines<F>(
    pending: &mut Vec<u8>,
    verbose: bool,
    trace: Option<&str>,
    initial: &mut bool,
    collected: &mut Vec<String>,
    sent: &mut usize,
    sink: &mut F,
) -> Option<FollowSummary>
where
    F: FnMut(&str) -> bool,
{
    while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
        let line: Vec<u8> = pending.drain(..=end).collect();
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\n', '\r']);
        if !keep(text, verbose, trace) {
            continue;
        }
        if *initial {
            collected.push(text.to_owned());
        }
        else {
            *sent = sent.saturating_add(1);
            if !sink(text) {
                return Some(FollowSummary { lines: *sent });
            }
        }
    }
    None
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
/// time — the "follow" would repeat itself — and would be quadratic in the file's size. The reader keeps an open handle
/// and an offset, and reads what was appended.
///
/// # Why rotation drains the old handle
///
/// Because a rotation renames the file and starts a new one under the same name. The reader's offset belongs to the old
/// file, and the bytes it had not read yet are still in that file — but the path no longer names it. Keeping the handle is
/// what lets those lines be sent before the reader switches to the new file; a follower that reopened by path on every
/// poll silently dropped them. The switch is detected by file identity (see [`file_id`]), falling back to "shorter than
/// it was" on a platform that reports none, and a line that had no newline in the old file is dropped rather than joined
/// to the first line of the new one — the two files are not one stream.
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
    let mut open: Option<std::fs::File> = None;
    let mut offset = 0u64;
    // The opening bytes of the file this reader holds, for the platforms with no file id. Filled from what was read, so
    // it costs no extra read; cleared when the reader switches files.
    let mut head: Vec<u8> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut collected: Vec<String> = Vec::new();
    let mut initial = true;
    let mut sent = 0usize;

    loop {
        use std::io::{Read as _, Seek as _, SeekFrom};

        let length = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());

        // ★ Rotation: the path names a different file than the one held open, or the same one truncated. Either way the
        // handle is drained first — those are lines the writer wrote, and the path is about to lose them.
        let held = open
            .as_ref()
            .and_then(|held| held.metadata().ok())
            .map(|metadata| file_id(&metadata));
        let path_id = std::fs::metadata(&path).ok().and_then(|metadata| file_id(&metadata));
        // ★ Both tests are needed. A different identity is a rotation; the path being **shorter than what this reader has
        // already consumed** is a truncation. The second test has to use the offset, not the handle's current length: after
        // an in-place truncation the handle reports the new, smaller length too, so comparing the two lengths sees "equal"
        // and the follower then waits at an offset the file will never reach.
        let mut replaced = held.is_some_and(|held_id| {
            held_id.zip(path_id).is_some_and(|(held_id, current)| held_id != current) || length < offset
        });
        // ★ Where the platform reports no file id (Windows), the opening bytes are the identity: a rotation starts a file
        // whose first bytes are not the ones this reader has already seen. Without this, a rotation whose new file was
        // already longer than the offset was invisible, and the new file was read from the old offset.
        if !replaced
            && held == Some(None)
            && !head.is_empty()
            && length >= u64::try_from(head.len()).unwrap_or(u64::MAX)
            && head_of(&path, head.len()).is_some_and(|current| current != head)
        {
            replaced = true;
        }
        if replaced {
            if let Some(held) = open.as_ref()
                && let Ok(mut clone) = held.try_clone()
            {
                let mut rest = Vec::new();
                if clone.read_to_end(&mut rest).is_ok() {
                    pending.extend_from_slice(&rest);
                }
            }
            if let Some(summary) =
                drain_lines(&mut pending, verbose, trace, &mut initial, &mut collected, &mut sent, &mut sink)
            {
                return summary;
            }
            // The end of the old file is not the start of the new one.
            pending.clear();
            head.clear();
            open = None;
            offset = 0;
        }

        if open.is_none() {
            open = std::fs::File::open(&path).ok();
            offset = 0;
        }

        let mut read_something = false;
        if let Some(file) = open.as_mut() {
            let held_length = file.metadata().map_or(0, |metadata| metadata.len());
            if held_length > offset {
                if file.seek(SeekFrom::Start(offset)).is_ok() {
                    let mut chunk = Vec::new();
                    if file.read_to_end(&mut chunk).is_ok() {
                        offset = offset.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                        if head.len() < HEAD_BYTES {
                            let wanted = HEAD_BYTES.saturating_sub(head.len());
                            let taken = chunk.len().min(wanted);
                            if let Some(bytes) = chunk.get(..taken) {
                                head.extend_from_slice(bytes);
                            }
                        }
                        pending.extend_from_slice(&chunk);
                        read_something = true;
                    }
                    else {
                        // A read that failed must not spin: take what the metadata said and wait for the next poll.
                        offset = held_length;
                    }
                }
                else {
                    offset = held_length;
                }
            }
        }

        if let Some(summary) =
            drain_lines(&mut pending, verbose, trace, &mut initial, &mut collected, &mut sent, &mut sink)
        {
            return summary;
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

        if !read_something {
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
    fn lines_written_just_before_a_rotation_are_not_lost() {
        // ★ The old file's unread bytes belong to the old handle. A follower that reopened by path on every poll would
        // miss them and then read the *new* file from the old offset — two half-lines of garbage where two real lines were.
        // The new file is deliberately **longer** than the old, so a length comparison would read it as "it grew"; the
        // inode catches it on unix, and the opening bytes catch it where no file id exists (Windows).
        let directory = scratch("rotation-loss");
        let path = path_in(&directory);
        std::fs::write(&path, "one\n").expect("a log");
        let rotated = directory.join("synra.log.1");

        let mut seen = Vec::new();
        follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
            seen.push(line.to_owned());
            if seen.len() == 1 {
                append(&path, "two\n");
                std::fs::rename(&path, &rotated).expect("rotates");
                std::fs::write(&path, "three\nfour\nfive\n").expect("a new log");
            }
            seen.len() < 5
        });

        assert_eq!(seen, vec!["one", "two", "three", "four", "five"]);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_rotation_to_a_shorter_file_keeps_what_the_old_one_held() {
        // The cross-platform case: the new file is shorter than what the reader has consumed, so the length fallback
        // detects it even where no file identity is available.
        let directory = scratch("rotation-short");
        let path = path_in(&directory);
        std::fs::write(&path, "one\n").expect("a log");
        let rotated = directory.join("synra.log.1");

        let mut seen = Vec::new();
        follow(&directory, 10, false, None, Duration::from_millis(5), |line| {
            seen.push(line.to_owned());
            if seen.len() == 1 {
                append(&path, "two\n");
                std::fs::rename(&path, &rotated).expect("rotates");
                std::fs::write(&path, "x\n").expect("a new log");
            }
            seen.len() < 3
        });

        assert_eq!(seen, vec!["one", "two", "x"]);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_tail_reaches_back_into_the_rotated_files() {
        // ★ Rotation renames the file, so a reader that only opened the current one answered "the last three lines" with
        // the one line written since the rename — at exactly the moment a user is reading the log.
        let directory = scratch("tail-rotated");
        std::fs::write(directory.join("synra.log.2"), "oldest one\noldest two\n").expect("a rotated log");
        std::fs::write(directory.join("synra.log.1"), "older one\nolder two\nolder three\n")
            .expect("a rotated log");
        std::fs::write(directory.join("synra.log"), "newest one\n").expect("the active log");

        let three = tail(&directory, 3, false, None);
        assert_eq!(three.lines, vec!["older two", "older three", "newest one"]);
        // The reader read the current file and `.1` — it stopped once it had enough, so `.2` was not opened, and the count
        // says "four matched" rather than pretending it saw the whole history.
        assert_eq!(three.matched, 4);

        let five = tail(&directory, 5, false, None);
        assert_eq!(
            five.lines,
            vec!["oldest two", "older one", "older two", "older three", "newest one"]
        );
        assert_eq!(five.matched, 6, "the oldest file was read for the last two lines");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_tail_filters_the_rotated_files_with_the_same_rule() {
        let directory = scratch("tail-rotated-filter");
        std::fs::write(
            directory.join("synra.log.1"),
            "visible one\nDEBUG hidden\nvisible two\n",
        )
        .expect("a rotated log");
        std::fs::write(directory.join("synra.log"), "newest\n").expect("the active log");

        let quiet = tail(&directory, 2, false, None);
        assert_eq!(quiet.lines, vec!["visible two", "newest"]);
        assert_eq!(quiet.matched, 3, "the hidden line is not counted as matched");

        let verbose = tail(&directory, 4, true, None);
        assert_eq!(
            verbose.lines,
            vec!["visible one", "DEBUG hidden", "visible two", "newest"]
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_active_file_wins_over_a_rotated_one_even_when_its_clock_is_older() {
        // ★ The two are written in the same clock tick at a rotation, and on a tie the reader must not pick `.1`: the file
        // with the plain name is the one being written, because rotation renames the old one away.
        let directory = scratch("tail-active");
        std::fs::write(path_in(&directory), "current\n").expect("the active log");
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(directory.join("synra.log.1"), "rotated\n").expect("a rotated log");

        let read = tail(&directory, 12, false, None);
        assert_eq!(read.lines, vec!["rotated", "current"]);
        assert_eq!(read.source.as_deref(), Some(path_in(&directory).as_path()));
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
