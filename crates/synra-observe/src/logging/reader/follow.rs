//! Streams complete lines and preserves unread bytes across log rotation.

use std::path::Path;
use std::time::Duration;

use super::{keep, path_in};

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
