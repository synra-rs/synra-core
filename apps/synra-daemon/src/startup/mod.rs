//! What a start-up does, as a value rather than a sequence of prints.
//!
//! # Why the decision is separated from the printing
//!
//! A daemon's start-up is: read the flags, check the plan, take the claim, report. Only the first and last of those
//! need a process; the middle two are decisions, and the interesting failures are all of them — a port collision, a
//! claim held by a live owner, a claim file this build cannot read.
//!
//! So [`startup`] returns a [`Startup`]: the lines to print, whether it may run, and what happened to the claim. A
//! test asserts the decision for each case, and `main` becomes four lines of I/O that nobody has to reason about.
//!
//! # A reclaim is reported, and taking a free directory is not
//!
//! The two are the same event as far as the *claim* is concerned and different events for a user: a directory nobody
//! owned is an ordinary first start, and taking one from a dead daemon means the last session ended badly. A log that
//! did not say which would leave a user with an unexplained gap in the record.

use std::path::Path;

mod claim;
mod decision;

pub use claim::{begin, mark_clean_shutdown, release, startup};
pub use decision::{Startup, StartupReport};

/// The reading a claim's timestamps are in: wall-clock milliseconds since the Unix epoch.
///
/// # Why the wall clock, after a monotonic reading was tried and was wrong
///
/// A claim outlives the process that wrote it — that is the entire point, since the interesting case is a daemon that
/// died. A monotonic reading is the right frame *within* a process and meaningless *across* two: each process has its
/// own origin, so the previous daemon's heartbeat is a number from a frame this process knows nothing about.
///
/// The failure that produced was not subtle. The second process read the first one's heartbeat, subtracted it from its
/// own small reading, saturated to zero, and concluded the dead daemon had just beaten — so the crash recovery never
/// fired and an abruptly killed daemon blocked the next start for ever.
///
/// A wall clock is comparable across processes, which is what is needed. Its weaknesses — an NTP correction, a user
/// changing the time — are handled by the claim's own `clean` flag rather than by arithmetic: staleness across two
/// processes is decided by what the previous owner *said* on its way out, and the heartbeat only has to be good enough
/// to notice a daemon that died without saying anything.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        // A clock set before 1970 is not a reason to refuse to start: zero is "the beginning of time" and every claim
        // will look stale, which is the direction that lets a daemon run.
        .unwrap_or(0)
}

/// Whether a path is a data directory this build would claim.
///
/// Exposed because the CLI's `doctor` asks a related question, and one answer for both is how the two stay in step.
#[must_use]
pub fn looks_like_a_data_dir(path: &Path) -> bool {
    path.join(crate::plan::LOCK_FILE_NAME).is_file() || path.join("synra.db").is_file()
}

#[cfg(test)]
mod tests;
