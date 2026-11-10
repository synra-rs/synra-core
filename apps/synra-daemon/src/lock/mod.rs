//! The instance lock: which process owns the data directory, and when a claim on it is stale.
//!
//! # Why a daemon needs one at all
//!
//! Two daemons over one data directory is not a performance problem, it is a **correctness** problem: both open the
//! same SQLite file, both believe they are the only one, and the writes interleave in ways neither can see. The
//! database's own locking would stop the *corruption* and would not stop the divergence — two processes each holding
//! half the truth about which devices are paired and which plugins are active.
//!
//! So the second one has to refuse to start, and the refusal has to be legible: "another instance is running" is
//! actionable, and "database is locked" is not.
//!
//! # The hard half is a process that died without cleaning up
//!
//! A lock file left by a crash is the ordinary case, not the exception: a machine loses power, a user kills the
//! process, a debugger stops it. A lock that treated every existing file as a live owner would leave the daemon
//! unable to start ever again, and the fix a user would find is "delete this file", which is the fix that also breaks
//! the real case.
//!
//! So the claim carries a **heartbeat**, and what decides is the heartbeat's age rather than the file's existence:
//!
//! * A heartbeat newer than the policy means a live owner, and the second instance refuses.
//! * A heartbeat older than the policy means the owner is gone, and the second instance takes the claim.
//!
//! # Why the heartbeat and not the process id
//!
//! "Is process 1234 alive" is a question about the operating system, and its answer is *wrong in the dangerous
//! direction*: process ids are reused, so a dead daemon's id can belong to something else entirely and the check
//! reports a live owner that is not one. A heartbeat is a fact the owner itself wrote, and its staleness is decidable
//! without asking the system anything — which is also what makes this module testable rather than a wrapper around a
//! syscall.
//!
//! The process id is still recorded, because a user reading the lock wants to know what to kill. It is information,
//! not the decision.

use serde::{Deserialize, Serialize};

/// How long a heartbeat is believed, in milliseconds.
///
/// Ninety seconds. The owner writes every [`HEARTBEAT_INTERVAL_MS`], so this is thirty missed beats — long enough that
/// a daemon busy with a large file, or one whose thread was descheduled, is not mistaken for dead; short enough that a
/// user who killed a daemon is not waiting two minutes to start another.
pub const HEARTBEAT_STALE_AFTER_MS: u64 = 90_000;

/// How often the owner should write its heartbeat.
///
/// Three seconds, so a live owner is never close to the threshold and the margin absorbs a stalled thread. Reported
/// here rather than in the daemon's loop because the two numbers have to be read together: a heartbeat interval that
/// drifted toward the staleness threshold would make a live daemon look dead under load, which is the failure that
/// produces two instances.
pub const HEARTBEAT_INTERVAL_MS: u64 = 3_000;

/// Who claims a data directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockOwner {
    /// The process's id.
    ///
    /// Recorded because a user reading the lock wants to know what to kill. It is **not** what decides whether the
    /// claim is live: process ids are reused, so a dead daemon's id can belong to something else and a liveness check
    /// would report an owner that is not one.
    pub pid: u32,
    /// Which build wrote it, so a user can tell daemons apart.
    pub version: String,
    /// When the claim was first taken, in the owner's monotonic milliseconds.
    pub claimed_at_ms: u64,
    /// When the owner last said it was alive.
    ///
    /// Wall-clock milliseconds since the Unix epoch, **not** a monotonic reading. A monotonic reading is the right
    /// frame *within* one process and meaningless *across* two: each process has its own origin, so a claim written by
    /// a daemon that has since died carries a number from a frame this process knows nothing about. Comparing the two
    /// made every cross-process claim look like it had just beaten, and the crash recovery — the case the lock exists
    /// for — never fired.
    pub heartbeat_ms: u64,
    /// Whether the owner shut down in an orderly way.
    ///
    /// ★ The field that makes cross-process staleness decidable at all. A clean shutdown sets it, and a claim that
    /// carries it is a directory nobody owns — regardless of how recent its heartbeat looks, which is a question that
    /// cannot be answered across two processes.
    ///
    /// Defaults to `false` when absent, so a claim written before this field existed is treated as a session that
    /// ended badly. That is the conservative direction: the cost of being wrong is one reclaim message in a log, and
    /// the cost of the other direction is two daemons over one database.
    #[serde(default)]
    pub clean: bool,
}

impl LockOwner {
    /// How old a heartbeat is at a reading.
    ///
    /// Saturating, so a clock that appears to have moved backwards gives zero rather than a huge age — and a huge age
    /// would take a live owner's claim away, which is the direction that produces two instances.
    #[must_use]
    pub const fn heartbeat_age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.heartbeat_ms)
    }

    /// Whether the claim is still believed at a reading.
    #[must_use]
    pub const fn is_live(&self, now_ms: u64) -> bool {
        // `<` rather than `<=`: a heartbeat exactly at the threshold is stale, because the threshold is the point at
        // which the owner has missed every beat it was supposed to send.
        self.heartbeat_age_ms(now_ms) < HEARTBEAT_STALE_AFTER_MS
    }
}

/// What happened when an instance tried to claim a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The directory was free, and this instance now owns it.
    Taken,
    /// Another instance owns it and is alive.
    Held {
        /// The owner, so the message can name what to stop.
        owner: LockOwner,
        /// How long since the owner last said it was alive.
        age_ms: u64,
    },
    /// The previous owner shut down in an orderly way, and this instance now owns the directory.
    ///
    /// ★ Distinct from [`Claim::Reclaimed`], because the two are different events for a user and only one of them is
    /// worth reporting. A clean handover is an ordinary restart; a reclaim means the last session ended badly, and the
    /// log says so. Collapsing them made every ordinary restart claim the previous session had crashed.
    Clean {
        /// The owner that finished, for the log.
        previous: LockOwner,
        /// How long since it last said it was alive.
        age_ms: u64,
    },
    /// The previous owner is gone and this instance now owns it.
    ///
    /// Distinct from [`Claim::Taken`], because the two are not the same event for a user: taking a claim from a dead
    /// daemon means the last session ended badly, and the log should say so.
    Reclaimed {
        /// The owner that was displaced, for the log.
        previous: LockOwner,
        /// How long since it last said it was alive.
        age_ms: u64,
    },
}

impl Claim {
    /// Whether this instance may run.
    #[must_use]
    pub const fn may_run(&self) -> bool {
        matches!(self, Self::Taken | Self::Clean { .. } | Self::Reclaimed { .. })
    }

    /// What to tell the user, when it may not run.
    ///
    /// The pid is in the message because it is the one part a user can act on, and the age is there so a user can tell
    /// "something is running" from "something died a moment ago and I should try again".
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        match self {
            Self::Taken | Self::Clean { .. } | Self::Reclaimed { .. } => None,
            Self::Held { owner, age_ms } => Some(format!(
                "another synra-daemon is already using this data directory (pid {}, version {}, last alive {}s ago)",
                owner.pid,
                owner.version,
                age_ms / 1_000
            )),
        }
    }
}

/// How this instance's claim would be written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockFile {
    /// The version of the lock file's own shape.
    ///
    /// A lock written by a newer daemon is one this build cannot interpret, and reading it as though it could would
    /// mean decisions made on misread fields. The version is what lets a mismatch be a refusal instead.
    pub version: u32,
    /// The owner.
    pub owner: LockOwner,
}

/// The shape this build writes.
///
/// One. A version below this is a lock from an older build — which this build can read, because the shape has not
/// changed — and one above is from a newer build, which it cannot.
pub const LOCK_FORMAT_VERSION: u32 = 1;

impl LockFile {
    /// A claim taken at a reading.
    #[must_use]
    pub fn claim(pid: u32, version: impl Into<String>, now_ms: u64) -> Self {
        Self {
            version: LOCK_FORMAT_VERSION,
            owner: LockOwner {
                pid,
                version: version.into(),
                claimed_at_ms: now_ms,
                heartbeat_ms: now_ms,
                clean: false,
            },
        }
    }

    /// Whether this build can interpret the file.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.version <= LOCK_FORMAT_VERSION
    }
}

/// Why a claim could not be settled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LockError {
    /// The lock file could not be read, and it exists.
    ///
    /// Distinct from a missing file. A lock that cannot be read might be a live owner's, so treating it as absent
    /// would start a second instance over a running one — the failure this whole module exists to prevent.
    #[error("the lock file at {path} could not be read: {reason}")]
    Unreadable {
        /// Where it is.
        path: String,
        /// What went wrong.
        reason: String,
    },

    /// The lock was written by a newer build.
    ///
    /// Refused rather than ignored: a newer daemon may have changed what the claim means, and this build deciding
    /// from fields it may be misreading is the shape that produces two instances.
    #[error("the lock file at {path} was written by a newer version ({found}, and this build writes {expected})")]
    FromTheFuture {
        /// Where it is.
        path: String,
        /// What was found.
        found: u32,
        /// What this build writes.
        expected: u32,
    },
}

/// Decides a claim from what was on disk.
///
/// # Why the decision is a function rather than a method on a file
///
/// Reading a file is the caller's job, so what a *given* lock file means is decidable without one — and that is the
/// part worth testing. The three cases here are the whole of the policy: nothing there, a live owner, a dead one.
///
/// # Errors
///
/// [`LockError`] when an existing file cannot be interpreted. A missing file is [`Claim::Taken`], because nothing
/// owns the directory.
pub fn decide(
    existing: Option<&LockFile>,
    now_ms: u64,
    path: &str,
) -> Result<Claim, LockError> {
    let Some(file) = existing else {
        return Ok(Claim::Taken);
    };

    if !file.is_readable() {
        return Err(LockError::FromTheFuture {
            path: path.to_owned(),
            found: file.version,
            expected: LOCK_FORMAT_VERSION,
        });
    }

    let age_ms = file.owner.heartbeat_age_ms(now_ms);
    // ★ A claim its owner marked clean is one nobody owns. Checked before the heartbeat, because staleness across two
    // processes is not answerable: the reading came from a frame this process does not share.
    if file.owner.clean {
        return Ok(Claim::Clean { previous: file.owner.clone(), age_ms });
    }
    if file.owner.is_live(now_ms) {
        Ok(Claim::Held { owner: file.owner.clone(), age_ms })
    }
    else {
        Ok(Claim::Reclaimed { previous: file.owner.clone(), age_ms })
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod proptests;
