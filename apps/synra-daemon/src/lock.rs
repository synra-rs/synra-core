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
mod tests {
    use super::*;

    fn owner(heartbeat_ms: u64) -> LockOwner {
        LockOwner {
            pid: 4_242,
            version: "0.1.0".to_owned(),
            claimed_at_ms: 0,
            heartbeat_ms,
            clean: false,
        }
    }

    fn file(heartbeat_ms: u64) -> LockFile {
        LockFile { version: LOCK_FORMAT_VERSION, owner: owner(heartbeat_ms) }
    }

    // ── A fresh directory ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_absent_lock_means_the_directory_is_free() {
        // Nothing owns it, so the instance takes it. This is the ordinary first start.
        assert_eq!(decide(None, 1_000, "/lock").expect("decides"), Claim::Taken);
        assert!(decide(None, 0, "/lock").expect("decides").may_run());
    }

    #[test]
    fn taking_a_fresh_claim_lets_the_instance_run() {
        assert!(Claim::Taken.may_run());
        assert_eq!(Claim::Taken.refusal(), None);
    }

    // ── A live owner ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_recent_heartbeat_holds_the_directory() {
        // The case the module exists for: two daemons over one data directory, each holding half the truth about which
        // devices are paired and which plugins are active.
        let claim = decide(Some(&file(1_000)), 2_000, "/lock").expect("decides");
        match &claim {
            Claim::Held { owner, age_ms } => {
                assert_eq!(owner.pid, 4_242);
                assert_eq!(*age_ms, 1_000);
            }
            other => panic!("expected a live owner, got {other:?}"),
        }
        assert!(!claim.may_run());
        let refusal = claim.refusal().expect("a refusal");
        assert!(refusal.contains("4242"), "{refusal}");
        assert!(refusal.contains("0.1.0"), "{refusal}");
    }

    #[test]
    fn a_heartbeat_exactly_at_the_threshold_is_stale() {
        // The threshold is the point at which the owner has missed every beat it was supposed to send, so a heartbeat
        // exactly there is not evidence of life. `<=` here would leave a daemon unable to start after a clean crash
        // until the next millisecond ticked over.
        let at_threshold = file(0);
        assert!(
            !at_threshold.owner.is_live(HEARTBEAT_STALE_AFTER_MS),
            "a heartbeat at the threshold was believed"
        );
        assert!(at_threshold.owner.is_live(HEARTBEAT_STALE_AFTER_MS - 1));
    }

    #[test]
    fn the_refusal_says_how_long_ago_in_seconds() {
        // So a user can tell "something is running" from "something died a moment ago and I should try again" — and
        // the number is in seconds because milliseconds is not a unit a person reads.
        let claim = decide(Some(&file(0)), 45_000, "/lock").expect("decides");
        let refusal = claim.refusal().expect("a refusal");
        assert!(refusal.contains("45s ago"), "{refusal}");
    }

    // ── A dead owner ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_stale_heartbeat_is_reclaimed() {
        // ★ The ordinary case rather than the exception: a machine loses power, a user kills the process, a debugger
        // stops it. A lock that treated every existing file as a live owner would leave the daemon unable to start
        // ever again.
        let claim = decide(Some(&file(0)), HEARTBEAT_STALE_AFTER_MS + 1, "/lock").expect("decides");
        match &claim {
            Claim::Reclaimed { previous, age_ms } => {
                assert_eq!(previous.pid, 4_242);
                assert_eq!(*age_ms, HEARTBEAT_STALE_AFTER_MS + 1);
            }
            other => panic!("expected a reclaim, got {other:?}"),
        }
        assert!(claim.may_run());
        assert_eq!(claim.refusal(), None, "a reclaim is not something to refuse");
    }

    #[test]
    fn a_reclaim_is_distinct_from_taking_a_free_directory() {
        // The two are not the same event for a user: taking a claim from a dead daemon means the last session ended
        // badly, and the log should say so.
        let free = decide(None, 1_000, "/lock").expect("decides");
        let stale = decide(Some(&file(0)), HEARTBEAT_STALE_AFTER_MS + 1, "/lock").expect("decides");
        assert_ne!(free, stale);
        assert!(free.may_run() && stale.may_run());
    }

    // ── Clock oddities ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_heartbeat_from_the_future_is_live_rather_than_infinitely_old() {
        // A reading *before* the heartbeat it is checking is a clock that moved, and the saturating subtraction gives
        // zero — which is the safe direction. A wrapping subtraction would give an enormous age and take a live
        // owner's claim away, which produces the two instances this module exists to prevent.
        let from_the_future = file(u64::MAX);
        assert_eq!(from_the_future.owner.heartbeat_age_ms(0), 0);
        assert!(from_the_future.owner.is_live(0));
        assert!(!decide(Some(&from_the_future), 0, "/lock").expect("decides").may_run());
    }

    #[test]
    fn a_clock_that_has_not_moved_still_leaves_a_heartbeat_live() {
        // A daemon that has just written its heartbeat and the second that reads it are the same millisecond on a
        // coarse clock, and that is a live owner.
        assert!(file(1_000).owner.is_live(1_000));
    }

    // ── Versions ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_lock_from_a_newer_build_is_refused_rather_than_ignored() {
        // A newer daemon may have changed what a claim means, and deciding from fields this build may be misreading is
        // the shape that produces two instances.
        let newer = LockFile { version: LOCK_FORMAT_VERSION + 1, owner: owner(0) };
        match decide(Some(&newer), 0, "/lock") {
            Err(LockError::FromTheFuture { found, expected, .. }) => {
                assert_eq!(found, LOCK_FORMAT_VERSION + 1);
                assert_eq!(expected, LOCK_FORMAT_VERSION);
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_lock_from_an_older_build_is_read() {
        // The shape has not changed, so an older claim is decidable — and refusing it would mean a user upgrading
        // could not start until they deleted a file.
        let older = LockFile { version: 0, owner: owner(0) };
        assert!(decide(Some(&older), HEARTBEAT_STALE_AFTER_MS + 1, "/lock").is_ok());
    }

    #[test]
    fn a_written_claim_carries_a_heartbeat_from_the_moment_it_was_taken() {
        // A claim whose heartbeat started at zero would look stale immediately, and the first thing the next start
        // would do is reclaim a claim that is live.
        let lock = LockFile::claim(1, "0.1.0", 5_000);
        assert_eq!(lock.owner.heartbeat_ms, 5_000);
        assert_eq!(lock.owner.claimed_at_ms, 5_000);
        assert_eq!(lock.version, LOCK_FORMAT_VERSION);
        assert!(lock.is_readable());
        assert!(lock.owner.is_live(5_000));
    }

    #[test]
    fn the_heartbeat_is_written_far_more_often_than_it_expires() {
        // The two numbers have to be read together: an interval that drifted toward the threshold would make a live
        // daemon look dead under load, which is the failure that produces two instances. Ten missed beats is the floor
        // a reviewer should accept.
        let missed = HEARTBEAT_STALE_AFTER_MS / HEARTBEAT_INTERVAL_MS;
        assert!(missed >= 10, "only {missed} beats are missed before a live owner looks dead");
    }

    // ── Serialisation ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_lock_round_trips_so_a_reader_gets_what_the_writer_meant() {
        let lock = LockFile::claim(7, "0.1.0", 1_000);
        let json = serde_json::to_string(&lock).expect("serialises");
        let back: LockFile = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, lock);
        // And camelCase on the wire, matching every other file this kernel writes.
        assert!(json.contains("heartbeatMs"), "{json}");
        assert!(json.contains("claimedAtMs"), "{json}");
    }

    #[test]
    fn lock_errors_explain_themselves() {
        let errors = [
            LockError::Unreadable { path: "/lock".to_owned(), reason: "permission denied".to_owned() },
            LockError::FromTheFuture { path: "/lock".to_owned(), found: 2, expected: 1 },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 30, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A heartbeat is live exactly when its age is below the threshold, for any pair of readings. The boundary is
        /// where this goes wrong in practice, and one millisecond of disagreement is a daemon that will not start or
        /// two that do.
        #[test]
        fn a_heartbeat_is_live_exactly_below_the_threshold(beat in 0u64..1_000_000, now in 0u64..2_000_000) {
            let owner = LockOwner {
                pid: 1,
                version: "0".to_owned(),
                claimed_at_ms: 0,
                heartbeat_ms: beat,
                clean: false,
            };
            let age = now.saturating_sub(beat);
            prop_assert_eq!(owner.heartbeat_age_ms(now), age);
            prop_assert_eq!(owner.is_live(now), age < HEARTBEAT_STALE_AFTER_MS);
        }

        /// Whatever the previous claim's state, a decision either lets this instance run or refuses it — never
        /// neither, and never both. A decision that returned `Held` for a stale owner is two daemons over one
        /// database; one that reclaimed a live owner is the same.
        #[test]
        fn a_decision_agrees_with_liveness(
            version in 0u32..4,
            beat in 0u64..200_000,
            now in 0u64..400_000,
        ) {
            let file = LockFile {
                version,
                owner: LockOwner {
                    pid: 1,
                    version: "0".to_owned(),
                    claimed_at_ms: 0,
                    heartbeat_ms: beat,
                    clean: false,
                },
            };
            let decision = decide(Some(&file), now, "/lock");

            if version > LOCK_FORMAT_VERSION {
                prop_assert!(
                    matches!(decision, Err(LockError::FromTheFuture { .. })),
                    "{:?}",
                    decision.err(),
                );
                return Ok(());
            }

            let claim = decision.expect("a readable lock decides");
            let live = file.owner.is_live(now);
            // A claim marked clean is one nobody owns, whatever its heartbeat says: staleness across two processes is
            // not decidable from a timestamp, which is why the flag exists.
            prop_assert_eq!(claim.may_run(), file.owner.clean || !live);
            match claim {
                Claim::Held { .. } => prop_assert!(live, "held a stale claim"),
                Claim::Reclaimed { .. } => prop_assert!(!live, "reclaimed a live claim"),
                Claim::Clean { .. } => prop_assert!(true),
                Claim::Taken => prop_assert!(false, "an existing lock was reported as absent"),
            }
        }
    }
}
