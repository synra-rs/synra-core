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

use serde::Serialize;

use crate::args::{ClaimFile, DaemonArgs, Parsed};
use crate::lock::{Claim, HEARTBEAT_INTERVAL_MS, LockError, LockFile, LockOwner};
use crate::plan::{DaemonPlan, PlanError};

/// What a start-up decided.
#[derive(Debug)]
pub enum Startup {
    /// The plan is unusable, so nothing will be created.
    Refused {
        /// Why.
        reason: String,
    },
    /// The plan is usable and this instance owns the directory.
    Ready {
        /// What it will do.
        plan: Box<DaemonPlan>,
        /// What happened to the claim.
        claim: Box<Claim>,
        /// The claim that was written, so a shutdown can mark it clean.
        ///
        /// `None` for a diagnostic run, which writes no claim — and a caller that marked one clean anyway would be
        /// writing into a running daemon's file.
        written: Option<Box<LockFile>>,
        /// What the previous owner was, when there was one.
        reclaimed_from: Option<Box<LockOwner>>,
    },
    /// Another instance owns the directory and is alive.
    AlreadyRunning {
        /// What it will not do, in the lines a user reads.
        lines: Vec<String>,
        /// What to tell the user.
        reason: String,
    },
    /// The plan is a dry run, so nothing was claimed.
    DryRun {
        /// What it would do.
        plan: Box<DaemonPlan>,
    },
}

impl Startup {
    /// Whether the daemon may proceed to start a kernel.
    #[must_use]
    pub const fn may_run(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// What the process should exit with.
    ///
    /// A dry run **succeeds**: it did exactly what was asked of it, and exiting non-zero would make a script that
    /// checks a configuration treat a good configuration as an error.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Refused { .. } | Self::AlreadyRunning { .. } => 1,
            Self::Ready { .. } | Self::DryRun { .. } => 0,
        }
    }

    /// The plan, when one was resolved.
    ///
    /// `None` for a refusal and for a directory another instance holds, because neither describes an installation this
    /// process will run — and a caller that released a claim from a plan it never took would delete a running daemon's.
    #[must_use]
    pub fn plan(&self) -> Option<&DaemonPlan> {
        match self {
            Self::Ready { plan, .. } => Some(plan),
            // A dry run resolved a plan and took no claim, so it has one to *report* and none to release. Returning
            // `None` is what keeps `main` from treating the two the same.
            Self::DryRun { .. } | Self::Refused { .. } | Self::AlreadyRunning { .. } => None,
        }
    }

    /// The lines to print, in order.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        match self {
            Self::Refused { .. } => Vec::new(),
            Self::DryRun { plan } => {
                let mut lines = plan.lines();
                lines.push("dry run: nothing was created and no claim was taken".to_owned());
                lines
            }
            Self::AlreadyRunning { lines, .. } => lines.clone(),
            Self::Ready { plan, claim, reclaimed_from, .. } => {
                let mut lines = plan.lines();
                match (claim.as_ref(), reclaimed_from.as_deref()) {
                    // ★ Reported rather than silent: taking a claim from a dead daemon means the last session ended
                    // badly, and a user reading the log is entitled to know that.
                    (Claim::Reclaimed { age_ms, .. }, Some(previous)) => {
                        lines.push(format!(
                            "reclaimed the data directory from pid {} (version {}), last alive {}s ago — the previous \
                             session ended without shutting down",
                            previous.pid,
                            previous.version,
                            age_ms / 1_000
                        ));
                    }
                    (Claim::Taken, _) => lines.push("claimed the data directory".to_owned()),
                    // An orderly restart, reported as itself. Collapsing this into the reclaim arm made every ordinary
                    // restart claim the previous session had crashed.
                    (Claim::Clean { previous, .. }, _) => lines.push(format!(
                        "took over from pid {} (version {}), which shut down cleanly",
                        previous.pid, previous.version
                    )),
                    _ => {}
                }
                // The heartbeat interval is reported because it is the number that decides how long a *dead* daemon
                // blocks the next start, and a user who is waiting for one wants to know.
                lines.push(format!("heartbeat every {HEARTBEAT_INTERVAL_MS}ms"));
                lines
            }
        }
    }

    /// What went wrong, for the error stream.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        match self {
            Self::Refused { reason } => Some(reason),
            Self::AlreadyRunning { reason, .. } => Some(reason),
            Self::Ready { .. } | Self::DryRun { .. } => None,
        }
    }

    /// A snapshot for a diagnostic bundle.
    ///
    /// `None` when nothing was decided, because a bundle that reported a plan for a start that was refused would
    /// describe an installation that does not exist.
    #[must_use]
    pub fn report(&self) -> Option<StartupReport> {
        match self {
            Self::Refused { .. } | Self::AlreadyRunning { .. } => None,
            Self::DryRun { plan } | Self::Ready { plan, .. } => Some(StartupReport {
                listen_port: plan.listen_port,
                discovery_port: plan.discovery_port,
                data_dir: plan.data_dir.clone(),
                exclusive: plan.exclusive,
                linger: plan.linger,
                can_prompt_the_user: plan.can_prompt_the_user,
            }),
        }
    }
}

/// The part of a start-up worth putting in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupReport {
    /// The transport port.
    pub listen_port: u16,
    /// The discovery port.
    pub discovery_port: u16,
    /// Where the data lives.
    pub data_dir: String,
    /// Whether the directory was claimed exclusively.
    pub exclusive: bool,
    /// Whether it keeps running with no clients.
    pub linger: bool,
    /// Whether the host can ask the user anything. Always false: this host has no window.
    pub can_prompt_the_user: bool,
}

/// Runs start-up as far as the claim, creating nothing.
///
/// # Errors
///
/// Never — a refusal is a [`Startup::Refused`] rather than an error, because "this configuration is wrong" is an
/// answer to the question the daemon was asked, not a failure of asking it.
#[must_use]
pub fn startup(args: &DaemonArgs, now_ms: u64) -> Startup {
    let parsed = match Parsed::resolve(args) {
        Ok(parsed) => parsed,
        Err(error) => return Startup::Refused { reason: describe(&error) },
    };

    if parsed.dry_run {
        return Startup::DryRun { plan: Box::new(parsed.plan) };
    }

    let path = parsed.plan.lock_path();
    let existing = match ClaimFile::read(&path) {
        Ok(existing) => existing,
        // A claim file that exists and cannot be interpreted is refused rather than treated as absent, because it
        // might be a live owner's — and starting over a running daemon is what the lock exists to prevent.
        Err(error) => return Startup::Refused { reason: describe_lock(&error) },
    };

    // A diagnostic run reads the claim and does not take it: a user who wants to see what a running daemon thinks
    // should not have to stop it.
    let claim = if parsed.plan.exclusive {
        match existing.decide(now_ms, &path) {
            Ok(claim) => claim,
            Err(error) => return Startup::Refused { reason: describe_lock(&error) },
        }
    }
    else {
        Claim::Taken
    };

    if !claim.may_run() {
        // The lines are the plan's, so a user sees which installation is already in use — which is the first thing
        // they need to know and the thing a bare "already running" would not tell them.
        let mut lines = parsed.plan.lines();
        // The claim's own refusal names the pid and the age, which is the part a user acts on.
        if let Claim::Held { owner, age_ms } = &claim {
            lines.push(format!(
                "held by pid {} (version {}), last alive {}s ago",
                owner.pid,
                owner.version,
                age_ms / 1_000
            ));
        }
        return Startup::AlreadyRunning {
            lines,
            reason: claim
                .refusal()
                .unwrap_or_else(|| "another synra-daemon is already using this data directory".to_owned()),
        };
    }

    let reclaimed_from = match &claim {
        Claim::Reclaimed { previous, .. } => Some(Box::new(previous.clone())),
        _ => None,
    };

    Startup::Ready {
        plan: Box::new(parsed.plan),
        claim: Box::new(claim),
        written: None,
        reclaimed_from,
    }
}

/// Runs start-up **and writes the claim**, which is what a real start does.
///
/// # Why this exists
///
/// [`startup`] decides and writes nothing, which is what makes it testable — a function with a side effect cannot be
/// called twice in one test to see what the second call decides. But a daemon that only *decided* it owned the
/// directory is a daemon whose exclusive claim is decorative: it reported "claimed the data directory" while leaving
/// no file behind, so a second instance decided the same thing and both believed they were alone.
///
/// So the writing is its own step, taken here, after the decision. A failure to write is a [`Startup::Refused`]: a
/// daemon that cannot write its claim must not run, because it would be running while believing it holds a claim it
/// does not.
#[must_use]
pub fn begin(args: &DaemonArgs, pid: u32, now_ms: u64) -> Startup {
    let decision = startup(args, now_ms);

    let Startup::Ready { plan, .. } = &decision else {
        return decision;
    };

    // A diagnostic run takes no claim, so there is nothing to write — writing one would make a run that promised not
    // to touch the directory the one that held it.
    if !plan.exclusive {
        return decision;
    }

    let path = plan.lock_path();
    match crate::args::write_claim(&path, pid, now_ms) {
        // The written claim goes back to the caller, because a clean shutdown has to mark *this* claim rather than
        // write a new one — and only the value knows the claimed-at reading and the pid.
        Ok(lock) => match decision {
            Startup::Ready { plan, claim, reclaimed_from, .. } => Startup::Ready {
                plan,
                claim,
                written: Some(Box::new(lock)),
                reclaimed_from,
            },
            other => other,
        },
        Err(error) => Startup::Refused { reason: error.to_string() },
    }
}

/// Releases the claim this process holds.
///
/// # Errors
///
/// [`LockError`] when the file exists and cannot be removed.
///
/// # Why a clean shutdown takes its own claim away
///
/// A claim left behind is not *wrong* — the next start reclaims it after the heartbeat goes stale — but it costs the
/// user ninety seconds of waiting and it writes "the previous session ended without shutting down" into the log for a
/// session that ended perfectly well. Removing it on the way out is what makes that message mean something.
pub fn release(decision: &Startup) -> Result<(), LockError> {
    let Startup::Ready { plan, written: Some(lock), .. } = decision else {
        // A diagnostic run wrote no claim, and a decision that never took one has nothing to mark. Returning `Ok`
        // rather than an error is right: the caller wanted the claim released and it is not there.
        return Ok(());
    };
    if !plan.exclusive {
        return Ok(());
    }
    mark_clean_shutdown(&plan.lock_path(), lock).map(|_| ())
}

/// Marks the claim as cleanly shut down.
///
/// # Why this is a write rather than a removal
///
/// Removing the file is indistinguishable from a daemon that was killed before it ever wrote one, and the difference
/// is exactly what the next start wants to know. So the claim is *kept* and marked: the next start reads it, sees
/// `clean`, and reports an ordinary first start rather than a reclaim.
///
/// # Errors
///
/// [`LockError`] when the file cannot be rewritten.
pub fn mark_clean_shutdown(path: &Path, lock: &LockFile) -> Result<LockFile, LockError> {
    let mut clean = lock.clone();
    clean.owner.clean = true;
    clean.owner.heartbeat_ms = now_ms();
    std::fs::write(path, crate::args::encode_claim(&clean, path)?).map_err(|error| LockError::Unreadable {
        path: path.display().to_string(),
        reason: format!("the claim could not be marked clean: {error}"),
    })?;
    Ok(clean)
}

/// A sentence for a plan failure.
fn describe(error: &PlanError) -> String {
    error.to_string()
}

/// A sentence for a lock failure.
fn describe_lock(error: &LockError) -> String {
    error.to_string()
}

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
mod tests {
    use super::*;
    use crate::plan::{DaemonOptions, DaemonPlan};
    use crate::lock::{HEARTBEAT_STALE_AFTER_MS, LockFile};
    use clap::Parser as _;

    /// A directory that exists for the duration of one test.
    struct Cleanup(std::path::PathBuf);

    impl Cleanup {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("synra-startup-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creates");
            Self(dir)
        }

        /// The data directory itself.
        ///
        /// No extra level: `--data-dir` names the data directory rather than a parent of it, and a fixture that added
        /// one would be testing a layout the daemon does not use — which is exactly the bug this fixture found once
        /// already.
        fn data(&self) -> std::path::PathBuf {
            self.0.clone()
        }

        /// Writes a claim for a heartbeat at a reading.
        ///
        /// The path comes from the *plan* rather than from the raw root, because `Paths::under` canonicalises the data
        /// directory — on Windows that adds a `\\?\` prefix — so a claim written beside the root is a claim the daemon
        /// never looks at. A fixture that wrote to the wrong path would make every case look like a free directory.
        fn write_claim(&self, heartbeat_ms: u64, pid: u32) {
            let plan = DaemonPlan::resolve(&DaemonOptions {
                data_dir: self.data(),
                listen_port: 0,
                ..DaemonOptions::default()
            })
            .expect("resolves");
            let lock = LockFile::claim(pid, "0.1.0", heartbeat_ms);
            std::fs::write(plan.lock_path(), serde_json::to_string(&lock).expect("serialises"))
                .expect("writes");
        }

        /// The path a claim for this directory would be read from.
        fn lock_path(&self) -> std::path::PathBuf {
            DaemonPlan::resolve(&DaemonOptions {
                data_dir: self.data(),
                listen_port: 0,
                ..DaemonOptions::default()
            })
            .expect("resolves")
            .lock_path()
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn args(dir: &Path, extra: &[&str]) -> DaemonArgs {
        let root = dir.display().to_string();
        let mut argv = vec!["synra-daemon", "--data-dir", root.as_str(), "--listen-port", "0"];
        argv.extend_from_slice(extra);
        DaemonArgs::try_parse_from(argv).expect("parses")
    }

    // ── A free directory ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_free_directory_is_claimed_and_the_daemon_runs() {
        let dir = Cleanup::new("free");
        let startup = startup(&args(&dir.data(), &[]), 0);
        assert!(startup.may_run(), "{startup:?}");
        assert_eq!(startup.exit_code(), 0);
        assert!(startup.failure().is_none());
        assert!(startup.lines().iter().any(|line| line.contains("claimed")), "{:?}", startup.lines());
    }

    #[test]
    fn the_lines_name_the_installation_being_started() {
        // A user with two profiles needs to see which one this is.
        let dir = Cleanup::new("lines");
        let startup = startup(&args(&dir.data(), &[]), 0);
        let lines = startup.lines();
        assert!(lines[0].contains("synra-daemon"), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("transport port")), "{lines:?}");
        // The heartbeat interval, because it is the number that decides how long a dead daemon blocks the next start.
        assert!(lines.iter().any(|line| line.contains("heartbeat every")), "{lines:?}");
    }

    // ── A live owner ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_live_owner_stops_a_second_start() {
        // ★ Two daemons over one database: both open the same SQLite file, both believe they are the only one, and
        // each holds half the truth about which devices are paired.
        let dir = Cleanup::new("held");
        dir.write_claim(1_000, 4_242);

        let startup = startup(&args(&dir.data(), &[]), 2_000);
        let a = args(&dir.data(), &[]);
        let from_args = Parsed::resolve(&a).expect("resolves").plan.lock_path();
        let expected = dir.lock_path();
        assert_eq!(
            from_args, expected,
            "the daemon looks at {} and the fixture wrote {}",
            from_args.display(),
            expected.display()
        );
        assert!(!startup.may_run(), "{startup:?}");
        assert_eq!(startup.exit_code(), 1);
        let reason = startup.failure().expect("a reason");
        assert!(reason.contains("4242"), "{reason}");
        assert!(reason.contains("already"), "{reason}");
    }

    #[test]
    fn a_refusal_still_shows_which_installation_is_in_use() {
        // The first thing a user needs to know, and the thing a bare "already running" would not tell them.
        let dir = Cleanup::new("held-lines");
        dir.write_claim(1_000, 4_242);
        let startup = startup(&args(&dir.data(), &[]), 2_000);
        let lines = startup.lines();
        assert!(lines.iter().any(|line| line.contains("data")), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("4242")), "{lines:?}");
    }

    // ── A dead owner ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_dead_owner_is_reclaimed_and_the_reclaim_is_reported() {
        // ★ A machine loses power, a user kills the process, a debugger stops it. A lock that treated every existing
        // file as a live owner would leave the daemon unable to start ever again — and a reclaim that was silent would
        // leave a user with an unexplained gap in the record.
        let dir = Cleanup::new("reclaim");
        dir.write_claim(0, 9_999);

        let startup = startup(&args(&dir.data(), &[]), HEARTBEAT_STALE_AFTER_MS + 1);
        assert!(startup.may_run(), "{startup:?}");
        let lines = startup.lines();
        let reclaim = lines
            .iter()
            .find(|line| line.contains("reclaimed"))
            .unwrap_or_else(|| panic!("no reclaim line in {lines:?}"));
        assert!(reclaim.contains("9999"), "{reclaim}");
        assert!(reclaim.contains("ended without shutting down"), "{reclaim}");
    }

    #[test]
    fn a_reclaim_is_reported_differently_from_taking_a_free_directory() {
        // The same event for the claim and different events for a user.
        let free = Cleanup::new("free-vs-reclaim");
        let stale = Cleanup::new("stale-vs-free");
        stale.write_claim(0, 1);

        let free_lines = startup(&args(&free.data(), &[]), 0).lines();
        let stale_lines = startup(&args(&stale.data(), &[]), HEARTBEAT_STALE_AFTER_MS + 1).lines();

        assert!(!free_lines.iter().any(|line| line.contains("reclaimed")), "{free_lines:?}");
        assert!(stale_lines.iter().any(|line| line.contains("reclaimed")), "{stale_lines:?}");
    }

    // ── A claim that cannot be read ───────────────────────────────────────────────────────────────

    #[test]
    fn a_claim_file_that_cannot_be_read_stops_the_start() {
        // It might be a live owner's. Treating it as absent is how a second daemon starts over a running one — the
        // failure the lock exists to prevent, arriving through the door the policy does not guard.
        let dir = Cleanup::new("garbage");
        std::fs::write(dir.lock_path(), "not a claim").expect("writes");

        let startup = startup(&args(&dir.data(), &[]), 0);
        assert!(!startup.may_run(), "{startup:?}");
        assert_eq!(startup.exit_code(), 1);
        assert!(startup.failure().is_some());
    }

    #[test]
    fn an_empty_claim_file_is_recovered_from() {
        // What a process killed between creating and writing leaves behind. Refusing would leave a daemon unable to
        // start after exactly the crash the lock exists to recover from.
        let dir = Cleanup::new("empty-recover");
        std::fs::write(dir.lock_path(), "").expect("writes");
        assert!(startup(&args(&dir.data(), &[]), 0).may_run());
    }

    // ── Diagnostic and dry runs ───────────────────────────────────────────────────────────────────

    #[test]
    fn a_diagnostic_run_starts_even_when_the_directory_is_held() {
        // A user who wants to see what a running daemon thinks should not have to stop it.
        let dir = Cleanup::new("diagnostic");
        dir.write_claim(1_000, 4_242);
        let startup = startup(&args(&dir.data(), &["--diagnostic"]), 2_000);
        assert!(startup.may_run(), "{startup:?}");
        assert!(startup.lines().iter().any(|line| line.contains("diagnostic run")), "{:?}", startup.lines());
    }

    #[test]
    fn starting_writes_the_claim_it_decided_about() {
        // ★ A daemon that only *decided* it owned the directory reported "claimed the data directory" while leaving no
        // file behind, so a second instance decided the same thing and both believed they were alone. The exclusive
        // claim was decorative.
        let dir = Cleanup::new("writes-claim");
        let decision = begin(&args(&dir.data(), &[]), 4_242, 1_000);
        assert!(decision.may_run(), "{decision:?}");

        let path = dir.lock_path();
        let written = ClaimFile::read(&path).expect("reads");
        let lock = written.as_lock().expect("a claim was written");
        assert_eq!(lock.owner.pid, 4_242);
        assert_eq!(lock.owner.heartbeat_ms, 1_000);
        assert_eq!(lock.owner.claimed_at_ms, 1_000);
    }

    #[test]
    fn a_second_start_after_the_first_is_refused() {
        // The end-to-end property, through the file system rather than through the policy: the first start leaves a
        // claim, and the second sees it and refuses. This is the case that was broken.
        let dir = Cleanup::new("second-start");
        let first = begin(&args(&dir.data(), &[]), 1_111, 1_000);
        assert!(first.may_run(), "{first:?}");

        // One second later, so the heartbeat is fresh.
        let second = begin(&args(&dir.data(), &[]), 2_222, 2_000);
        assert!(!second.may_run(), "{second:?}");
        assert_eq!(second.exit_code(), 1);
        assert!(second.failure().expect("a reason").contains("1111"));
    }

    #[test]
    fn a_start_after_a_clean_shutdown_is_a_free_directory() {
        // A clean shutdown takes its own claim away, so the next start is an ordinary first start rather than a
        // reclaim that writes "the previous session ended without shutting down" into the log about a session that
        // ended perfectly well.
        let dir = Cleanup::new("clean-shutdown");
        let first = begin(&args(&dir.data(), &[]), 1_111, 1_000);
        assert!(first.may_run(), "{first:?}");
        release(&first).expect("releases");
        // ★ The claim is *kept* and marked, not deleted: a deleted file is indistinguishable from a daemon killed
        // before it wrote one, and that difference is what the next start wants to know.
        assert!(dir.lock_path().exists(), "a clean shutdown deleted its claim");
        let kept = ClaimFile::read(&dir.lock_path()).expect("reads");
        assert!(kept.as_lock().expect("a claim").owner.clean, "the claim was not marked clean");

        let second = begin(&args(&dir.data(), &[]), 2_222, 2_000);
        assert!(second.may_run(), "{second:?}");
        assert!(
            !second.lines().iter().any(|line| line.contains("reclaimed")),
            "a clean restart reported a crash: {:?}",
            second.lines()
        );
    }

    #[test]
    fn a_diagnostic_run_writes_no_claim() {
        // Writing one would make a run that promised not to touch the directory the one that held it.
        let dir = Cleanup::new("diagnostic-no-write");
        let decision = begin(&args(&dir.data(), &["--diagnostic"]), 4_242, 1_000);
        assert!(decision.may_run(), "{decision:?}");
        assert!(!dir.lock_path().exists(), "a diagnostic run took a claim");
    }

    #[test]
    fn a_dry_run_writes_no_claim() {
        let dir = Cleanup::new("dry-no-write");
        let decision = begin(&args(&dir.data(), &["--dry-run"]), 4_242, 1_000);
        assert_eq!(decision.exit_code(), 0);
        assert!(decision.plan().is_none(), "a dry run has no claim to release");
        assert!(!dir.lock_path().exists());
    }

    #[test]
    fn a_refreshed_heartbeat_keeps_the_claim_identity() {
        // The claimed-at reading and the pid are the identity: a user reading the file wants to know when the session
        // started and which process it is. Overwriting them on every beat would make `claimedAtMs` mean "the last
        // beat", which is the one thing a reader is trying to tell apart from the heartbeat.
        let dir = Cleanup::new("heartbeat");
        let decision = begin(&args(&dir.data(), &[]), 4_242, 1_000);
        assert!(decision.may_run(), "{decision:?}");
        let path = dir.lock_path();
        let lock = ClaimFile::read(&path)
            .expect("reads")
            .as_lock()
            .expect("a claim")
            .clone();

        let refreshed = crate::args::refresh_claim(&path, &lock, 4_000).expect("refreshes");
        assert_eq!(refreshed.owner.heartbeat_ms, 4_000);
        assert_eq!(refreshed.owner.claimed_at_ms, 1_000, "the identity moved");
        assert_eq!(refreshed.owner.pid, 4_242);

        // And it is still one claim, readable, with the new beat — so a live daemon does not look dead.
        let reread = ClaimFile::read(&path).expect("reads");
        assert_eq!(reread.as_lock().expect("a claim").owner.heartbeat_ms, 4_000);
    }

    #[test]
    fn removing_a_claim_that_is_gone_is_not_an_error() {
        // A shutdown that failed because it had already cleaned up would report a problem where there is none.
        let dir = Cleanup::new("remove-twice");
        let path = dir.lock_path();
        assert!(crate::args::remove_claim(&path).is_ok(), "a missing file is not a failure");
        let decision = begin(&args(&dir.data(), &[]), 1, 0);
        assert!(decision.may_run(), "{decision:?}");
        assert!(crate::args::remove_claim(&path).is_ok());
        assert!(crate::args::remove_claim(&path).is_ok());
    }

    #[test]
    fn a_dry_run_succeeds_without_claiming_anything() {
        // It did exactly what was asked of it, and exiting non-zero would make a script that checks a configuration
        // treat a good configuration as an error.
        let dir = Cleanup::new("dry");
        let startup = startup(&args(&dir.data(), &["--dry-run"]), 0);
        assert_eq!(startup.exit_code(), 0);
        assert!(!startup.may_run(), "a dry run does not start a kernel");
        assert!(startup.lines().iter().any(|line| line.contains("dry run")), "{:?}", startup.lines());
        // And nothing was written.
        assert!(!dir.lock_path().exists());
    }

    #[test]
    fn a_dry_run_reports_a_configuration_that_would_be_refused() {
        // The whole value of a dry run: a user finds out before starting that their two ports collide.
        let dir = Cleanup::new("dry-refused");
        let root = dir.data().display().to_string();
        let args = DaemonArgs::try_parse_from([
            "synra-daemon",
            "--data-dir",
            root.as_str(),
            "--listen-port",
            "5000",
            "--discovery-port",
            "5000",
            "--dry-run",
        ])
        .expect("parses");

        let startup = startup(&args, 0);
        assert!(matches!(startup, Startup::Refused { .. }), "{startup:?}");
        assert_eq!(startup.exit_code(), 1);
        assert!(startup.failure().expect("a reason").contains("5000"));
    }

    #[test]
    fn a_refused_startup_prints_nothing_of_the_plan() {
        // The plan describes an installation that will not exist, and printing it would suggest otherwise.
        let dir = Cleanup::new("refused-lines");
        let root = dir.data().display().to_string();
        let args = DaemonArgs::try_parse_from([
            "synra-daemon",
            "--data-dir",
            root.as_str(),
            "--listen-port",
            "5000",
            "--discovery-port",
            "5000",
        ])
        .expect("parses");
        assert!(startup(&args, 0).lines().is_empty());
    }

    // ── The report ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_report_describes_a_start_that_will_happen() {
        let dir = Cleanup::new("report");
        let startup = startup(&args(&dir.data(), &[]), 0);
        let report = startup.report().expect("a report");
        assert!(!report.can_prompt_the_user, "this host has no window");
        assert!(report.exclusive);
        assert!(report.linger);
        assert_eq!(report.listen_port, 0);
    }

    #[test]
    fn a_refused_startup_reports_nothing() {
        // A bundle that described a plan for a start that was refused would describe an installation that does not
        // exist.
        let dir = Cleanup::new("report-refused");
        dir.write_claim(1_000, 1);
        assert!(startup(&args(&dir.data(), &[]), 2_000).report().is_none());
    }

    #[test]
    fn the_report_serialises_for_a_bundle() {
        let dir = Cleanup::new("report-json");
        let report = startup(&args(&dir.data(), &[]), 0).report().expect("a report");
        let json = serde_json::to_value(&report).expect("serialises");
        assert_eq!(json["canPromptTheUser"], false);
        assert_eq!(json["linger"], true);
        assert!(json["dataDir"].is_string());
    }

    // ── Recognising a data directory ──────────────────────────────────────────────────────────────

    #[test]
    fn a_directory_with_a_lock_or_a_database_looks_like_one() {
        // The question the CLI's `doctor` also asks, and one answer for both is how the two stay in step.
        let dir = Cleanup::new("recognise");
        assert!(!looks_like_a_data_dir(&dir.data()), "an empty directory is not one");

        std::fs::write(dir.data().join("synra.db"), "").expect("writes");
        assert!(looks_like_a_data_dir(&dir.data()));

        let other = Cleanup::new("recognise-lock");
        std::fs::write(other.data().join(crate::plan::LOCK_FILE_NAME), "").expect("writes");
        assert!(looks_like_a_data_dir(&other.data()));
    }
}
