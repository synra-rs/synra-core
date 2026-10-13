//! The daemon's flags, and the reading of the claim file.
//!
//! # Why the file reading is here
//!
//! [`lock::decide`] is the policy and takes a decoded value, because that is the part worth testing. Turning bytes into
//! that value is I/O, and it is the part with the *failure modes a policy cannot see*: a file that exists and cannot
//! be read, a file that is not JSON, a file written by a newer build.
//!
//! Those are separated deliberately. A lock that cannot be read might be a live owner's, so treating it as absent
//! would start a second instance over a running one — which is the failure the whole lock exists to prevent, arriving
//! through the door the policy does not guard. So `read_claim` refuses rather than returning "no lock", and the
//! distinction between "nothing there" and "something there I could not understand" is the point of it.
//!
//! # Why the flags are a struct
//!
//! So the daemon can be started from a test with a plan, and so a flag that contradicts another is refused by `clap`
//! rather than by whichever branch runs first.

use std::path::Path;

use clap::Parser;

use crate::lock::{Claim, LockError, LockFile, decide};
use crate::plan::{DATA_DIR_VAR, DaemonOptions, DaemonPlan, PlanError, default_data_root};

/// The kernel's windowless host.
#[derive(Debug, Parser)]
#[command(
    name = "synra-daemon",
    version,
    about = "Runs the Synra kernel with no interface",
    long_about = "Runs the kernel without a window and keeps serving after any client disconnects. It exists to \
                  prove the kernel needs no interface, and as the shape a user gets when they want the kernel to \
                  outlive the application."
)]
pub struct DaemonArgs {
    /// Where the data lives.
    ///
    /// Defaults to the same answer `synra` uses, from the same environment variable, so `synra doctor` checks the
    /// installation this daemon actually runs.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<std::path::PathBuf>,

    /// The transport port.
    #[arg(long, value_name = "PORT", default_value_t = crate::plan::DEFAULT_LISTEN_PORT)]
    pub listen_port: u16,

    /// The discovery port.
    #[arg(long, value_name = "PORT", default_value_t = crate::plan::DEFAULT_DISCOVERY_PORT)]
    pub discovery_port: u16,

    /// Run without claiming the data directory.
    ///
    /// For looking at a live installation: a user who wants to see what a running daemon thinks should not have to
    /// stop it. Two daemons writing one database is not something this flag makes safe, and the flag's name says what
    /// it is for rather than what it does.
    #[arg(long, conflicts_with = "exclusive")]
    pub diagnostic: bool,

    /// Exit when the last client disconnects, rather than keeping running.
    ///
    /// What a user wants when running one from a terminal to watch it.
    #[arg(long)]
    pub exit_with_last_client: bool,

    /// Claim the data directory exclusively, which is the default.
    ///
    /// The opposite of `--diagnostic`, spelled out so a script can be explicit rather than relying on a default.
    #[arg(long)]
    pub exclusive: bool,

    /// Print the start-up plan and exit.
    ///
    /// For a script and for a user who wants to know which directories and ports a start would use without starting
    /// one.
    #[arg(long)]
    pub dry_run: bool,
}

impl DaemonArgs {
    /// The options these flags describe.
    #[must_use]
    pub fn options(&self) -> DaemonOptions {
        DaemonOptions {
            data_dir: self.data_dir.clone().unwrap_or_else(default_data_root),
            listen_port: self.listen_port,
            discovery_port: self.discovery_port,
            // `--diagnostic` means not exclusive. `--exclusive` is the default spelled out, so it cannot turn a
            // diagnostic run back into a claiming one — `clap` refuses both at once.
            exclusive: !self.diagnostic,
            linger: !self.exit_with_last_client,
        }
    }
}

/// The flags, with the plan checked.
#[derive(Debug)]
pub struct Parsed {
    /// What the daemon will do.
    pub plan: DaemonPlan,
    /// Whether to print the plan and stop.
    pub dry_run: bool,
}

impl Parsed {
    /// Checks the flags and resolves the plan.
    ///
    /// # Errors
    ///
    /// [`PlanError`] when the ports or directories are unusable.
    pub fn resolve(args: &DaemonArgs) -> Result<Self, PlanError> {
        Ok(Self { plan: DaemonPlan::resolve(&args.options())?, dry_run: args.dry_run })
    }
}

/// What was on disk, as far as this build can tell.
///
/// # The two failures are different from "nothing there"
///
/// A missing file is a free directory. A file that exists and cannot be interpreted is *not* — it might be a live
/// owner's, and treating it as absent is how a second daemon starts over a running one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimFile {
    /// Nothing owns the directory.
    Absent,
    /// A claim was read.
    Found(Box<LockFile>),
}

impl ClaimFile {
    /// Reads the claim file.
    ///
    /// # Errors
    ///
    /// [`LockError::Unreadable`] when the file exists and cannot be read as a claim, and
    /// [`LockError::FromTheFuture`] when it was written by a newer build. Both are refusals rather than "absent".
    pub fn read(path: &Path) -> Result<Self, LockError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            // A missing file is the ordinary first start. Every other read error — permission, a directory where a
            // file should be, a device that does not answer — might be a live owner's claim and is refused.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(error) => {
                return Err(LockError::Unreadable {
                    path: path.display().to_string(),
                    reason: error.to_string(),
                });
            }
        };

        // An empty file is what a process killed *between* creating and writing leaves behind. It is not a claim, and
        // it is also not another instance — so it is absent rather than unreadable, because refusing would leave a
        // daemon unable to start after exactly the crash this module exists to recover from.
        if text.trim().is_empty() {
            return Ok(Self::Absent);
        }

        match serde_json::from_str::<LockFile>(&text) {
            Ok(file) => Ok(Self::Found(Box::new(file))),
            Err(error) => Err(LockError::Unreadable {
                path: path.display().to_string(),
                reason: format!("the claim file is not one this build understands: {error}"),
            }),
        }
    }

    /// The lock value, for [`decide`].
    #[must_use]
    pub fn as_lock(&self) -> Option<&LockFile> {
        match self {
            Self::Absent => None,
            Self::Found(file) => Some(file),
        }
    }

    /// Decides the claim from what was on disk.
    ///
    /// # Errors
    ///
    /// [`LockError`] when the file was written by a newer build.
    pub fn decide(&self, now_ms: u64, path: &Path) -> Result<Claim, LockError> {
        decide(self.as_lock(), now_ms, &path.display().to_string())
    }
}

/// Writes the claim for this process.
///
/// # Why writing is separate from deciding
///
/// Deciding is a pure function of what was on disk, which is the part worth testing. Writing is the part that makes
/// the decision *mean* something — and this function exists because a daemon that decided it owned the directory and
/// never wrote the file reported "claimed the data directory" while leaving no claim behind, so a second instance
/// decided the same thing. The exclusive claim was decorative.
///
/// # Errors
///
/// [`LockError::Unreadable`] when the directory cannot be made or the file cannot be written. A daemon that cannot
/// write its claim must not start: it would be running while believing it holds a claim it does not.
pub fn write_claim(path: &Path, pid: u32, now_ms: u64) -> Result<LockFile, LockError> {
    let refuse =
        |reason: String| LockError::Unreadable { path: path.display().to_string(), reason };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| refuse(format!("the data directory could not be made: {error}")))?;
    }

    let lock = LockFile::claim(pid, env!("CARGO_PKG_VERSION"), now_ms);
    std::fs::write(path, encode_claim(&lock, path)?)
        .map_err(|error| refuse(format!("the claim could not be written: {error}")))?;
    Ok(lock)
}

/// Rewrites the claim's heartbeat, leaving its identity alone.
///
/// # Errors
///
/// [`LockError::Unreadable`] when the file cannot be rewritten.
///
/// # Why the identity is preserved
///
/// The claimed-at reading and the pid *are* the claim's identity: a user reading the file wants to know when the
/// session started and which process it is. Overwriting them on every beat would make `claimed_at_ms` mean "the last
/// beat", which is the one thing a reader is trying to tell apart from the heartbeat.
pub fn refresh_claim(path: &Path, lock: &LockFile, now_ms: u64) -> Result<LockFile, LockError> {
    let mut refreshed = lock.clone();
    refreshed.owner.heartbeat_ms = now_ms;
    std::fs::write(path, encode_claim(&refreshed, path)?).map_err(|error| LockError::Unreadable {
        path: path.display().to_string(),
        reason: format!("the heartbeat could not be written: {error}"),
    })?;
    Ok(refreshed)
}

/// Removes the claim.
///
/// # Errors
///
/// [`LockError::Unreadable`] when the file exists and cannot be removed. A missing file is **not** an error: the claim
/// being gone is the outcome the caller wanted, and a shutdown that failed because it had already cleaned up would be
/// a shutdown that reported a problem where there is none.
pub fn remove_claim(path: &Path) -> Result<(), LockError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LockError::Unreadable {
            path: path.display().to_string(),
            reason: format!("the claim could not be removed: {error}"),
        }),
    }
}

/// The claim file's contents for an owner, as text.
///
/// # Errors
///
/// [`LockError::Unreadable`] when it cannot be serialised, which is a bug in the shape rather than a runtime
/// condition — and reported rather than unwrapped because a daemon that panicked while writing its lock would leave
/// the file it was mid-write on.
pub fn encode_claim(lock: &LockFile, path: &Path) -> Result<String, LockError> {
    serde_json::to_string_pretty(lock).map_err(|error| LockError::Unreadable {
        path: path.display().to_string(),
        reason: format!("the claim could not be written: {error}"),
    })
}

/// The environment variable that moves the data directory, re-exported for a caller that wants to set it.
pub const ENV_DATA_DIR: &str = DATA_DIR_VAR;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;
    use crate::lock::HEARTBEAT_STALE_AFTER_MS;
    use crate::plan::{DEFAULT_DISCOVERY_PORT, DEFAULT_LISTEN_PORT};

    fn parse(args: &[&str]) -> Result<DaemonArgs, clap::Error> {
        DaemonArgs::try_parse_from(args)
    }

    fn parsed(args: &[&str]) -> DaemonArgs {
        parse(args).expect("parses")
    }

    /// A directory that exists for the duration of one test.
    ///
    /// The crate has no `tempfile` dependency; a directory under the system's temporary location, named after the
    /// test's own thread, is enough and is removed by `Cleanup`.
    struct Cleanup(std::path::PathBuf);

    impl Cleanup {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("synra-daemon-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creates");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── Flags ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_parser_is_internally_consistent() {
        // `clap`'s own check: two flags with one long name, a conflict that names a flag that does not exist, and so
        // on. A build failure rather than something a user finds.
        DaemonArgs::command().debug_assert();
    }

    #[test]
    fn the_defaults_claim_the_directory_and_linger() {
        // Two daemons over one database is a correctness problem, and a daemon whose purpose is to keep serving after
        // the interface closes must not exit with it.
        let args = parsed(&["synra-daemon"]);
        let options = args.options();
        assert!(options.exclusive);
        assert!(options.linger);
        assert_eq!(options.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(options.discovery_port, DEFAULT_DISCOVERY_PORT);
    }

    #[test]
    fn a_diagnostic_run_does_not_claim_the_directory() {
        // For looking at a live installation: a user who wants to see what a running daemon thinks should not have to
        // stop it.
        let args = parsed(&["synra-daemon", "--diagnostic"]);
        assert!(!args.options().exclusive);
    }

    #[test]
    fn diagnostic_and_exclusive_together_are_refused() {
        // They are opposites, and `clap` refusing both means the choice is never silently one of them.
        assert!(parse(&["synra-daemon", "--diagnostic", "--exclusive"]).is_err());
    }

    #[test]
    fn a_daemon_can_be_told_to_exit_with_its_last_client() {
        let args = parsed(&["synra-daemon", "--exit-with-last-client"]);
        assert!(!args.options().linger);
    }

    #[test]
    fn the_ports_can_be_moved() {
        // A user with two profiles needs to move them, which is the thing that collides.
        let args = parsed(&["synra-daemon", "--listen-port", "5000", "--discovery-port", "5001"]);
        let options = args.options();
        assert_eq!(options.listen_port, 5_000);
        assert_eq!(options.discovery_port, 5_001);
    }

    #[test]
    fn a_port_outside_the_range_is_refused_by_the_parser() {
        // A `u16` cannot hold it, so `clap` refuses before the plan sees a number the socket layer would truncate.
        assert!(parse(&["synra-daemon", "--listen-port", "70000"]).is_err());
        assert!(parse(&["synra-daemon", "--listen-port", "-1"]).is_err());
        assert!(parse(&["synra-daemon", "--listen-port", "many"]).is_err());
    }

    #[test]
    fn the_data_directory_can_be_moved() {
        let args = parsed(&["synra-daemon", "--data-dir", "/custom"]);
        assert_eq!(args.options().data_dir, std::path::PathBuf::from("/custom"));
    }

    #[test]
    fn a_dry_run_is_a_flag_rather_than_a_mode() {
        // Given a real directory, because the point of a dry run is to exercise the same checks a start would — and a
        // fixture that skipped them would be testing a path the daemon does not take.
        let dir = Cleanup::new("dry-run-flag");
        let root = dir.path().display().to_string();
        let args = parsed(&["synra-daemon", "--data-dir", root.as_str(), "--dry-run"]);
        assert!(args.dry_run);
        assert!(Parsed::resolve(&args).is_ok());
    }

    #[test]
    fn a_dry_run_reports_a_plan_that_would_be_refused() {
        // The whole value of a dry run: a user finds out before starting that their two ports collide.
        let args = parsed(&["synra-daemon", "--listen-port", "5000", "--discovery-port", "5000", "--dry-run"]);
        assert!(matches!(Parsed::resolve(&args), Err(PlanError::PortsCollide { port: 5_000 })));
    }

    // ── Reading a claim ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_missing_claim_file_is_a_free_directory() {
        // The ordinary first start.
        let dir = Cleanup::new("missing");
        let path = dir.path().join("daemon.lock");
        let claim = ClaimFile::read(&path).expect("reads");
        assert_eq!(claim, ClaimFile::Absent);
        assert!(claim.decide(0, &path).expect("decides").may_run());
    }

    #[test]
    fn an_empty_claim_file_is_absent_rather_than_unreadable() {
        // What a process killed *between* creating and writing leaves behind. It is not a claim and not another
        // instance, so refusing would leave a daemon unable to start after exactly the crash this module exists to
        // recover from.
        let dir = Cleanup::new("empty");
        let path = dir.path().join("daemon.lock");
        std::fs::write(&path, "").expect("writes");
        assert_eq!(ClaimFile::read(&path).expect("reads"), ClaimFile::Absent);

        // Whitespace too, which is what a partial write can leave.
        std::fs::write(&path, "   \n").expect("writes");
        assert_eq!(ClaimFile::read(&path).expect("reads"), ClaimFile::Absent);
    }

    #[test]
    fn a_claim_file_that_is_not_json_is_refused_rather_than_treated_as_absent() {
        // ★ It might be a live owner's file that this build cannot parse. Treating it as absent is how a second daemon
        // starts over a running one — the failure the lock exists to prevent, arriving through the door the policy
        // does not guard.
        let dir = Cleanup::new("garbage");
        let path = dir.path().join("daemon.lock");
        std::fs::write(&path, "not a claim").expect("writes");

        match ClaimFile::read(&path) {
            Err(LockError::Unreadable { path: named, reason }) => {
                assert!(named.contains("daemon.lock"), "{named}");
                assert!(!reason.is_empty());
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_claim_file_a_directory_cannot_be_read_is_refused() {
        // A directory where a file should be is not "no lock": something is there, and something there unreadable is
        // exactly the case that must not become a second instance.
        let dir = Cleanup::new("isdir");
        let path = dir.path().join("daemon.lock");
        std::fs::create_dir_all(&path).expect("creates");
        assert!(matches!(ClaimFile::read(&path), Err(LockError::Unreadable { .. })));
    }

    #[test]
    fn a_valid_claim_file_is_read_into_the_policy() {
        let dir = Cleanup::new("valid");
        let path = dir.path().join("daemon.lock");
        let lock = LockFile::claim(4_242, "0.1.0", 1_000);
        std::fs::write(&path, encode_claim(&lock, &path).expect("encodes")).expect("writes");

        let claim = ClaimFile::read(&path).expect("reads");
        assert_eq!(claim.as_lock(), Some(&lock));

        // And the policy sees a live owner.
        assert!(!claim.decide(2_000, &path).expect("decides").may_run());
    }

    #[test]
    fn a_stale_claim_file_is_read_and_reclaimed() {
        // The crash recovery, through the file rather than through the policy alone.
        let dir = Cleanup::new("stale");
        let path = dir.path().join("daemon.lock");
        std::fs::write(&path, encode_claim(&LockFile::claim(1, "0.1.0", 0), &path).expect("encodes"))
            .expect("writes");

        let claim = ClaimFile::read(&path).expect("reads");
        let decision = claim.decide(HEARTBEAT_STALE_AFTER_MS + 1, &path).expect("decides");
        assert!(matches!(decision, Claim::Reclaimed { .. }));
        assert!(decision.may_run());
    }

    #[test]
    fn a_claim_from_a_newer_build_is_refused() {
        // Through the file, so the version check is exercised where it is actually reached.
        let dir = Cleanup::new("future");
        let path = dir.path().join("daemon.lock");
        let mut lock = LockFile::claim(1, "9.9.9", 0);
        lock.version = crate::lock::LOCK_FORMAT_VERSION + 1;
        std::fs::write(&path, serde_json::to_string(&lock).expect("serialises")).expect("writes");

        let claim = ClaimFile::read(&path).expect("reads, since the JSON is fine");
        assert!(matches!(claim.decide(0, &path), Err(LockError::FromTheFuture { .. })));
    }

    #[test]
    fn an_encoded_claim_round_trips() {
        let path = Path::new("/lock");
        let lock = LockFile::claim(7, "0.1.0", 1_000);
        let text = encode_claim(&lock, path).expect("encodes");
        let back: LockFile = serde_json::from_str(&text).expect("decodes");
        assert_eq!(back, lock);
        // Pretty, because a user reads this file when they are deciding whether to kill something.
        assert!(text.contains('\n'), "{text}");
    }

    #[test]
    fn the_environment_variable_is_the_one_the_cli_uses() {
        // One spelling for both binaries, or `synra doctor` checks a directory the daemon does not use.
        assert_eq!(ENV_DATA_DIR, "SYNRA_DATA_DIR");
    }
}
