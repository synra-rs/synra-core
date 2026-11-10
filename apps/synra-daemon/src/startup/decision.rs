use serde::Serialize;

use crate::lock::{Claim, HEARTBEAT_INTERVAL_MS, LockFile, LockOwner};
use crate::plan::DaemonPlan;

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
