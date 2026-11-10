use super::data::{Consent, Progress, Resolved, Verified};
use super::source::{FailStage, InstallSource};

/// A move through the pipeline.
///
/// # Why the moves carry their results
///
/// Because the alternative is a caller that produces a value and then tells the slot about it, which is two places
/// that can disagree about what was produced. `Resolved { resolved }` is the same value the next state holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Move {
    /// Begin: the user asked for this source.
    Install {
        /// What was asked for.
        source: InstallSource,
    },
    /// Resolving produced this.
    Resolved {
        /// What resolving found.
        resolved: Resolved,
    },
    /// A download reported progress.
    Downloaded {
        /// How much.
        progress: Progress,
    },
    /// The bytes arrived and hashed to this.
    Fetched {
        /// The digest of the bytes.
        artifact_digest: String,
    },
    /// Verification passed.
    Verified {
        /// What it concluded.
        verified: Verified,
    },
    /// The user decided.
    Consented {
        /// What they allowed.
        consent: Consent,
    },
    /// It is on disk.
    Installed,
    /// The plugin asked to be started and the host is loading it.
    Activate,
    /// It is running.
    Activated,
    /// Stop it.
    Deactivate,
    /// It stopped.
    Deactivated,
    /// It misbehaved.
    Fault {
        /// Why, in a sentence.
        reason: String,
    },
    /// The user re-enabled it.
    ClearFault,
    /// Remove it.
    Remove,
    /// It is gone.
    Removed,
    /// Retry an installation that failed.
    Retry,
    /// Give up on one that failed.
    Abandon,
    /// Something went wrong.
    Fail {
        /// Which stage.
        stage: FailStage,
        /// What happened.
        detail: String,
        /// Whether the caller knows a retry cannot fix it. `None` takes the stage's own answer.
        retryable: Option<bool>,
    },
}

impl Move {
    /// A short name, for a log line.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Install { .. } => "install",
            Self::Resolved { .. } => "resolved",
            Self::Downloaded { .. } => "downloaded",
            Self::Fetched { .. } => "fetched",
            Self::Verified { .. } => "verified",
            Self::Consented { .. } => "consented",
            Self::Installed => "installed",
            Self::Activate => "activate",
            Self::Activated => "activated",
            Self::Deactivate => "deactivate",
            Self::Deactivated => "deactivated",
            Self::Fault { .. } => "fault",
            Self::ClearFault => "clear-fault",
            Self::Remove => "remove",
            Self::Removed => "removed",
            Self::Retry => "retry",
            Self::Abandon => "abandon",
            Self::Fail { .. } => "fail",
        }
    }
}
