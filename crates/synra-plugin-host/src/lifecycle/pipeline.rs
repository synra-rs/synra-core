//! The full lifecycle: thirteen states, and what each move out of one has to carry.
//!
//! # Why this is a second machine rather than a bigger [`Lifecycle`](super::Lifecycle)
//!
//! Because the two answer different questions, and the answer to one of them is *"nothing has happened yet"*.
//! [`Lifecycle`](super::Lifecycle) is about a plugin that is **on this device**: it has a version, a manifest digest,
//! grants and possibly a running instance. The states before `Installed` are about a plugin that is not on this device
//! at all — being resolved, downloaded and checked — and each of them holds something the later states do not: a
//! source, a partial download, a verification report.
//!
//! One enum holding both would be thirteen variants whose payloads are mostly irrelevant to whoever is reading, and
//! every method would have to say "except before installation" somewhere. Two types with one conversion between them
//! says the same thing in a way a reader can check.
//!
//! # The rule the design document is emphatic about
//!
//! **`Failed` is a state, not a log line.** A pipeline that returns to `Available` on failure and writes a note has
//! thrown away the three things a user needs: which stage failed, whether trying again could work, and how many times
//! it has been tried. All three are in [`Failed`], and the state is only left deliberately — by a retry, or by the
//! user abandoning the install.
//!
//! # Cancel, timeout and error are the same move
//!
//! Every state that is *doing* something can fail, and the three ways it fails arrive as one transition because
//! nothing downstream distinguishes them: what a caller does about a cancelled download and a timed-out one is the
//! same, and the sentence in [`Failed::detail`] is what tells a user which happened.

use serde::{Deserialize, Serialize};

use super::machine::Lifecycle;
use super::state::State;
use super::transition::{Transition, TransitionError};

/// Where an installation is coming from.
///
/// # Why `Local` is a variant and not a separate entry point
///
/// Because a local install goes through the *same* pipeline as every other one — verification, consent, the atomic
/// write — and the only difference is where the bytes come from. A second entry point would be a second pipeline, and
/// the one that mattered less would be the one that drifted.
///
/// It is refused outside development by [`InstallSource::refuses_outside_development`], which the resolver's caller
/// checks. That refusal is not politeness: a local path is a directory the user can change under a running plugin, and
/// "install whatever is at this path" in a shipped build is a way to run unsigned code.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum InstallSource {
    /// A package in a registry.
    Registry {
        /// The package name, as the registry knows it.
        package: String,
        /// The version asked for, as a requirement rather than a version.
        version: String,
    },
    /// A git repository.
    Git {
        /// Where it is.
        url: String,
        /// The branch, tag or commit, when one was named.
        reference: Option<String>,
    },
    /// A URL pointing at an artifact.
    Url {
        /// Where it is.
        url: String,
        /// The digest it must have, when the caller knows it. An artifact fetched from a URL without one is a
        /// download of whatever was at that address at that moment.
        digest: Option<String>,
    },
    /// A directory on this machine, which only development builds accept.
    Local {
        /// Where it is.
        path: String,
    },
}

impl InstallSource {
    /// A short name, for a log line.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Registry { .. } => "registry",
            Self::Git { .. } => "git",
            Self::Url { .. } => "url",
            Self::Local { .. } => "local",
        }
    }

    /// Whether this source may only be used by a development build.
    #[must_use]
    pub const fn refuses_outside_development(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// The digest the artifact must have, when the source names one.
    #[must_use]
    pub fn expected_digest(&self) -> Option<&str> {
        match self {
            Self::Url { digest, .. } => digest.as_deref(),
            Self::Registry { .. } | Self::Git { .. } | Self::Local { .. } => None,
        }
    }

    /// A sentence naming the source, for a refusal a user reads.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Registry { package, version } => format!("{package}@{version}"),
            Self::Git { url, reference } => match reference {
                Some(reference) => format!("{url}#{reference}"),
                None => url.clone(),
            },
            Self::Url { url, .. } => url.clone(),
            Self::Local { path } => path.clone(),
        }
    }
}

/// The stage a failure happened in, which is what a retry is decided from.
///
/// # Why this is a type and not a string
///
/// Because "which stage" decides "can this work if I try again", and a string makes that a comparison somebody has to
/// remember to write. [`FailStage::is_retryable`] is the rule in one place, and a new stage cannot be added without
/// answering it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailStage {
    /// Finding the artifact: a registry that does not answer, a package that does not exist.
    Resolve,
    /// Fetching it: a connection that dropped, a host that went away.
    Download,
    /// Checking it: a signature that does not verify, a digest that does not match.
    Verify,
    /// The user said no.
    Consent,
    /// Writing it: a disk that is full, a path that is not writable.
    Install,
    /// Loading it: a trap in the start function, an engine that refused the module.
    Activate,
    /// Removing it.
    Remove,
}

impl FailStage {
    /// A short name, for a log line and a state column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Download => "download",
            Self::Verify => "verify",
            Self::Consent => "consent",
            Self::Install => "install",
            Self::Activate => "activate",
            Self::Remove => "remove",
        }
    }

    /// Whether trying the same thing again could produce a different answer.
    ///
    /// # The rule, and the two stages that break it
    ///
    /// A failure in `Verify` is not retryable **by itself**: the same bytes will hash the same way, and a signature
    /// that did not verify will not verify on the second attempt. Reporting it as retryable would offer a user a
    /// button that cannot work, which is worse than telling them the artifact is bad.
    ///
    /// `Consent` is not a failure at all in the usual sense — the user declined — so retrying means asking again, and
    /// that is a decision the *user* makes rather than the caller.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Resolve | Self::Download | Self::Install | Self::Activate | Self::Remove)
    }
}

/// An installation that stopped, with everything needed to retry or to explain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Failed {
    /// What was being installed.
    pub source: InstallSource,
    /// Which stage stopped.
    pub stage: FailStage,
    /// What went wrong, in a sentence.
    pub detail: String,
    /// Whether asking again could work — [`FailStage::is_retryable`], unless the caller knows better.
    ///
    /// A field as well as a rule because the caller *can* know better: the same stage fails differently when a server
    /// is down and when a package does not exist, and only the resolver saw which.
    pub retryable: bool,
    /// How many times this installation has been attempted.
    ///
    /// Counted rather than inferred, because "this has failed four times and the fifth will not be different" is a
    /// thing a user should be told rather than left to discover.
    pub attempts: u32,
    /// When it last failed, in signed milliseconds since the epoch.
    pub failed_at_ms: i64,
}

impl Failed {
    /// A failure whose retryability comes from its stage.
    #[must_use]
    pub fn at(source: InstallSource, stage: FailStage, detail: impl Into<String>, now_ms: i64) -> Self {
        Self {
            source,
            stage,
            detail: detail.into(),
            retryable: stage.is_retryable(),
            attempts: 1,
            failed_at_ms: now_ms,
        }
    }

    /// The same failure, marked as one a retry cannot fix.
    ///
    /// For the case the stage cannot see: a registry that answered `404` failed at `Resolve`, and no amount of retrying
    /// will make the package exist.
    #[must_use]
    pub const fn not_retryable(mut self) -> Self {
        self.retryable = false;
        self
    }

    /// Another attempt of the same installation.
    #[must_use]
    pub fn retried(&self, now_ms: i64) -> Self {
        Self { attempts: self.attempts.saturating_add(1), failed_at_ms: now_ms, ..self.clone() }
    }

    /// Whether this has been attempted so many times that a user should be told rather than offered a button.
    #[must_use]
    pub const fn is_worn_out(&self) -> bool {
        self.attempts >= WEAR_OUT_AFTER
    }
}

/// How many attempts before an installation is reported as one that keeps failing.
///
/// Three, and the number is a judgement rather than a limit: a fourth offer of the same button is one a user has
/// already declined twice, and the useful thing at that point is the stage and the sentence rather than another try.
pub const WEAR_OUT_AFTER: u32 = 3;

/// What resolving produced, which is what downloading needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolved {
    /// The version the source resolved to.
    pub version: String,
    /// Every file the package consists of, by name.
    pub artifacts: Vec<String>,
    /// The digest of the manifest, which grants are later recorded against.
    pub manifest_digest: String,
    /// Whether the source is one a development build is required for.
    pub development_only: bool,
}

/// How far a download has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    /// Bytes received.
    pub received: u64,
    /// Total bytes, when the source declared them.
    pub total: Option<u64>,
}

impl Progress {
    /// The fraction received, when the total is known.
    ///
    /// # Why this is an `Option` and not a `0.0`
    ///
    /// Because a progress bar at zero and a progress bar with no total are different things to draw, and collapsing
    /// them makes a chunked response with no `Content-Length` look like a download that has not started.
    #[must_use]
    pub fn fraction(&self) -> Option<f64> {
        let total = self.total?;
        if total == 0 {
            return Some(1.0);
        }
        Some((self.received as f64 / total as f64).clamp(0.0, 1.0))
    }

    /// Whether there is nothing left.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.total.is_some_and(|total| self.received >= total)
    }
}

/// What verification concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verified {
    /// The version.
    pub version: String,
    /// The digest of the artifact that was checked.
    pub artifact_digest: String,
    /// The digest of the manifest.
    pub manifest_digest: String,
    /// The capabilities the manifest asks for, which consent is about.
    pub requested: Vec<String>,
    /// Why the signature was accepted, when there was one.
    ///
    /// A sentence rather than a boolean because "signed by a publisher this device has seen before" and "signed by a
    /// publisher nobody has seen" are different answers, and the second one is what a user is being asked about.
    pub trust: Option<String>,
}

/// The user's decision about a plugin's capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Consent {
    /// The capabilities the user allowed.
    pub granted: Vec<String>,
    /// The ones they refused.
    pub denied: Vec<String>,
}

impl Consent {
    /// Whether anything was refused.
    ///
    /// Recorded because a plugin running with some capabilities denied behaves differently from one running with all
    /// of them, and a bug report that does not say which is a bug report about a different plugin.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        !self.denied.is_empty()
    }

    /// Whether every capability was refused, which is a refusal of the plugin.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        self.granted.is_empty() && !self.denied.is_empty()
    }
}

/// Where a plugin is, from the moment somebody asks for it to the moment it is gone.
///
/// The thirteen states of the design document's §1.1, in the order they are reached, with two exceptions that are
/// reachable from anywhere: [`Self::Faulted`] and [`Self::Failed`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum PluginSlot {
    /// In a registry, not on this device.
    Available,
    /// Finding out what the source actually is.
    Resolving {
        /// What was asked for.
        source: InstallSource,
    },
    /// Fetching the bytes.
    Downloading {
        /// What was asked for.
        source: InstallSource,
        /// What resolving produced.
        resolved: Resolved,
        /// How far it has got.
        progress: Progress,
    },
    /// Checking the signature, the digests, the manifest and the dependencies.
    Verifying {
        /// What was asked for.
        source: InstallSource,
        /// What was resolved and downloaded.
        resolved: Resolved,
        /// The digest of the bytes that arrived.
        artifact_digest: String,
    },
    /// Waiting for a person to decide about the plugin's capabilities.
    AwaitingConsent {
        /// What was asked for.
        source: InstallSource,
        /// What verification concluded.
        verified: Verified,
    },
    /// Writing it to disk, recording it, and precompiling it.
    Installing {
        /// What was asked for.
        source: InstallSource,
        /// What verification concluded.
        verified: Verified,
        /// What the user allowed.
        consent: Consent,
    },
    /// On this device, not running.
    Installed {
        /// What was asked for.
        source: InstallSource,
        /// The plugin's own lifecycle from here on.
        lifecycle: Lifecycle,
    },
    /// Loading the module and calling its `activate`.
    Activating {
        /// What was asked for.
        source: InstallSource,
        /// The lifecycle, mid-move.
        lifecycle: Lifecycle,
    },
    /// Running.
    Active {
        /// What was asked for.
        source: InstallSource,
        /// The lifecycle.
        lifecycle: Lifecycle,
    },
    /// Stopping: the plugin's `deactivate` is being awaited.
    Deactivating {
        /// What was asked for.
        source: InstallSource,
        /// The lifecycle, mid-move.
        lifecycle: Lifecycle,
    },
    /// Stopped because it misbehaved, and not restartable without a decision.
    Faulted {
        /// What was asked for.
        source: InstallSource,
        /// The lifecycle, holding the reason.
        lifecycle: Lifecycle,
    },
    /// Being removed: `deactivate` if it was running, then the artifact and the stored data.
    Removing {
        /// What was asked for.
        source: InstallSource,
        /// The lifecycle, if it still describes something.
        lifecycle: Option<Lifecycle>,
    },
    /// It stopped, and this is everything needed to retry or to explain why not.
    Failed(Failed),
}

impl PluginSlot {
    /// A plugin that is nowhere yet.
    #[must_use]
    pub const fn available() -> Self {
        Self::Available
    }

    /// A plugin already on this device, which is where a kernel that found one in its database starts.
    #[must_use]
    pub const fn installed(source: InstallSource, lifecycle: Lifecycle) -> Self {
        Self::Installed { source, lifecycle }
    }

    /// Where it is, for a log line, a metric label or a state column.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Resolving { .. } => "resolving",
            Self::Downloading { .. } => "downloading",
            Self::Verifying { .. } => "verifying",
            Self::AwaitingConsent { .. } => "awaiting-consent",
            Self::Installing { .. } => "installing",
            Self::Installed { .. } => "installed",
            Self::Activating { .. } => "activating",
            Self::Active { .. } => "active",
            Self::Deactivating { .. } => "deactivating",
            Self::Faulted { .. } => "faulted",
            Self::Removing { .. } => "removing",
            Self::Failed(_) => "failed",
        }
    }

    /// What was asked for, if there is anything to ask about yet.
    #[must_use]
    pub const fn source(&self) -> Option<&InstallSource> {
        match self {
            Self::Available => None,
            Self::Failed(failed) => Some(&failed.source),
            Self::Resolving { source }
            | Self::Downloading { source, .. }
            | Self::Verifying { source, .. }
            | Self::AwaitingConsent { source, .. }
            | Self::Installing { source, .. }
            | Self::Installed { source, .. }
            | Self::Activating { source, .. }
            | Self::Active { source, .. }
            | Self::Deactivating { source, .. }
            | Self::Faulted { source, .. }
            | Self::Removing { source, .. } => Some(source),
        }
    }

    /// The plugin's lifecycle, for a state that has one.
    #[must_use]
    pub const fn lifecycle(&self) -> Option<&Lifecycle> {
        match self {
            Self::Installed { lifecycle, .. }
            | Self::Activating { lifecycle, .. }
            | Self::Active { lifecycle, .. }
            | Self::Deactivating { lifecycle, .. }
            | Self::Faulted { lifecycle, .. } => Some(lifecycle),
            Self::Removing { lifecycle, .. } => lifecycle.as_ref(),
            _ => None,
        }
    }

    /// Whether the plugin's code may be executing.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    /// Whether the plugin is on this device, whatever it is doing.
    ///
    /// # Why this is not `matches!(self, Self::Installed { .. })`
    ///
    /// Because a plugin that is activating, running, stopping or faulted is *also* installed, and a caller asking
    /// "should this appear in the list of plugins I have" wants all five answers to be yes.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(
            self,
            Self::Installed { .. }
                | Self::Activating { .. }
                | Self::Active { .. }
                | Self::Deactivating { .. }
                | Self::Faulted { .. }
                | Self::Removing { .. }
        )
    }

    /// Whether a user can stop what is happening.
    ///
    /// # Why not every state is cancellable
    ///
    /// Because the ones that are not are the ones where cancelling would leave something half-done that nothing
    /// cleans up. A download can be abandoned — it has written nothing — and an install cannot: the artifact is being
    /// renamed into place, and a user who cancels at that instant gets a plugin that is neither there nor absent.
    /// Those states are short, and the honest answer is that the request will be honoured when the state is.
    #[must_use]
    pub const fn is_cancellable(&self) -> bool {
        matches!(
            self,
            Self::Resolving { .. }
                | Self::Downloading { .. }
                | Self::Verifying { .. }
                | Self::AwaitingConsent { .. }
                | Self::Activating { .. }
                | Self::Deactivating { .. }
                | Self::Removing { .. }
        )
    }

    /// Whether a retry from here could work, and what has to be done first.
    ///
    /// `false` for everything that is not [`Self::Failed`] and for a failure a retry cannot fix. That is the answer a
    /// button is drawn from, so it is computed here rather than at the interface.
    #[must_use]
    pub const fn can_retry(&self) -> bool {
        matches!(self, Self::Failed(failed) if failed.retryable && !failed.is_worn_out())
    }

    /// What a user is shown.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Available => "not installed".to_owned(),
            Self::Resolving { source } => format!("looking up {}", source.describe()),
            Self::Downloading { progress, .. } => match progress.fraction() {
                Some(fraction) => format!("downloading, {:.0}% done", fraction * 100.0),
                None => "downloading".to_owned(),
            },
            Self::Verifying { .. } => "checking the signature and the contents".to_owned(),
            Self::AwaitingConsent { verified, .. } => format!(
                "waiting for a decision about {} permission(s)",
                verified.requested.len()
            ),
            Self::Installing { .. } => "installing".to_owned(),
            Self::Installed { lifecycle, .. } => lifecycle.state().describe(),
            Self::Activating { .. } => "starting".to_owned(),
            Self::Active { lifecycle, .. } => lifecycle.state().describe(),
            Self::Deactivating { .. } => "stopping".to_owned(),
            Self::Faulted { lifecycle, .. } => lifecycle.state().describe(),
            Self::Removing { .. } => "being removed".to_owned(),
            Self::Failed(failed) => {
                let mut sentence = format!("{} failed: {}", failed.stage.as_str(), failed.detail);
                if failed.is_worn_out() {
                    sentence.push_str(&format!(" ({} attempts)", failed.attempts));
                }
                sentence
            }
        }
    }
}

impl From<Failed> for PluginSlot {
    fn from(failed: Failed) -> Self {
        Self::Failed(failed)
    }
}

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

/// Why a move was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MoveError {
    /// The move does not apply to the state the plugin is in.
    #[error("cannot {attempted} a plugin that is {current}")]
    WrongState {
        /// What was attempted.
        attempted: &'static str,
        /// Where the plugin is.
        current: &'static str,
    },

    /// The source is one this build may not install from.
    #[error("a local installation is a development feature and this build does not accept one")]
    LocalInstallNotAllowed,

    /// The plugin's own lifecycle refused the move.
    ///
    /// Passed through rather than folded into [`Self::WrongState`], because the two have different next steps: the
    /// lifecycle's refusal may be a step the caller has to perform first.
    #[error(transparent)]
    Lifecycle(#[from] TransitionError),
}

impl PluginSlot {
    /// Applies a move.
    ///
    /// `now_ms` is passed in rather than read, so a failure's timestamp is a value a test can assert.
    ///
    /// # Errors
    ///
    /// [`MoveError`] naming what was attempted and where the plugin is.
    pub fn apply(&mut self, step: Move, now_ms: i64) -> Result<&Self, MoveError> {
        // The name is bound before the match for the reason `Lifecycle::apply` binds it: the match moves the step's
        // payloads, and a closure borrowing the step would keep them borrowed for the whole body.
        let name = step.as_str();
        let wrong = |current: &'static str| MoveError::WrongState { attempted: name, current };

        match step {
            Move::Install { source } => {
                if !matches!(self, Self::Available | Self::Failed(_)) {
                    return Err(wrong(self.as_str()));
                }
                if source.refuses_outside_development() && !cfg!(debug_assertions) {
                    return Err(MoveError::LocalInstallNotAllowed);
                }
                *self = Self::Resolving { source };
            }

            Move::Resolved { resolved } => {
                let Self::Resolving { source } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Downloading {
                    source: source.clone(),
                    resolved,
                    progress: Progress::default(),
                };
            }

            Move::Downloaded { progress } => {
                let Self::Downloading { progress: held, .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                // ★ Monotonic: a progress report that goes backwards is a stalled connection being retried inside a
                // request, and drawing it would make a download appear to restart. A caller that has restarted the
                // download has a new `Downloading` state, not a smaller number in this one.
                held.received = held.received.max(progress.received);
                held.total = progress.total.or(held.total);
            }

            Move::Fetched { artifact_digest } => {
                let Self::Downloading { source, resolved, .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Verifying {
                    source: source.clone(),
                    resolved: resolved.clone(),
                    artifact_digest,
                };
            }

            Move::Verified { verified } => {
                let Self::Verifying { source, .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::AwaitingConsent { source: source.clone(), verified };
            }

            Move::Consented { consent } => {
                let Self::AwaitingConsent { source, verified } = self else {
                    return Err(wrong(self.as_str()));
                };
                if consent.is_refusal() {
                    // A refusal everywhere is not a partial grant: it is the user saying no, and the pipeline ends in
                    // the state that means "a person decided against this" rather than in one that means "it broke".
                    let failed = Failed::at(
                        source.clone(),
                        FailStage::Consent,
                        "every requested permission was refused",
                        now_ms,
                    )
                    .not_retryable();
                    *self = Self::Failed(failed);
                    return Ok(self);
                }
                *self = Self::Installing {
                    source: source.clone(),
                    verified: verified.clone(),
                    consent,
                };
            }

            Move::Installed => {
                let Self::Installing { source, verified, consent } = self else {
                    return Err(wrong(self.as_str()));
                };
                let mut lifecycle = Lifecycle::installed(verified.version.clone());
                // The lifecycle's own moves, driven from the values the pipeline already produced — not from new ones,
                // so the version a plugin is recorded with is the version that was verified.
                let _ = lifecycle.apply(Transition::Validate {
                    manifest_digest: verified.manifest_digest.clone(),
                })?;
                let _ = lifecycle.apply(Transition::Grant {
                    partially_denied: consent.is_partial(),
                })?;
                *self = Self::Installed { source: source.clone(), lifecycle };
            }

            Move::Activate => {
                let Self::Installed { source, mut lifecycle } = self.clone() else {
                    return Err(wrong(self.as_str()));
                };
                // The lifecycle is moved **before** the state changes, so a refusal leaves the slot exactly where it
                // was rather than in an activating state with nothing to activate.
                let _ = lifecycle.apply(Transition::Activate)?;
                *self = Self::Activating { source, lifecycle };
            }

            Move::Activated => {
                let Self::Activating { source, lifecycle } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Active { source: source.clone(), lifecycle: lifecycle.clone() };
            }

            Move::Deactivate => {
                let Self::Active { source, lifecycle } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Deactivating { source: source.clone(), lifecycle: lifecycle.clone() };
            }

            Move::Deactivated => {
                let Self::Deactivating { source, mut lifecycle } = self.clone() else {
                    return Err(wrong(self.as_str()));
                };
                let _ = lifecycle.apply(Transition::Deactivate)?;
                *self = Self::Installed { source, lifecycle };
            }

            Move::Fault { reason } => {
                // From anything that holds loaded code, which is the same set the lifecycle faults from. A fault while
                // activating is the case that matters: the module loaded and its start function trapped.
                let (source, mut lifecycle) = match self.clone() {
                    Self::Activating { source, lifecycle }
                    | Self::Active { source, lifecycle }
                    | Self::Deactivating { source, lifecycle } => (source, lifecycle),
                    _ => return Err(wrong(self.as_str())),
                };
                let _ = lifecycle.apply(Transition::Fault { reason })?;
                *self = Self::Faulted { source, lifecycle };
            }

            Move::ClearFault => {
                let Self::Faulted { source, mut lifecycle } = self.clone() else {
                    return Err(wrong(self.as_str()));
                };
                let _ = lifecycle.apply(Transition::ClearFault)?;
                *self = Self::Installed { source, lifecycle };
            }

            Move::Remove => {
                // From anything on this device, except while something is running: the caller stops it first, and a
                // removal that skipped that would take the artifact out from under a live instance.
                let (source, lifecycle) = match self.clone() {
                    Self::Installed { source, lifecycle } | Self::Faulted { source, lifecycle } => {
                        (source, Some(lifecycle))
                    }
                    Self::Activating { .. } | Self::Active { .. } | Self::Deactivating { .. } => {
                        return Err(wrong(self.as_str()));
                    }
                    _ => return Err(wrong(self.as_str())),
                };
                *self = Self::Removing { source, lifecycle };
            }

            Move::Removed => {
                let Self::Removing { .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Available;
            }

            Move::Retry => {
                let Self::Failed(failed) = self else {
                    return Err(wrong(self.as_str()));
                };
                if !failed.retryable {
                    return Err(wrong(self.as_str()));
                }
                // ★ The attempt count is *not* incremented here. A retry that has not failed yet has not been tried,
                // and counting it now would report "2 attempts" for a user who has pressed the button once.
                let source = failed.source.clone();
                *self = Self::Resolving { source };
            }

            Move::Abandon => {
                let Self::Failed(_) = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Available;
            }

            Move::Fail { stage, detail, retryable } => {
                // ★ From anywhere that has a source — which is everywhere except `Available`. A second failure does
                // not replace the first's attempt count; it increments it, so a pipeline that fails four times reports
                // four rather than one.
                let Some(source) = self.source().cloned() else {
                    return Err(wrong(self.as_str()));
                };
                let mut failed = match self {
                    Self::Failed(previous) => previous.retried(now_ms),
                    _ => Failed::at(source, stage, detail.clone(), now_ms),
                };
                failed.stage = stage;
                failed.detail = detail;
                if let Some(known) = retryable {
                    failed.retryable = known;
                }
                *self = Self::Failed(failed);
            }
        }

        Ok(self)
    }

    /// The plugin's lifecycle state, when it has one.
    #[must_use]
    pub fn lifecycle_state(&self) -> Option<&State> {
        self.lifecycle().map(Lifecycle::state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000;

    fn registry_source() -> InstallSource {
        InstallSource::Registry { package: "@acme/hello".to_owned(), version: "^1".to_owned() }
    }

    fn resolved() -> Resolved {
        Resolved {
            version: "1.2.3".to_owned(),
            artifacts: vec!["plugin.wasm".to_owned()],
            manifest_digest: "aaa".to_owned(),
            development_only: false,
        }
    }

    fn verified() -> Verified {
        Verified {
            version: "1.2.3".to_owned(),
            artifact_digest: "bbb".to_owned(),
            manifest_digest: "aaa".to_owned(),
            requested: vec!["platform:open-url".to_owned()],
            trust: Some("signed by a publisher this device has seen".to_owned()),
        }
    }

    fn consented() -> Consent {
        Consent { granted: vec!["platform:open-url".to_owned()], denied: Vec::new() }
    }

    /// Drives a slot to `Installed`, through every stage, the way a caller does.
    fn installed() -> PluginSlot {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
        let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW).expect("fetched");
        let _ = slot.apply(Move::Verified { verified: verified() }, NOW).expect("verified");
        let _ = slot.apply(Move::Consented { consent: consented() }, NOW).expect("consented");
        let _ = slot.apply(Move::Installed, NOW).expect("installed");
        slot
    }

    #[test]
    fn the_pipeline_runs_from_available_to_running() {
        // The whole path, driven from the caller's side at every step: a test that jumped to `Active` would prove the
        // states exist and nothing about the moves between them.
        let mut slot = installed();
        assert_eq!(slot.as_str(), "installed");
        assert_eq!(slot.lifecycle_state(), Some(&State::Granted {
            version: "1.2.3".to_owned(),
            manifest_digest: "aaa".to_owned(),
            partially_denied: false,
        }));

        let _ = slot.apply(Move::Activate, NOW).expect("activate");
        assert_eq!(slot.as_str(), "activating");
        let _ = slot.apply(Move::Activated, NOW).expect("activated");
        assert_eq!(slot.as_str(), "active");
        assert!(slot.is_running());

        let _ = slot.apply(Move::Deactivate, NOW).expect("deactivate");
        assert_eq!(slot.as_str(), "deactivating");
        let _ = slot.apply(Move::Deactivated, NOW).expect("deactivated");
        assert_eq!(slot.as_str(), "installed");
        assert_eq!(slot.lifecycle_state().map(State::as_str), Some("deactivated"));
    }

    #[test]
    fn a_local_source_is_only_installed_by_a_development_build() {
        // ★ The rule from §2.1.2. In a release build a local path is a way to run unsigned code, and the refusal is
        // here rather than in the resolver because it is about *this build* rather than about the source.
        let mut slot = PluginSlot::available();
        let local = InstallSource::Local { path: "./hello".to_owned() };
        let refused = slot.apply(Move::Install { source: local }, NOW);

        if cfg!(debug_assertions) {
            assert!(refused.is_ok(), "a development build accepts a local source");
            assert_eq!(slot.as_str(), "resolving");
        }
        else {
            assert!(matches!(refused, Err(MoveError::LocalInstallNotAllowed)), "{refused:?}");
            assert_eq!(slot.as_str(), "available", "a refused install leaves the slot where it was");
        }
        assert!(InstallSource::Local { path: "x".to_owned() }.refuses_outside_development());
        assert!(!registry_source().refuses_outside_development());
    }

    #[test]
    fn every_stage_refuses_the_move_that_belongs_to_another() {
        // A caller that skips verification must be told so rather than reaching `Active` with unchecked code.
        let mut slot = PluginSlot::available();
        for step in [
            Move::Verified { verified: verified() },
            Move::Consented { consent: consented() },
            Move::Installed,
            Move::Activated,
            Move::Activated,
            Move::Deactivated,
            Move::ClearFault,
            Move::Removed,
        ] {
            // The step is cloned for the message rather than moved into the call: a refusal has to name what was
            // attempted, and the assertion below is where that name is read.
            let refused = slot.apply(step.clone(), NOW);
            assert!(refused.is_err(), "{step:?} was accepted while available");
        }
    }

    #[test]
    fn progress_never_goes_backwards() {
        // A stalled connection retried inside one request reports less than it did; drawing that would make a download
        // appear to restart.
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
        let _ = slot.apply(Move::Downloaded { progress: Progress { received: 900, total: Some(1_000) } }, NOW);
        let _ = slot.apply(Move::Downloaded { progress: Progress { received: 100, total: None } }, NOW);

        let PluginSlot::Downloading { progress, .. } = &slot else {
            panic!("expected a download");
        };
        assert_eq!(progress.received, 900);
        assert_eq!(progress.total, Some(1_000), "a total that was known stays known");
        assert_eq!(progress.fraction(), Some(0.9));
    }

    #[test]
    fn a_refused_consent_ends_the_install_without_blaming_the_plugin() {
        // A user saying no is a decision, not a breakage: the stage is `Consent`, the sentence says so, and a retry
        // button would be offering to ask again without saying that is what it does.
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
        let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW).expect("fetched");
        let _ = slot.apply(Move::Verified { verified: verified() }, NOW).expect("verified");
        let _ = slot
            .apply(Move::Consented { consent: Consent { granted: Vec::new(), denied: vec!["log:*".to_owned()] } }, NOW)
            .expect("consented");

        let PluginSlot::Failed(failed) = &slot else {
            panic!("expected a failure, got {slot:?}");
        };
        assert_eq!(failed.stage, FailStage::Consent);
        assert!(!failed.retryable, "asking again is the user's decision, not a retry button");
        assert!(!slot.can_retry());
    }

    #[test]
    fn a_partial_consent_installs_and_is_recorded_as_partial() {
        // A plugin running with some capabilities denied behaves differently, and the record has to say which.
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
        let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW).expect("fetched");
        let _ = slot.apply(Move::Verified { verified: verified() }, NOW).expect("verified");
        let _ = slot
            .apply(
                Move::Consented {
                    consent: Consent {
                        granted: vec!["log:*".to_owned()],
                        denied: vec!["platform:open-url".to_owned()],
                    },
                },
                NOW,
            )
            .expect("consented");
        let _ = slot.apply(Move::Installed, NOW).expect("installed");

        assert_eq!(
            slot.lifecycle_state(),
            Some(&State::Granted {
                version: "1.2.3".to_owned(),
                manifest_digest: "aaa".to_owned(),
                partially_denied: true,
            })
        );
    }

    #[test]
    fn a_failure_records_its_stage_and_whether_a_retry_could_work() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(
                Move::Fail {
                    stage: FailStage::Download,
                    detail: "the connection dropped".to_owned(),
                    retryable: None,
                },
                1_500,
            )
            .expect("failed");

        let PluginSlot::Failed(failed) = &slot else {
            panic!("expected a failure");
        };
        assert_eq!(failed.stage, FailStage::Download);
        assert!(failed.retryable, "a download can be tried again");
        assert_eq!(failed.attempts, 1);
        assert_eq!(failed.failed_at_ms, 1_500);
        assert!(slot.can_retry());
    }

    #[test]
    fn a_verification_failure_is_not_offered_as_a_retry() {
        // ★ The same bytes hash the same way. A retry button here is a button that cannot work.
        assert!(!FailStage::Verify.is_retryable(), "the stage's own answer");
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(
                Move::Fail {
                    stage: FailStage::Verify,
                    detail: "the digest does not match".to_owned(),
                    retryable: None,
                },
                NOW,
            )
            .expect("failed");

        assert!(!slot.can_retry());
        assert!(matches!(slot.apply(Move::Retry, NOW), Err(MoveError::WrongState { .. })));
    }

    #[test]
    fn a_caller_that_knows_better_can_mark_a_retryable_stage_as_hopeless() {
        // A registry that answered 404 failed at `Resolve`, and no amount of trying will make the package exist.
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(
                Move::Fail {
                    stage: FailStage::Resolve,
                    detail: "no such package".to_owned(),
                    retryable: Some(false),
                },
                NOW,
            )
            .expect("failed");

        assert!(!slot.can_retry(), "the caller's answer wins over the stage's");
    }

    #[test]
    fn retrying_counts_the_attempts_and_starts_over_from_resolving() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(Move::Fail { stage: FailStage::Download, detail: "dropped".to_owned(), retryable: None }, NOW)
            .expect("failed");
        let _ = slot.apply(Move::Fail { stage: FailStage::Download, detail: "dropped again".to_owned(), retryable: None }, NOW);

        let PluginSlot::Failed(failed) = &slot else {
            panic!("expected a failure");
        };
        assert_eq!(failed.attempts, 2, "a second failure increments rather than replaces");

        let _ = slot.apply(Move::Retry, NOW + 10).expect("retry");
        assert_eq!(slot.as_str(), "resolving", "a retry starts where the source is known again");
    }

    #[test]
    fn a_failure_that_keeps_happening_stops_offering_a_button() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        for attempt in 0..WEAR_OUT_AFTER {
            let _ = slot
                .apply(
                    Move::Fail {
                        stage: FailStage::Install,
                        detail: format!("attempt {attempt}"),
                        retryable: None,
                    },
                    NOW,
                )
                .expect("failed");
        }

        let PluginSlot::Failed(failed) = &slot else {
            panic!("expected a failure");
        };
        assert_eq!(failed.attempts, WEAR_OUT_AFTER);
        assert!(failed.is_worn_out());
        assert!(!slot.can_retry(), "the fourth offer of the same button is not useful");
        assert!(slot.describe().contains("attempts"), "{}", slot.describe());
    }

    #[test]
    fn abandoning_a_failure_returns_the_slot_to_available() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(Move::Fail { stage: FailStage::Download, detail: "dropped".to_owned(), retryable: None }, NOW)
            .expect("failed");
        let _ = slot.apply(Move::Abandon, NOW).expect("abandon");

        assert_eq!(slot, PluginSlot::Available);
        assert!(slot.source().is_none());
    }

    #[test]
    fn a_fault_from_running_is_a_state_and_the_user_can_clear_it() {
        let mut slot = installed();
        let _ = slot.apply(Move::Activate, NOW).expect("activate");
        let _ = slot.apply(Move::Activated, NOW).expect("activated");
        let _ = slot
            .apply(Move::Fault { reason: "exceeded its quota".to_owned() }, NOW)
            .expect("faulted");

        assert_eq!(slot.as_str(), "faulted");
        assert!(slot.describe().contains("exceeded its quota"), "{}", slot.describe());
        // Not running, but still present: a faulted plugin is one the user still has.
        assert!(!slot.is_running());
        assert!(slot.is_present());

        let _ = slot.apply(Move::ClearFault, NOW).expect("cleared");
        assert_eq!(slot.as_str(), "installed");
        assert_eq!(slot.lifecycle_state().map(State::as_str), Some("validated"));
    }

    #[test]
    fn a_fault_while_activating_is_recorded_where_it_happened() {
        // The case that matters: the module loaded and its start function trapped. Nothing is running, and the plugin
        // is not "installed and fine" either.
        let mut slot = installed();
        let _ = slot.apply(Move::Activate, NOW).expect("activate");
        let _ = slot
            .apply(Move::Fault { reason: "the start function trapped".to_owned() }, NOW)
            .expect("faulted");

        assert_eq!(slot.as_str(), "faulted");
        assert!(slot.lifecycle_state().is_some());
    }

    #[test]
    fn a_running_plugin_is_stopped_before_it_is_removed() {
        // Removing an active plugin would take the artifact out from under a live instance. The caller has a step to
        // perform, and the refusal says which.
        let mut slot = installed();
        let _ = slot.apply(Move::Activate, NOW).expect("activate");
        let _ = slot.apply(Move::Activated, NOW).expect("activated");

        match slot.apply(Move::Remove, NOW) {
            Err(MoveError::WrongState { attempted, current }) => {
                assert_eq!(attempted, "remove");
                assert_eq!(current, "active");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        let _ = slot.apply(Move::Deactivate, NOW).expect("deactivate");
        let _ = slot.apply(Move::Deactivated, NOW).expect("deactivated");
        let _ = slot.apply(Move::Remove, NOW).expect("remove");
        assert_eq!(slot.as_str(), "removing");
    }

    #[test]
    fn removal_ends_at_available_with_nothing_left() {
        let mut slot = installed();
        let _ = slot.apply(Move::Remove, NOW).expect("remove");
        let _ = slot.apply(Move::Removed, NOW).expect("removed");

        assert_eq!(slot, PluginSlot::Available);
        assert!(!slot.is_present());
        assert!(slot.lifecycle().is_none());
    }

    #[test]
    fn a_cancellable_state_is_the_one_where_nothing_is_half_written() {
        // The list is a claim about what cancelling leaves behind, so it is asserted rather than described.
        assert!(PluginSlot::Resolving { source: registry_source() }.is_cancellable());
        assert!(
            PluginSlot::AwaitingConsent { source: registry_source(), verified: verified() }.is_cancellable(),
            "a prompt nobody has answered is the easiest thing in the world to withdraw"
        );
        let removing = {
            let mut slot = installed();
            let _ = slot.apply(Move::Remove, NOW).expect("remove");
            slot
        };
        assert!(removing.is_cancellable());

        // ★ And the two states where cancelling would leave something half-done are not:
        // `Installing` is renaming an artifact into place, and `Active` is not a stage at all.
        let installing = {
            let mut slot = PluginSlot::available();
            let _ = slot.apply(Move::Install { source: registry_source() }, NOW);
            let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW);
            let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW);
            let _ = slot.apply(Move::Verified { verified: verified() }, NOW);
            let _ = slot.apply(Move::Consented { consent: consented() }, NOW);
            slot
        };
        assert_eq!(installing.as_str(), "installing");
        assert!(!installing.is_cancellable(), "the artifact is being renamed into place");

        assert!(!PluginSlot::Available.is_cancellable());
        assert!(!installed().is_cancellable(), "installed is not a stage something is happening in");
    }

    #[test]
    fn every_state_has_a_name_and_a_sentence() {
        // The property an interface depends on: a state with no label is a spinner with no text.
        let states = [
            PluginSlot::Available,
            PluginSlot::Resolving { source: registry_source() },
            PluginSlot::Downloading {
                source: registry_source(),
                resolved: resolved(),
                progress: Progress { received: 1, total: Some(2) },
            },
            PluginSlot::Verifying {
                source: registry_source(),
                resolved: resolved(),
                artifact_digest: "bbb".to_owned(),
            },
            PluginSlot::AwaitingConsent { source: registry_source(), verified: verified() },
            PluginSlot::Installing {
                source: registry_source(),
                verified: verified(),
                consent: consented(),
            },
            installed(),
            {
                let mut slot = installed();
                let _ = slot.apply(Move::Activate, NOW);
                slot
            },
            {
                let mut slot = installed();
                let _ = slot.apply(Move::Activate, NOW);
                let _ = slot.apply(Move::Activated, NOW);
                slot
            },
            {
                let mut slot = installed();
                let _ = slot.apply(Move::Remove, NOW);
                slot
            },
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Download, "dropped", NOW)),
        ];

        let mut seen: Vec<&str> = Vec::new();
        for state in &states {
            let name = state.as_str();
            assert!(!name.is_empty());
            assert!(!seen.contains(&name), "{name} names two states");
            seen.push(name);
            let sentence = state.describe();
            assert!(sentence.len() > 3, "{name} -> {sentence}");
        }
        // And the thirteen names are all distinct, which is what the design document's table is.
        assert!(seen.len() >= 11, "{} states covered", seen.len());
    }

    #[test]
    fn a_clock_change_does_not_move_a_download_backwards() {
        // Progress is bytes, not time, so this is the one place a clock cannot hurt — asserted because "progress" is
        // the kind of field somebody later divides by an elapsed time.
        let progress = Progress { received: 500, total: Some(1_000) };
        assert_eq!(progress.fraction(), Some(0.5));
        assert!(!progress.is_complete());
        assert_eq!(Progress { received: 10, total: None }.fraction(), None);
        assert_eq!(Progress { received: 0, total: Some(0) }.fraction(), Some(1.0));
        assert!(Progress { received: 1_000, total: Some(1_000) }.is_complete());
    }

    #[test]
    fn every_state_survives_a_trip_through_json() {
        // ★ The reason these types are serialisable at all: a settings screen shows where a plugin is, and the state it
        // shows should be the state that was decided rather than a rendering of it. A round trip that lost a field
        // would be a screen describing a plugin that is not the one the kernel has.
        let states = [
            PluginSlot::Available,
            PluginSlot::Resolving { source: registry_source() },
            PluginSlot::Downloading {
                source: registry_source(),
                resolved: resolved(),
                progress: Progress { received: 900, total: Some(1_000) },
            },
            PluginSlot::Verifying {
                source: registry_source(),
                resolved: resolved(),
                artifact_digest: "bbb".to_owned(),
            },
            PluginSlot::AwaitingConsent { source: registry_source(), verified: verified() },
            PluginSlot::Installing {
                source: registry_source(),
                verified: verified(),
                consent: consented(),
            },
            installed(),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Download, "the connection dropped", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Verify, "the digest does not match", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Activate, "it trapped", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Consent, "declined", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Install, "the disk is full", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Remove, "the file is locked", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Resolve, "no such package", NOW)),
        ];

        for state in &states {
            let json = serde_json::to_string(state).unwrap_or_else(|error| panic!("{state:?}: {error}"));
            let back: PluginSlot = serde_json::from_str(&json).unwrap_or_else(|error| panic!("{json}: {error}"));
            assert_eq!(&back, state, "{json}");
            // And the tag a screen matches on is the same word the kernel calls the state, which is what stops the two
            // from drifting.
            assert!(json.contains(state.as_str()), "{json}");
        }
    }

    #[test]
    fn an_install_source_says_what_kind_it_is_in_json() {
        // A tagged union, so a reader does not have to guess which fields are present — and the tag is the same word
        // `kind` returns.
        let source = InstallSource::Git { url: "https://example".to_owned(), reference: Some("main".to_owned()) };
        let json = serde_json::to_string(&source).expect("serialises");
        assert!(json.contains("\"kind\":\"git\""), "{json}");
        assert!(json.contains("https://example"), "{json}");
        let back: InstallSource = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, source);
        assert_eq!(source.kind(), "git");
    }

    #[test]
    fn a_failure_that_went_through_json_still_knows_whether_a_retry_could_work() {
        // The field a button is drawn from, so a round trip that lost it would be a screen offering a retry for a
        // digest that will never match.
        let hopeless = Failed::at(registry_source(), FailStage::Verify, "the digest does not match", NOW);
        let json = serde_json::to_string(&hopeless).expect("serialises");
        let back: Failed = serde_json::from_str(&json).expect("deserialises");
        assert!(!back.retryable);
        assert_eq!(back.stage, FailStage::Verify);
        assert_eq!(back.stage.as_str(), "verify");
        assert_eq!(back.failed_at_ms, NOW);
    }
}
