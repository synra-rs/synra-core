use serde::{Deserialize, Serialize};

use super::data::{Consent, Progress, Resolved, Verified};
use super::source::{Failed, InstallSource};

use super::super::machine::Lifecycle;

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
