use super::*;
use synra_plugin_api::manifest::{check_version, compare_versions};

/// What to do about what the other device has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConflictPolicy {
    /// Keep both devices' versions as they are.
    ///
    /// **The default.** An automatic downgrade can put a device back on a version with a known vulnerability, and a
    /// user's objection to having their software rolled back remotely is not a preference to be configured away.
    NeverDowngrade,
    /// What the sending device has wins, whatever it is.
    ///
    /// Available because a user *can* mean it — a device being brought in line deliberately — and never the default.
    SourceWins,
    /// Whichever version is newer wins.
    KeepNewest,
    /// Do not reconcile: each device keeps what it has, and a sync does nothing.
    Independent,
    /// Ask the user.
    Ask,
}

impl ConflictPolicy {
    /// A name, for a log line and a setting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverDowngrade => "never-downgrade",
            Self::SourceWins => "source-wins",
            Self::KeepNewest => "keep-newest",
            Self::Independent => "independent",
            Self::Ask => "ask",
        }
    }
}

/// What a sync should do next.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncAction {
    /// Send the package.
    Push {
        /// Why, in a sentence a log line can carry.
        why: String,
    },
    /// Nothing to do.
    Skip {
        /// Why.
        why: String,
    },
    /// The user has to decide.
    Ask {
        /// What they are deciding between.
        ours: String,
        /// The other device's version, when it has one.
        theirs: Option<String>,
    },
    /// Refused, and the sender should not try again unasked.
    Refuse {
        /// Why.
        why: String,
    },
}

impl SyncAction {
    /// Whether this ends the sync with the package sent.
    #[must_use]
    pub const fn is_push(&self) -> bool {
        matches!(self, Self::Push { .. })
    }

    /// A name, for a metric label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Push { .. } => "push",
            Self::Skip { .. } => "skip",
            Self::Ask { .. } => "ask",
            Self::Refuse { .. } => "refuse",
        }
    }
}

/// Compares what this device has with what the other one said.
///
/// # The order the comparisons happen in
///
/// The **digest** first, because it is the answer to "do they already have this artifact" — two devices may hold the
/// same version string with different bytes, and comparing versions alone would call that synced. Then the version,
/// which is what the conflict policies are about.
#[must_use]
pub fn decide(
    ours_version: &str,
    ours_digest: &str,
    theirs: &RemoteState,
    policy: ConflictPolicy,
) -> SyncAction {
    let Some(theirs_version) = theirs.version.as_deref() else {
        if let Err(error) = check_version(ours_version) {
            return SyncAction::Refuse {
                why: error.to_string(),
            };
        }
        return SyncAction::Push {
            why: "the other device does not have this plugin".to_owned(),
        };
    };

    // ★ Same bytes is the same plugin, whatever the version strings say. A rebuilt artifact with an unchanged version
    // is the case this catches, and a sender that pushed it again would waste a transfer and change nothing.
    if theirs.digest.as_deref() == Some(ours_digest) {
        return SyncAction::Skip {
            why: "the other device already has these exact bytes".to_owned(),
        };
    }

    match policy {
        ConflictPolicy::Independent => SyncAction::Skip {
            why: "this device is configured to keep its plugins independent".to_owned(),
        },
        ConflictPolicy::SourceWins => SyncAction::Push {
            why: "this device's version wins by policy".to_owned(),
        },
        ConflictPolicy::Ask => SyncAction::Ask {
            ours: ours_version.to_owned(),
            theirs: Some(theirs_version.to_owned()),
        },
        ConflictPolicy::NeverDowngrade | ConflictPolicy::KeepNewest => {
            decide_by_precedence(ours_version, theirs_version, policy)
        }
    }
}

fn decide_by_precedence(ours: &str, theirs: &str, policy: ConflictPolicy) -> SyncAction {
    use core::cmp::Ordering;
    match compare_versions(ours, theirs) {
        Err(error) => SyncAction::Refuse {
            why: error.to_string(),
        },
        Ok(Ordering::Greater) => SyncAction::Push {
            why: format!("{ours} is newer than {theirs}"),
        },
        Ok(Ordering::Equal) if policy == ConflictPolicy::NeverDowngrade => SyncAction::Push {
            why: format!("{ours} and {theirs} have the same precedence and different bytes"),
        },
        Ok(Ordering::Less) if policy == ConflictPolicy::NeverDowngrade => SyncAction::Skip {
            why: format!(
                "the other device is on {theirs} and this device has {ours}, which is older"
            ),
        },
        Ok(_) => SyncAction::Skip {
            why: format!("{theirs} is at least as new as {ours}"),
        },
    }
}

/// What the receiving device is obliged to do, and whether it did.
///
/// # Why this is a value with a state
///
/// Because the list in the design document is a list of things that must **not** be skipped, and a list in a document
/// is a list somebody skips. Making each obligation a step that is either done or not makes "did this device re-verify
/// a package it received" a question with an answer rather than a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ReceiverDuty {
    /// The whole package's digest, before anything is unpacked.
    PackageDigest,
    /// The signature, by the same pipeline an install goes through.
    Signature,
    /// The manifest and the capabilities.
    Manifest,
    /// The archive limits: size, entries, depth, traversal, links.
    ArchiveLimits,
    /// Every chunk arrived, session-level, before "complete" means anything.
    SessionComplete,
    /// Whether to enable it, decided here rather than by the sender.
    LocalActivation,
    /// The grants stay this device's, and a sync does not overwrite them.
    LocalGrants,
}

impl ReceiverDuty {
    /// Every obligation, in the order they are performed.
    pub const ALL: &'static [Self] = &[
        Self::PackageDigest,
        Self::Signature,
        Self::Manifest,
        Self::ArchiveLimits,
        Self::SessionComplete,
        Self::LocalActivation,
        Self::LocalGrants,
    ];

    /// A name, for a report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PackageDigest => "package-digest",
            Self::Signature => "signature",
            Self::Manifest => "manifest",
            Self::ArchiveLimits => "archive-limits",
            Self::SessionComplete => "session-complete",
            Self::LocalActivation => "local-activation",
            Self::LocalGrants => "local-grants",
        }
    }
}
