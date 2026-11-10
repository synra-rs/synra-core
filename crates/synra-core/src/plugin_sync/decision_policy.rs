use super::*;

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
        ConflictPolicy::NeverDowngrade => {
            if compare_versions(ours_version, theirs_version).is_lt() {
                // ★ The rule the default exists for: the other device has something newer, and sending this one would
                // take it backwards.
                SyncAction::Skip {
                    why: format!(
                        "the other device is on {theirs_version} and this device has {ours_version}, which is older"
                    ),
                }
            } else {
                SyncAction::Push {
                    why: format!("{ours_version} is not older than {theirs_version}"),
                }
            }
        }
        ConflictPolicy::KeepNewest => {
            if compare_versions(ours_version, theirs_version).is_gt() {
                SyncAction::Push {
                    why: format!("{ours_version} is newer than {theirs_version}"),
                }
            } else {
                SyncAction::Skip {
                    why: format!("{theirs_version} is at least as new as {ours_version}"),
                }
            }
        }
    }
}

/// Compares two version strings by their numeric parts.
///
/// The same shape the registry's comparison has, and for the same reason: the one semantic rule that matters for
/// picking between two versions is that a release is newer than its own pre-releases, and plain string ordering gets
/// `1.10.0` and `1.9.0` backwards.
#[must_use]
pub fn compare_versions(first: &str, second: &str) -> core::cmp::Ordering {
    let parts = |version: &str| -> (Vec<u64>, bool) {
        let (core, pre) = version
            .split_once('-')
            .map_or((version, ""), |(core, pre)| (core, pre));
        let numbers = core
            .split(['.', '+'])
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect();
        (numbers, !pre.is_empty())
    };
    let (left, left_pre) = parts(first);
    let (right, right_pre) = parts(second);
    match left.cmp(&right) {
        core::cmp::Ordering::Equal => match (left_pre, right_pre) {
            (true, false) => core::cmp::Ordering::Less,
            (false, true) => core::cmp::Ordering::Greater,
            _ => core::cmp::Ordering::Equal,
        },
        other => other,
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
