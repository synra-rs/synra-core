use serde::{Deserialize, Serialize};

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
