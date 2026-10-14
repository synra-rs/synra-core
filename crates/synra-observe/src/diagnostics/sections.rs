//! What a bundle may contain, and what it never contains.
//!
//! # Why the exclusion list is a constant
//!
//! Because it is a promise. The prompt renders it verbatim, and a test asserts it holds for a bundle built with every
//! optional section enabled. A computed list is one that could differ from what the user agreed to.

use serde::{Deserialize, Serialize};

/// How many log lines a bundle carries by default.
///
/// A tail plus every error, rather than the whole file: the interesting part of a log is what happened just
/// before the problem, and a bundle containing two weeks of `INFO` lines is one nobody reads.
pub const DEFAULT_LOG_TAIL_LINES: usize = 2_000;

/// The longest a single log line may be in a bundle.
pub const MAX_LOG_LINE_BYTES: usize = 4_096;

/// What can be included, and what is always excluded.
///
/// The distinction is a field rather than a convention: a caller assembles a plan and the plan is what is
/// shown, so an inclusion nobody intended cannot reach the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BundleSection {
    /// Operating system, architecture, application and kernel versions.
    Environment,
    /// The application's configuration, with secret fields removed.
    Config,
    /// Which devices are paired and whether the links are up.
    Devices,
    /// Which plugins are installed and their state.
    Plugins,
    /// Counters and histograms.
    Metrics,
    /// The tail of the log, plus every error.
    Logs,
    /// Recent crash reports.
    Crashes,
    /// The environment probe results.
    Probes,
    /// What plugins have been doing, including refusals.
    ///
    /// Optional, and off by default. It is the one section that describes the user's own activity rather than
    /// the software's state.
    AuditTrail,
    /// Debug-level log lines.
    ///
    /// Optional, and off by default. Debug lines carry device names and file paths, which are the user's
    /// information even though they are not secrets.
    DebugLogs,
}

impl BundleSection {
    /// Every section, in the order the prompt lists them.
    pub const ALL: &'static [Self] = &[
        Self::Environment,
        Self::Config,
        Self::Devices,
        Self::Plugins,
        Self::Metrics,
        Self::Logs,
        Self::Crashes,
        Self::Probes,
        Self::AuditTrail,
        Self::DebugLogs,
    ];

    /// The name used in the prompt and in the bundle's manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Config => "config",
            Self::Devices => "devices",
            Self::Plugins => "plugins",
            Self::Metrics => "metrics",
            Self::Logs => "logs",
            Self::Crashes => "crashes",
            Self::Probes => "probes",
            Self::AuditTrail => "audit-trail",
            Self::DebugLogs => "debug-logs",
        }
    }

    /// Whether this section is off unless the user turns it on.
    ///
    /// Two sections, and both are about the user rather than the software: what they did, and the detail
    /// lines that name their devices and files. Everything else is state the application would report about
    /// itself anyway.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(self, Self::AuditTrail | Self::DebugLogs)
    }

    /// Whether this section is in the bundle by default.
    #[must_use]
    pub const fn is_default(self) -> bool {
        !self.is_optional()
    }

    /// A phrase for the consent prompt.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Environment => "version and platform information",
            Self::Config => "your settings, with anything secret removed",
            Self::Devices => "which devices are paired, and whether they are reachable",
            Self::Plugins => "which plugins are installed and whether they are running",
            Self::Metrics => "performance counters",
            Self::Logs => "recent errors and the last part of the log",
            Self::Crashes => "reports from any recent crash",
            Self::Probes => "the environment check results",
            Self::AuditTrail => "which capabilities plugins used, including refusals",
            Self::DebugLogs => "detailed debug lines, which may name your devices and files",
        }
    }
}

/// What is never included, whatever the user asks for.
///
/// A constant rather than a computation, because it is a promise. The prompt renders it verbatim, and a test
/// asserts the promise holds for a bundle built with every optional section enabled.
pub const NEVER_INCLUDED: &[&str] = &[
    "clipboard contents",
    "the body of any message",
    "the contents of any file",
    "passwords, tokens or pairing secrets",
    "anything a plugin stored in secure storage",
];
