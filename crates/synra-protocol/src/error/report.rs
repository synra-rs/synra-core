use core::fmt;
use serde::{Deserialize, Serialize};

use super::ErrorCode;

/// What the user should be told about a failure.
///
/// A three-way verdict rather than a boolean because "silent" and "degraded" are different
/// messages: a transient reset during reconnect should say nothing at all, while a heartbeat
/// timeout means the device is showing as offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum UserVisibility {
    /// Do not surface it. Transient network noise and local shutdowns.
    Silent,
    /// The feature is degraded; the interface should say so, without an error.
    Degraded,
    /// The user needs to know, and probably needs to act.
    Error,
}

/// A structured failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub struct SynraError {
    /// Machine-readable reason. Branch on this.
    pub code: ErrorCode,
    /// Human-readable explanation. Never branch on this.
    pub message: String,
    /// Whether the same operation may be retried as-is.
    pub retryable: bool,
    /// What the user could do about it, in priority order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<SuggestedAction>,
    /// Trace id of the operation that failed, so a report can be tied to a log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Optional structured diagnostic context. Never use it to override the error classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Box<serde_json::Value>>,
}

impl fmt::Display for SynraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl SynraError {
    /// Builds an error, deriving `retryable` from the code.
    ///
    /// The derived value is the point: a constructor that let each call site decide would produce a
    /// codebase where the same failure is retryable in one place and not in another.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: code.retryable(),
            actions: Vec::new(),
            trace_id: None,
            details: None,
        }
    }

    /// The user declined, or the platform cannot do this.
    #[must_use]
    pub fn capability_denied(capability: impl fmt::Display) -> Self {
        Self::new(
            ErrorCode::CapabilityDenied,
            format!("missing capability: {capability}"),
        )
        .with_action(SuggestedAction::RequestCapability {
            capability: capability.to_string(),
        })
    }

    /// The plugin is not installed on the other device.
    #[must_use]
    pub fn plugin_not_installed(plugin: impl fmt::Display) -> Self {
        Self::new(
            ErrorCode::PluginNotInstalled,
            format!("the other device does not have {plugin} installed"),
        )
        .with_action(SuggestedAction::InstallPlugin {
            plugin_id: plugin.to_string(),
        })
    }

    /// The device is not reachable.
    #[must_use]
    pub fn device_offline(device: impl fmt::Display) -> Self {
        Self::new(
            ErrorCode::DeviceOffline,
            format!("{device} is not reachable"),
        )
        .with_action(SuggestedAction::ConnectDevice {
            device_id: device.to_string(),
        })
        .with_action(SuggestedAction::Retry)
    }

    /// The host cannot do this at all.
    #[must_use]
    pub fn unsupported(what: impl fmt::Display) -> Self {
        Self::new(
            ErrorCode::Unsupported,
            format!("this platform does not support {what}"),
        )
    }

    /// An argument was missing or malformed.
    #[must_use]
    pub fn invalid_argument(what: impl fmt::Display) -> Self {
        Self::new(ErrorCode::InvalidArgument, format!("invalid argument: {what}"))
    }

    /// The operation took too long.
    #[must_use]
    pub fn timeout(what: impl fmt::Display) -> Self {
        Self::new(ErrorCode::Timeout, format!("{what} timed out"))
    }

    /// The bytes did not match the declared digest.
    #[must_use]
    pub fn integrity_mismatch(expected: &str, actual: &str) -> Self {
        Self::new(
            ErrorCode::IntegrityMismatch,
            format!("digest mismatch: expected {expected}, got {actual}"),
        )
    }

    /// Attaches a suggested action.
    #[must_use]
    pub fn with_action(mut self, action: SuggestedAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Attaches diagnostic context without changing the error classification.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(Box::new(details));
        self
    }

    /// Attaches the trace id of the failing operation.
    #[must_use]
    pub fn with_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// What the user should be told.
    #[must_use]
    pub const fn visibility(&self) -> UserVisibility {
        match self.code {
            // The user asked for something that cannot happen; silence would be a bug report.
            ErrorCode::CapabilityDenied
            | ErrorCode::PluginNotInstalled
            | ErrorCode::NotPaired
            | ErrorCode::IntegrityMismatch
            | ErrorCode::PayloadTooLarge
            | ErrorCode::InvalidArgument
            | ErrorCode::SchemeNotAllowed
            | ErrorCode::HostNotAllowed
            | ErrorCode::IpNotAllowed
            | ErrorCode::RedirectBlocked
            | ErrorCode::ResponseTooLarge
            | ErrorCode::ProtocolViolation
            | ErrorCode::ProtocolVersionUnsupported
            | ErrorCode::PluginTrapped => UserVisibility::Error,

            // Recoverable, but the interface should show that something is off.
            ErrorCode::DeviceOffline
            | ErrorCode::TransportNotOpen
            | ErrorCode::TransferFailed
            | ErrorCode::Timeout
            | ErrorCode::RateLimited
            | ErrorCode::PluginTimeout
            | ErrorCode::Internal => UserVisibility::Degraded,

            // The platform simply cannot, and the interface should already have offered a different
            // path rather than reporting a failure after the fact.
            ErrorCode::Unsupported => UserVisibility::Degraded,
        }
    }
}

/// Something the user can do about a failure.
///
/// Structured rather than a sentence so the interface can render a button, and so a translation
/// layer never has to parse prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
#[non_exhaustive]
pub enum SuggestedAction {
    /// Open a settings section.
    OpenSettings {
        /// Section key, stable across versions.
        section: String,
    },
    /// Ask the user to grant a capability.
    RequestCapability {
        /// The capability string to grant.
        capability: String,
    },
    /// Offer to install a plugin on the other device.
    InstallPlugin {
        /// Plugin to install.
        plugin_id: String,
    },
    /// Offer to connect (or pair with) a device.
    ConnectDevice {
        /// Device to connect to.
        device_id: String,
    },
    /// The operation is safe to repeat.
    Retry,
    /// Open the log view, filtered to a trace.
    ViewLogs {
        /// Trace to show.
        trace_id: String,
    },
}

impl SuggestedAction {
    /// One of every suggestion, for the generated binding and for the test that keeps it in step.
    ///
    /// # Why the payloads are placeholders
    ///
    /// Four of the six variants carry a field — a section, a capability, a plugin, a device — so a list of *values*
    /// needs a value for each. These are examples rather than defaults: the point of the list is that every variant
    /// appears once and that its `kind` tag is the one the protocol serialises, and the payloads are never shown to
    /// anyone. A caller that wanted a real suggestion constructs one.
    ///
    /// The companion test asserts the count, so adding a variant without adding it here fails the suite.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::OpenSettings { section: "general".to_owned() },
            Self::RequestCapability { capability: "log:read".to_owned() },
            Self::InstallPlugin { plugin_id: "@synra-plugin/example".to_owned() },
            Self::ConnectDevice { device_id: "example".to_owned() },
            Self::Retry,
            Self::ViewLogs { trace_id: "example".to_owned() },
        ]
    }
}
