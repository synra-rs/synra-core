//! The error model.
//!
//! Two audiences, two shapes:
//!
//! * **On the wire** an error is a [`SynraError`] — a stable [`ErrorCode`], a human message, and a
//!   list of actions the user could take. It is serialisable and it is what a peer receives.
//! * **Inside a process** the same type is used, so there is no translation layer whose mapping can
//!   drift.
//!
//! # Why codes, not strings
//!
//! Callers branch on [`ErrorCode`]. Branching on the message would look like a shortcut and behave
//! like a trap: the message text changes with platform and with dependency version, and a real
//! error that happens to contain a keyword gets silently reclassified. `UserVisibility` exists for
//! the same reason — whether the user should see something is a property of the *kind* of failure,
//! decided by the type, not by matching substrings.

use core::fmt;
use serde::{Deserialize, Serialize};

/// A stable, machine-readable reason a request failed.
///
/// Adding a variant is a compatible change; renaming or repurposing one is not, because a peer
/// branches on the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The plugin is not granted the capability the call needs.
    CapabilityDenied,
    /// The target device does not have this plugin installed.
    PluginNotInstalled,
    /// The target device is not reachable right now.
    DeviceOffline,
    /// The two devices are not paired.
    NotPaired,
    /// The link exists but is not usable (still connecting, or draining).
    TransportNotOpen,
    /// The transfer failed for a reason other than integrity.
    TransferFailed,
    /// The received bytes did not match the declared digest.
    IntegrityMismatch,
    /// The payload exceeds the ceiling for an inline message.
    PayloadTooLarge,
    /// The operation did not complete in time.
    Timeout,
    /// Too many calls in too short a window.
    RateLimited,
    /// The action is not supported on this platform, or by this host version.
    Unsupported,
    /// The arguments did not validate.
    InvalidArgument,
    /// A URL scheme other than the allowed set.
    SchemeNotAllowed,
    /// A host outside the plugin's declared allowlist.
    HostNotAllowed,
    /// An address in a range the network capability refuses (loopback, link-local, private).
    IpNotAllowed,
    /// A redirect pointed outside the allowlist.
    RedirectBlocked,
    /// The response body exceeded the configured ceiling.
    ResponseTooLarge,
    /// A plugin exceeded the capabilities it declared, or used a namespace it does not own.
    ProtocolViolation,
    /// The peer speaks an incompatible protocol version.
    ProtocolVersionUnsupported,
    /// A plugin trapped, ran out of fuel, or exceeded its memory ceiling.
    PluginTrapped,
    /// A plugin exceeded its time budget.
    PluginTimeout,
    /// Something unexpected. Carries no structure on purpose: if a caller needs to branch, the code
    /// belongs above.
    Internal,
}

impl ErrorCode {
    /// The wire representation, identical to the `serde` output.
    ///
    /// Exists so logging and tests do not need to serialise to a string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityDenied => "capability_denied",
            Self::PluginNotInstalled => "plugin_not_installed",
            Self::DeviceOffline => "device_offline",
            Self::NotPaired => "not_paired",
            Self::TransportNotOpen => "transport_not_open",
            Self::TransferFailed => "transfer_failed",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::PayloadTooLarge => "payload_too_large",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::Unsupported => "unsupported",
            Self::InvalidArgument => "invalid_argument",
            Self::SchemeNotAllowed => "scheme_not_allowed",
            Self::HostNotAllowed => "host_not_allowed",
            Self::IpNotAllowed => "ip_not_allowed",
            Self::RedirectBlocked => "redirect_blocked",
            Self::ResponseTooLarge => "response_too_large",
            Self::ProtocolViolation => "protocol_violation",
            Self::ProtocolVersionUnsupported => "protocol_version_unsupported",
            Self::PluginTrapped => "plugin_trapped",
            Self::PluginTimeout => "plugin_timeout",
            Self::Internal => "internal",
        }
    }

    /// Whether retrying the same operation could plausibly succeed.
    ///
    /// A property of the code, not a judgement the caller should make. Getting it wrong in either
    /// direction is expensive: marking a permanent failure retryable produces a retry loop, and
    /// marking a transient one permanent makes the user do it by hand.
    #[must_use]
    pub const fn retryable(self) -> bool {
        match self {
            Self::DeviceOffline
            | Self::TransportNotOpen
            | Self::Timeout
            | Self::RateLimited
            | Self::TransferFailed
            | Self::Internal => true,

            Self::CapabilityDenied
            | Self::PluginNotInstalled
            | Self::NotPaired
            | Self::IntegrityMismatch
            | Self::PayloadTooLarge
            | Self::Unsupported
            | Self::InvalidArgument
            | Self::SchemeNotAllowed
            | Self::HostNotAllowed
            | Self::IpNotAllowed
            | Self::RedirectBlocked
            | Self::ResponseTooLarge
            | Self::ProtocolViolation
            | Self::ProtocolVersionUnsupported
            | Self::PluginTrapped
            | Self::PluginTimeout => false,
        }
    }

    /// Whether the capability behind this failure is a platform feature the host may simply not
    /// have, as opposed to something the user declined.
    ///
    /// Drives whether the interface offers "grant this" or shows a disabled control.
    #[must_use]
    pub const fn is_platform_limitation(self) -> bool {
        matches!(self, Self::Unsupported)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the user should be told about a failure.
///
/// A three-way verdict rather than a boolean because "silent" and "degraded" are different
/// messages: a transient reset during reconnect should say nothing at all, while a heartbeat
/// timeout means the device is showing as offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Attaches the trace id of the failing operation.
    #[must_use]
    pub fn with_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// What the user should be told.
    #[must_use]
    pub fn visibility(&self) -> UserVisibility {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_strings_are_snake_case_and_unique() {
        let all = [
            ErrorCode::CapabilityDenied,
            ErrorCode::PluginNotInstalled,
            ErrorCode::DeviceOffline,
            ErrorCode::NotPaired,
            ErrorCode::TransportNotOpen,
            ErrorCode::TransferFailed,
            ErrorCode::IntegrityMismatch,
            ErrorCode::PayloadTooLarge,
            ErrorCode::Timeout,
            ErrorCode::RateLimited,
            ErrorCode::Unsupported,
            ErrorCode::InvalidArgument,
            ErrorCode::SchemeNotAllowed,
            ErrorCode::HostNotAllowed,
            ErrorCode::IpNotAllowed,
            ErrorCode::RedirectBlocked,
            ErrorCode::ResponseTooLarge,
            ErrorCode::ProtocolViolation,
            ErrorCode::ProtocolVersionUnsupported,
            ErrorCode::PluginTrapped,
            ErrorCode::PluginTimeout,
            ErrorCode::Internal,
        ];

        let mut seen = std::collections::HashSet::new();
        for code in all {
            let s = code.as_str();
            assert!(seen.insert(s), "duplicate wire string: {s}");
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "not snake_case: {s}",
            );
            // `as_str` and `serde` must agree, or logs and the wire disagree about the same error.
            let json = serde_json::to_string(&code).expect("serialises");
            assert_eq!(json, format!("\"{s}\""));
        }
    }

    #[test]
    fn serde_round_trip_preserves_code() {
        for code in [ErrorCode::DeviceOffline, ErrorCode::PluginTrapped] {
            let json = serde_json::to_string(&code).expect("serialises");
            let back: ErrorCode = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, code);
        }
    }

    #[test]
    fn retryable_derives_from_code_not_call_site() {
        assert!(ErrorCode::DeviceOffline.retryable());
        assert!(!ErrorCode::CapabilityDenied.retryable());
        // The constructor must agree with the code.
        let err = SynraError::capability_denied("platform:open-url");
        assert_eq!(err.retryable, ErrorCode::CapabilityDenied.retryable());
        let err = SynraError::device_offline("dev_a");
        assert_eq!(err.retryable, ErrorCode::DeviceOffline.retryable());
    }

    #[test]
    fn errors_carry_an_action_the_interface_can_render() {
        let err = SynraError::capability_denied("platform:open-url");
        assert!(matches!(
            err.actions.as_slice(),
            [SuggestedAction::RequestCapability { capability }] if capability == "platform:open-url"
        ));

        let err = SynraError::plugin_not_installed("@synra-plugin/chat");
        assert!(matches!(
            err.actions.as_slice(),
            [SuggestedAction::InstallPlugin { plugin_id }] if plugin_id == "@synra-plugin/chat"
        ));

        // An offline device offers both "connect" and "retry", in that order: connecting is the
        // action that actually resolves it, retrying is the fallback.
        let err = SynraError::device_offline("dev_b");
        assert!(matches!(err.actions.first(), Some(SuggestedAction::ConnectDevice { .. })));
        assert!(matches!(err.actions.get(1), Some(SuggestedAction::Retry)));
    }

    #[test]
    fn every_error_has_a_visibility() {
        // Degraded and Silent are both "do not shout"; only Error means the user must be told.
        let denied = SynraError::capability_denied("fs:read:/x");
        assert_eq!(denied.visibility(), UserVisibility::Error);

        let unsupported = SynraError::unsupported("simulate_keys");
        assert_eq!(unsupported.visibility(), UserVisibility::Degraded);

        let offline = SynraError::device_offline("dev_b");
        assert_eq!(offline.visibility(), UserVisibility::Degraded);
    }

    #[test]
    fn error_round_trips_over_the_wire() {
        let err = SynraError::capability_denied("network:fetch:api.example.com")
            .with_trace("0123456789abcdef0123456789abcdef");

        let json = serde_json::to_string(&err).expect("serialises");
        // Field names are camelCase on the wire.
        assert!(json.contains("\"traceId\""), "{json}");
        assert!(!json.contains("trace_id"), "{json}");

        let back: SynraError = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, err);
    }

    #[test]
    fn unsupported_is_the_only_platform_limitation() {
        assert!(ErrorCode::Unsupported.is_platform_limitation());
        assert!(!ErrorCode::CapabilityDenied.is_platform_limitation());
    }

    #[test]
    fn visibility_ordering_is_usable_by_callers() {
        // A caller that wants "at least degraded" can compare rather than match.
        assert!(UserVisibility::Silent < UserVisibility::Degraded);
        assert!(UserVisibility::Degraded < UserVisibility::Error);
    }
}
