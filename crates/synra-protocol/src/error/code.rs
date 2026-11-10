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
    /// Every code, for a table-driven test and for a generated binding.
    ///
    /// # Why this exists rather than a derive
    ///
    /// The interface's TypeScript union of codes is generated from this list, and the check that matters is that the
    /// list is *complete*: a code missing from it is one the interface does not handle, and the symptom is a switch
    /// that falls through to a default message the user has already read. A macro_rules! over the enum declaration
    /// would keep it in step automatically and would also hide the enum's own documentation; a written list plus a
    /// test that counts the variants makes forgetting a compile-and-test failure instead.
    ///
    /// The companion test asserts the count, so adding a variant without adding it here fails the suite.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::CapabilityDenied,
            Self::PluginNotInstalled,
            Self::DeviceOffline,
            Self::NotPaired,
            Self::TransportNotOpen,
            Self::TransferFailed,
            Self::IntegrityMismatch,
            Self::PayloadTooLarge,
            Self::Timeout,
            Self::RateLimited,
            Self::Unsupported,
            Self::InvalidArgument,
            Self::SchemeNotAllowed,
            Self::HostNotAllowed,
            Self::IpNotAllowed,
            Self::RedirectBlocked,
            Self::ResponseTooLarge,
            Self::ProtocolViolation,
            Self::ProtocolVersionUnsupported,
            Self::PluginTrapped,
            Self::PluginTimeout,
            Self::Internal,
        ]
    }
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
