use synra_protocol::ErrorCode;

mod keys;
mod reports;

/// Every error code, so a test can assert a property over all of them.
pub(super) const ALL_CODES: &[ErrorCode] = &[
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
