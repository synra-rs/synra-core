use super::{ErrorCode, SuggestedAction, SynraError, UserVisibility};

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
        .with_details(
            serde_json::json!({"pluginCode":"hostFailed","pluginDetails":{"label":"中文🖱️"}}),
        )
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
