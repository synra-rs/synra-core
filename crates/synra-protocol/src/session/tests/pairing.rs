use core::time::Duration;
use crate::error::SynraError;
use crate::ids::{DeviceId, IntentId, PluginId};
use crate::limits;
use super::super::{
    IntentDisplay, IntentInvocation, IntentOutcome, PeerProfile, PlatformKind, SessionTimeouts,
};

fn profile() -> PeerProfile {
    PeerProfile {
        device_id: DeviceId::new(),
        display_name: "imba97's laptop".to_owned(),
        platform: PlatformKind::Desktop,
        app_version: "1.0.0".to_owned(),
    }
}

#[test]
fn default_timeouts_are_self_consistent() {
    assert_eq!(SessionTimeouts::default().validate(), Ok(()));
}

#[test]
fn a_result_cache_shorter_than_the_dedup_window_is_refused() {
    let timeouts = SessionTimeouts {
        result_cache: limits::REQUEST_DEDUP_WINDOW - Duration::from_secs(1),
        ..SessionTimeouts::default()
    };
    assert!(timeouts.validate().is_err());
}

#[test]
fn an_idle_timeout_longer_than_the_total_is_refused() {
    let timeouts = SessionTimeouts {
        transfer_idle: Duration::from_secs(3600),
        transfer_total: Duration::from_secs(60),
        ..SessionTimeouts::default()
    };
    assert!(timeouts.validate().is_err());
}

#[test]
fn zero_session_timeouts_are_refused() {
    for timeouts in [
        SessionTimeouts { pairing: Duration::ZERO, ..SessionTimeouts::default() },
        SessionTimeouts { intent: Duration::ZERO, ..SessionTimeouts::default() },
    ] {
        assert!(timeouts.validate().is_err());
    }
}

#[test]
fn a_profile_needs_a_usable_name() {
    let mut profile = profile();
    assert_eq!(profile.validate(), Ok(()));

    profile.display_name = "   ".to_owned();
    assert!(profile.validate().is_err());

    profile.display_name = "x".repeat(PeerProfile::MAX_DISPLAY_NAME + 1);
    assert!(profile.validate().is_err());

    // Counted in characters: a CJK name of the same character count is accepted.
    profile.display_name = "电".repeat(PeerProfile::MAX_DISPLAY_NAME);
    assert_eq!(profile.validate(), Ok(()));

    profile.app_version = String::new();
    assert!(profile.validate().is_err());
}


#[test]
fn an_intent_invocation_round_trips_with_its_raw_args() {
    let invocation = IntentInvocation {
        intent_id: IntentId::new(),
        plugin_id: PluginId::parse("@synra-plugin/github-bridge").expect("valid"),
        action: "open-url".to_owned(),
        args: serde_json::value::to_raw_value(&serde_json::json!({ "url": "https://example.com" }))
            .expect("raw"),
        display: Some(IntentDisplay {
            title: "Open this link".to_owned(),
            detail: Some("https://example.com".to_owned()),
            source_display_name: "phone".to_owned(),
        }),
    };

    let json = serde_json::to_string(&invocation).expect("serialises");
    let back: IntentInvocation = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, invocation);
    // The args stay text until somebody reads them.
    assert!(invocation.args.get().contains("example.com"));
}

#[test]
fn an_outcome_is_either_a_result_or_an_error() {
    let intent = IntentId::new();
    assert_eq!(IntentOutcome::ok(intent, None, 12).validate(), Ok(()));
    assert_eq!(
        IntentOutcome::failed(intent, SynraError::unsupported("x"), 5).validate(),
        Ok(())
    );

    // Both at once is refused: an interface that had to choose which to believe would
    // eventually meet a case where they disagree.
    let contradictory = IntentOutcome {
        intent_id: intent,
        ok: true,
        result: None,
        error: Some(SynraError::unsupported("x")),
        elapsed_ms: 5,
    };
    assert!(contradictory.validate().is_err());

    // And a failure with no error tells the user nothing.
    let mute = IntentOutcome {
        intent_id: intent,
        ok: false,
        result: None,
        error: None,
        elapsed_ms: 5,
    };
    assert!(mute.validate().is_err());
}

#[test]
fn platform_kinds_report_mobility() {
    assert!(!PlatformKind::Desktop.is_mobile());
    assert!(PlatformKind::Android.is_mobile());
    assert!(PlatformKind::Ios.is_mobile());
    assert_eq!(PlatformKind::Desktop.to_string(), "desktop");
}
