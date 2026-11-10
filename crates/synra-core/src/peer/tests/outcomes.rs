use synra_protocol::frame::FrameError;
use synra_protocol::handshake::{Agreed, Feature};
use synra_protocol::limits;
use synra_protocol::session::PlatformKind;
use super::super::{Flags, HandshakeError, Negotiated};
use super::{DIALER, device};

#[test]
fn the_production_flags_use_the_protocols_hello_timeout() {
    // The timeout is the protocol's constant rather than a figure chosen here, so a link is abandoned at the moment
    // every other part of the kernel believes it should be.
    assert_eq!(Flags::production().timeout, Some(limits::HELLO_TIMEOUT));
    assert_eq!(Flags::no_timeout().timeout, None);
    assert_eq!(Flags::default(), Flags::production());
}

// ── Errors ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_error_explains_itself() {
    let errors = [
        HandshakeError::Transport { why: "reset".to_owned() },
        HandshakeError::Closed,
        HandshakeError::Frame(FrameError::Poisoned),
        HandshakeError::Unexpected {
            expected: "Hello",
            found: "Ping".to_owned(),
        },
        HandshakeError::Payload { message: "Hello", why: "missing field".to_owned() },
        HandshakeError::VersionMismatch { theirs: 9, ours: 1 },
        HandshakeError::Refused { reason: "busy".to_owned() },
        HandshakeError::NonceMismatch,
        HandshakeError::Invalid { why: "too many endpoints".to_owned() },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And the version mismatch names both, because "incompatible" alone leaves a user with nothing.
    let text = errors[5].to_string();
    assert!(text.contains('9') && text.contains('1'), "{text}");
}

#[test]
fn a_negotiated_link_knows_whether_it_is_usable() {
    let usable = Negotiated {
        device_id: device(DIALER),
        display_name: "P".to_owned(),
        platform: PlatformKind::Android,
        app_version: "0.1.0".to_owned(),
        agreed: Agreed { common: vec![Feature::EventStream], missing_required: Vec::new() },
    };
    assert!(usable.is_usable());

    let unusable = Negotiated {
        agreed: Agreed { common: Vec::new(), missing_required: vec![Feature::TransferResume] },
        ..usable
    };
    assert!(!unusable.is_usable());
}
