use crate::ids::DeviceId;
use crate::session::PlatformKind;

use super::super::{Feature, HelloAck, HelloError, NextStep, RefusalReason, SessionNonce, next_step};
use super::accepted_ack;

#[test]
fn an_ack_must_echo_the_nonce() {
    let nonce = SessionNonce(0x1234);
    let ack = accepted_ack(nonce);
    assert_eq!(ack.validate(nonce), Ok(()));

    // A reply to a different attempt must not reach any other conclusion — including "the peer
    // refused us", which is why this check comes first.
    assert!(matches!(
        ack.validate(SessionNonce(0x9999)),
        Err(HelloError::Malformed(_))
    ));
}

#[test]
fn a_refusal_acknowledges_the_attempt_without_being_trusted() {
    let nonce = SessionNonce(1);
    let ack = HelloAck::refuse(
        DeviceId::new(),
        "phone",
        PlatformKind::Android,
        "1.0.0",
        nonce,
        RefusalReason::TooManyLinks,
    );

    assert!(!ack.is_accepted());
    assert!(ack.validate(nonce).is_err(), "the caller must be told");
}

#[test]
fn a_retryable_refusal_asks_for_a_retry_and_a_block_does_not() {
    let nonce = SessionNonce(1);

    let busy = HelloAck::refuse(
        DeviceId::new(),
        "phone",
        PlatformKind::Android,
        "1.0.0",
        nonce,
        RefusalReason::TooManyLinks,
    );
    assert!(matches!(
        next_step(&busy, Feature::ALL, &[]),
        NextStep::Retry { reason: RefusalReason::TooManyLinks }
    ));

    // Retrying a block is not a transient failure; it is the user's decision ignored once a
    // second.
    let blocked = HelloAck::refuse(
        DeviceId::new(),
        "phone",
        PlatformKind::Android,
        "1.0.0",
        nonce,
        RefusalReason::Blocked,
    );
    assert!(matches!(
        next_step(&blocked, Feature::ALL, &[]),
        NextStep::Refused(RefusalReason::Blocked)
    ));
}




#[test]
fn a_peer_that_cannot_meet_our_requirement_is_refused_before_use() {
    let nonce = SessionNonce(1);
    let mut ack = accepted_ack(nonce);
    ack.features = vec![Feature::ClipboardSync];

    // Without a requirement the link is fine.
    assert!(matches!(next_step(&ack, Feature::ALL, &[]), NextStep::Established(_)));

    // With one it is not, and the failure surfaces here rather than at the moment the missing
    // capability was first needed.
    assert!(matches!(
        next_step(&ack, Feature::ALL, &[Feature::EventStream]),
        NextStep::Refused(RefusalReason::MissingRequiredFeature)
    ));
}

#[test]
fn refusal_reasons_round_trip_and_report_retryability() {
    for reason in [
        RefusalReason::ProtocolMismatch,
        RefusalReason::MissingRequiredFeature,
        RefusalReason::Blocked,
        RefusalReason::TooManyLinks,
        RefusalReason::Malformed,
    ] {
        let json = serde_json::to_string(&reason).expect("serialises");
        assert_eq!(json, format!("\"{}\"", reason.as_str()));
        let back: RefusalReason = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, reason);
    }

    assert!(RefusalReason::TooManyLinks.is_retryable());
    assert!(!RefusalReason::Blocked.is_retryable());
    assert!(!RefusalReason::ProtocolMismatch.is_retryable());
    assert!(!RefusalReason::MissingRequiredFeature.is_retryable());
    assert!(!RefusalReason::Malformed.is_retryable());
}
