use super::super::identity::SessionKey;
use super::super::record::PeerSession;
use super::super::registry::{RegistryError, SessionRegistry};
use super::super::state::{ClosureReason, LinkState};
use super::opened_random;

#[test]
fn a_report_of_the_states_says_which_is_which() {
    // The names reach a log line and a diagnostic bundle, and a reader has to tell a draining link from a closed
    // one to know whether the peer is going away or gone.
    assert_eq!(LinkState::Connecting.as_str(), "connecting");
    assert_eq!(LinkState::Handshaking.as_str(), "handshaking");
    assert_eq!(LinkState::Ready.as_str(), "ready");
    assert_eq!(LinkState::Draining.as_str(), "draining");
    assert_eq!(LinkState::Closed.as_str(), "closed");
    assert!(LinkState::Closed.is_over());
    assert!(!LinkState::Draining.is_over());
}

#[test]
fn only_the_reasons_the_user_did_not_cause_are_unexpected() {
    // ★ A user who pressed "disconnect" does not need a notification saying the device disconnected — they were
    // there when it happened. A peer that stopped answering does, because they did not cause it.
    assert!(!ClosureReason::Local { why: "asked".to_owned() }.is_unexpected());
    assert!(!ClosureReason::Peer { why: None }.is_unexpected());
    assert!(ClosureReason::HeartbeatMissed { silent_ms: 1 }.is_unexpected());
    assert!(ClosureReason::HandshakeFailed { why: "v".to_owned() }.is_unexpected());
    assert!(ClosureReason::TransportFailed { why: "e".to_owned() }.is_unexpected());
}

#[test]
fn every_reason_explains_itself_for_a_log_line() {
    // These sentences reach a user's diagnostic bundle, and one that contained a brace would be a debugging aid that
    // looks like a bug.
    for reason in [
        ClosureReason::Local { why: "the user asked".to_owned() },
        ClosureReason::Peer { why: Some("done".to_owned()) },
        ClosureReason::Peer { why: None },
        ClosureReason::HeartbeatMissed { silent_ms: 90_000 },
        ClosureReason::HandshakeFailed { why: "no shared feature".to_owned() },
        ClosureReason::TransportFailed { why: "reset by peer".to_owned() },
    ] {
        let text = reason.explain();
        assert!(text.len() > 15, "{reason:?} -> {text}");
        assert!(!text.contains('{'), "{reason:?} -> {text}");
        assert!(!text.contains('}'), "{reason:?} -> {text}");
    }
}

#[test]
fn the_errors_explain_themselves() {
    let key = SessionKey(3);
    let errors = [
        RegistryError::NoSuchSession(key),
        RegistryError::AlreadyClosed {
            key,
            reason: ClosureReason::Peer { why: Some("done".to_owned()) },
        },
        RegistryError::IllegalTransition {
            key,
            from: LinkState::Draining,
            to: LinkState::Ready,
        },
        RegistryError::TokenMismatch { key },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.contains('3'), "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

#[test]
fn a_key_is_readable_in_a_report() {
    assert_eq!(SessionKey(7).to_string(), "s7");
    assert_eq!(SessionKey(7).get(), 7);
}

#[test]
fn the_registry_iterates_in_key_order() {
    // A report and a test both want the same order twice, so the store is ordered rather than a `HashMap`.
    let mut registry = SessionRegistry::new();
    let keys: Vec<SessionKey> = (0..4)
        .map(|_| opened_random(&mut registry, 1_000))
        .collect();
    let iterated: Vec<SessionKey> = registry.iter().map(PeerSession::key).collect();
    assert_eq!(iterated, keys);
}

#[test]
fn an_empty_registry_says_so() {
    let mut registry = SessionRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert!(registry.ready().next().is_none());
    assert!(registry.sweep_expired(1_000_000).is_empty());
    assert_eq!(registry.forget_closed(), 0);
    assert_eq!(SessionRegistry::default().len(), 0);
}
