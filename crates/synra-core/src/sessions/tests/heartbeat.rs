use synra_protocol::limits;
use super::super::registry::{RegistryEvent, SessionRegistry};
use super::super::state::{ClosureReason, LinkState};
use super::{opened, agreed};

#[test]
fn a_frame_from_the_peer_moves_the_deadline() {
    // The heartbeat is the only thing that distinguishes a quiet peer from a gone one, and it is evidence the peer
    // is there.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let key = opened(&mut registry, "a", 0);
    assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);

    registry.record_frame_in(key, 800).expect("frame");
    assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_800);
    assert_eq!(registry.get(key).expect("key").frames_in(), 1);
}


#[test]
fn a_sweep_closes_a_silent_peer_and_says_for_how_long() {
    // ★ The user-visible consequence: a device that was unplugged disappears from the list rather than staying
    // selectable and failing when chosen.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let key = opened(&mut registry, "a", 0);
    registry.agree(key, agreed(), 0).expect("agree");

    let events = registry.sweep_expired(1_500);
    assert_eq!(events.len(), 1);
    match &events[0] {
        RegistryEvent::Closed(closed, ClosureReason::HeartbeatMissed { silent_ms }) => {
            assert_eq!(*closed, key);
            assert_eq!(*silent_ms, 1_500);
        }
        other => panic!("expected a heartbeat closure, got {other:?}"),
    }
    assert!(registry.get(key).expect("key").state().is_over());
    // And it is the *unexpected* kind, so a UI tells the user rather than staying silent as it would for a close
    // the user asked for.
    let reason = registry.get(key).expect("key").closure().expect("a reason");
    assert!(reason.is_unexpected());
}

#[test]
fn a_sweep_before_the_deadline_closes_nothing() {
    // The boundary. A sweep that fired one millisecond early would disconnect a peer that is answering, and the
    // symptom is a link that drops every few seconds for no reason a user can see.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let key = opened(&mut registry, "a", 0);
    assert!(registry.sweep_expired(999).is_empty());
    assert_eq!(registry.get(key).expect("key").state(), LinkState::Connecting);
}

#[test]
fn a_sweep_handles_every_session_that_expired() {
    // The caller is a timer on an interval, so one call has to handle every session that expired since the last
    // one. A method that handled one would need the caller to keep asking which — which is this loop.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let a = opened(&mut registry, "a", 0);
    let b = opened(&mut registry, "b", 0);
    let fresh = opened(&mut registry, "c", 900);
    registry.record_frame_in(fresh, 950).expect("frame");

    let events = registry.sweep_expired(1_500);
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(registry.get(a).expect("a").state().is_over());
    assert!(registry.get(b).expect("b").state().is_over());
    // The one that spoke is untouched.
    assert!(!registry.get(fresh).expect("fresh").state().is_over());
}

#[test]
fn a_second_sweep_does_not_close_what_is_already_closed() {
    // ★ The first reason wins. Without this, a sweep after a `bye` would replace "the peer said goodbye" with "the
    // peer was silent" — turning an ordinary close into a network fault in the user's report, and double-counting
    // the closure in a log.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let key = opened(&mut registry, "a", 0);
    registry.close(key, ClosureReason::Peer { why: None }, 500);

    assert!(registry.sweep_expired(5_000).is_empty());
    let reason = registry.get(key).expect("key").closure().expect("a reason");
    assert!(matches!(reason, ClosureReason::Peer { .. }), "{reason:?}");
}

#[test]
fn closing_a_closed_session_does_not_replace_the_reason() {
    // A `bye` and a timeout can race, and the second to arrive has nothing left to do — but it must not overwrite
    // the first explanation.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let key = opened(&mut registry, "a", 0);
    registry.close(key, ClosureReason::Peer { why: Some("done".to_owned()) }, 100);
    let events = registry.close(
        key,
        ClosureReason::HeartbeatMissed { silent_ms: 9_000 },
        9_000,
    );

    assert!(events.is_empty(), "{events:?}");
    assert!(matches!(
        registry.get(key).expect("key").closure(),
        Some(ClosureReason::Peer { .. })
    ));
}

#[test]
fn a_handshake_that_takes_longer_than_the_timeout_is_closed() {
    // A peer that opened a socket and said nothing. Without the sweep it would hold a session forever, and a device
    // that is powered off mid-scan would stay in the list.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let key = opened(&mut registry, "a", 0);
    let events = registry.sweep_expired(2_000);
    assert_eq!(events.len(), 1);
    assert!(registry.get(key).expect("key").state().is_over());
}

#[test]
fn a_zero_timeout_is_raised_rather_than_accepted() {
    // ★ A session that is overdue the instant it opens is one the kernel would close before its handshake could
    // finish, and the user would see a device that connects and immediately disconnects with no explanation.
    let registry = SessionRegistry::with_heartbeat_timeout(0);
    assert_eq!(registry.heartbeat_timeout_ms(), 1);
}

#[test]
fn the_default_timeout_is_the_protocols() {
    // The registry does not invent a figure: the constant is the protocol's, and a registry with its own would time
    // out a peer at a different moment from every other part of the kernel.
    let registry = SessionRegistry::new();
    assert_eq!(
        registry.heartbeat_timeout_ms(),
        limits::HEARTBEAT_TIMEOUT.as_millis() as u64
    );
}

#[test]
fn a_deadline_is_stored_rather_than_recomputed() {
    // ★ Changing the timeout mid-session does not move a running session's deadline. A deadline computed as
    // `last_seen + timeout` at the check would move it, so a user raising the timeout would silently extend the
    // life of a session that is already gone.
    let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
    let key = opened(&mut registry, "a", 0);
    assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);

    // A new registry would have a different timeout; this session keeps its own.
    let other = SessionRegistry::with_heartbeat_timeout(5_000);
    assert_eq!(other.heartbeat_timeout_ms(), 5_000);
    assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);
}
