use super::super::identity::SessionKey;
use super::super::registry::{RegistryError, RegistryEvent, SessionRegistry};
use super::super::state::{ClosureReason, LinkState};
use super::{opened, agreed};

#[test]
fn a_link_becomes_ready_only_after_an_agreement() {
    // ★ The distinction the whole module exists for. A message sent on a link whose handshake has not finished is
    // one the peer will refuse, and `accepts_work` is what a caller checks before sending.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    assert!(!registry.get(key).expect("key").accepts_work());

    registry.begin_handshake(key, 1_100).expect("handshake");
    assert!(!registry.get(key).expect("key").accepts_work());

    let events = registry.agree(key, agreed(), 1_200).expect("agree");
    assert_eq!(events, vec![RegistryEvent::Ready(key)]);
    assert!(registry.get(key).expect("key").accepts_work());
    assert!(registry.get(key).expect("key").agreed().is_some());
}

#[test]
fn connecting_may_become_ready_without_passing_through_handshaking() {
    // A peer that answers a hello *with* an agreement has done both steps. Requiring the kernel to pass through
    // `Handshaking` would be requiring it to invent an event it never observed.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    registry.agree(key, agreed(), 1_100).expect("agree");
    assert_eq!(registry.get(key).expect("key").state(), LinkState::Ready);
}

#[test]
fn a_link_does_not_go_back_to_a_state_it_left() {
    // ★ A draining session that became ready again would take new work after telling the peer it was going away —
    // and the peer may already have released its state for this session.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    registry.agree(key, agreed(), 1_100).expect("agree");
    registry.begin_draining(key, 1_200).expect("drain");

    match registry.agree(key, agreed(), 1_300) {
        Err(RegistryError::IllegalTransition { from, to, .. }) => {
            assert_eq!(from, LinkState::Draining);
            assert_eq!(to, LinkState::Ready);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(registry.get(key).expect("key").state(), LinkState::Draining);
}

#[test]
fn draining_twice_is_not_a_mistake() {
    // Both ends sending a goodbye at once is ordinary, so the second one has nothing to do rather than being an
    // error a caller has to handle.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    registry.agree(key, agreed(), 1_100).expect("agree");
    registry.begin_draining(key, 1_200).expect("drain");
    assert!(registry.begin_draining(key, 1_300).is_ok());
    assert_eq!(registry.get(key).expect("key").state(), LinkState::Draining);
}

#[test]
fn a_draining_link_still_exchanges_frames_but_takes_no_work() {
    // ★ The goodbye is a frame and the replies to work already in flight are frames. Refusing them would make a
    // clean close impossible, and accepting new work would start a transfer neither side will finish.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    registry.agree(key, agreed(), 1_100).expect("agree");
    registry.begin_draining(key, 1_200).expect("drain");

    assert!(!registry.get(key).expect("key").accepts_work());
    assert!(registry.get(key).expect("key").state().accepts_frames());
    assert!(registry.record_frame_out(key).is_ok());
}

#[test]
fn a_closed_link_takes_nothing() {
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    registry.close(key, ClosureReason::Local { why: "the user asked".to_owned() }, 1_100);

    assert!(!registry.get(key).expect("key").state().accepts_frames());
    assert!(!registry.get(key).expect("key").accepts_work());
    assert!(matches!(
        registry.record_frame_out(key),
        Err(RegistryError::AlreadyClosed { .. })
    ));
}

#[test]
fn a_transition_to_the_same_state_changes_nothing() {
    // A duplicate hello is not a mistake, and a registry that refused it would make a retransmitted frame an error
    // the caller has to swallow.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 1000);
    registry.begin_handshake(key, 1_100).expect("handshake");
    assert!(registry.begin_handshake(key, 1_200).is_ok());
    assert_eq!(registry.get(key).expect("key").state(), LinkState::Handshaking);
}

#[test]
fn an_unknown_key_is_an_error_rather_than_a_panic() {
    // A stale key is ordinary — a timer firing after a session was forgotten — and a panic there would take the
    // kernel down for a scheduling mistake.
    let mut registry = SessionRegistry::new();
    let ghost = SessionKey(9_999);
    assert!(matches!(
        registry.begin_handshake(ghost, 1_000),
        Err(RegistryError::NoSuchSession(_))
    ));
    assert!(matches!(registry.record_frame_out(ghost), Err(RegistryError::NoSuchSession(_))));
    assert!(matches!(registry.forget(ghost), Err(RegistryError::NoSuchSession(_))));
    // And closing one is a no-op rather than an error: the caller has nothing to do about it.
    assert!(registry.close(ghost, ClosureReason::Local { why: String::new() }, 1_000).is_empty());
}
