use synra_protocol::session::PlatformKind;
use super::super::identity::SessionKey;
use super::super::registry::{RegistryEvent, SessionRegistry};
use super::super::state::LinkState;
use super::{DEV_A, DEV_B, DEV_C, SESSION_ONE, SESSION_TWO, device, session_id, opened_random, opened_for};

#[test]
fn opening_a_session_starts_it_connecting() {
    // The state a link is in before anything is exchanged. A registry that started at `Ready` would let the kernel
    // send work on a link the peer has not agreed to anything on.
    let mut registry = SessionRegistry::new();
    let key = opened_for(&mut registry, device(DEV_A), 1_000);
    let session = registry.get(key).expect("the session");

    assert_eq!(session.state(), LinkState::Connecting);
    assert!(!session.accepts_work());
    // And it accepts frames, because the hello is a frame.
    assert!(session.state().accepts_frames());
    assert_eq!(session.opened_at_ms(), 1_000);
    assert_eq!(session.device_id(), device(DEV_A));
}

#[test]
fn opening_a_session_for_a_peer_that_has_one_closes_the_old() {
    // ★ A reconnect. Two live sessions to one device is a state nothing below can resolve: an envelope arrives on
    // one of them and the kernel does not know which state it belongs to, half its work goes to each, and a `bye`
    // on one does not end the other.
    let mut registry = SessionRegistry::new();
    let (old, _) = registry.open(
        session_id(SESSION_ONE),
        device(DEV_A),
        PlatformKind::Desktop,
        1_000,
    );
    let (new, events) = registry.open(
        session_id(SESSION_TWO),
        device(DEV_A),
        PlatformKind::Desktop,
        2_000,
    );

    assert_ne!(old, new);
    // The event names both, and the *new* key is the real one — the `Replaced` event is built before the new
    // session exists, so a registry that did not correct it would name a key nothing has.
    let replaced = events
        .iter()
        .find_map(|event| match event {
            RegistryEvent::Replaced { old, new } => Some((*old, *new)),
            _ => None,
        })
        .expect("a Replaced event");
    assert_eq!(replaced, (old, new));

    assert!(registry.get(old).expect("old").state().is_over());
    assert_eq!(registry.get(new).expect("new").state(), LinkState::Connecting);
    assert_eq!(registry.live_for(device(DEV_A)).expect("live").key(), new);
}

#[test]
fn the_replaced_session_says_why_it_ended() {
    // The user asked nothing, so without a reason a UI would show an unexplained disconnect — and the explanation
    // is the one thing only the registry knows.
    let mut registry = SessionRegistry::new();
    let (old, _) = registry.open(
        session_id(SESSION_ONE),
        device(DEV_A),
        PlatformKind::Desktop,
        1_000,
    );
    registry.open(
        session_id(SESSION_TWO),
        device(DEV_A),
        PlatformKind::Desktop,
        2_000,
    );

    let reason = registry.get(old).expect("old").closure().expect("a reason");
    assert!(!reason.is_unexpected(), "a reconnect is not a network fault: {reason:?}");
    assert!(reason.explain().contains("new session"), "{}", reason.explain());
}

#[test]
fn two_devices_have_two_sessions() {
    // The map is per device. A registry keyed only by session would let the second device's session replace the
    // first's `live` entry, and the first device would have no session the kernel could find.
    let mut registry = SessionRegistry::new();
    let a = opened_for(&mut registry, device(DEV_A), 1_000);
    let b = opened_for(&mut registry, device(DEV_B), 1_000);

    assert_eq!(registry.len(), 2);
    assert_eq!(registry.live_for(device(DEV_A)).expect("a").key(), a);
    assert_eq!(registry.live_for(device(DEV_B)).expect("b").key(), b);
    assert!(registry.live_for(device(DEV_C)).is_none());
}

#[test]
fn the_keys_are_distinct_and_ordered() {
    // `BTreeMap` iteration order is the report's order, so the keys have to be ordered and distinct — two sessions
    // sharing a key is one session.
    let mut registry = SessionRegistry::new();
    let keys: Vec<SessionKey> = (0..5)
        .map(|_| opened_random(&mut registry, 1_000))
        .collect();

    let mut sorted = keys.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted, keys);
}
