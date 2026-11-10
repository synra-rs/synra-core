use synra_protocol::session::PlatformKind;
use super::super::identity::SessionKey;
use super::super::record::PeerSession;
use super::super::registry::{RegistryError, RegistryEvent, SessionRegistry};
use super::super::state::{ClosureReason, LinkState};
use super::{DEV_A, SESSION_TWO, device, session_id, opened, agreed};

#[test]
fn a_closed_session_is_kept_until_it_is_forgotten() {
    // ★ A user asking "why did it disconnect" asks *after* it disconnected, and by then the session is the only
    // thing that knew. Keeping it until the caller removes it is what makes that answerable.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 0);
    registry.close(key, ClosureReason::TransportFailed { why: "reset".to_owned() }, 100);

    assert_eq!(registry.len(), 1);
    let forgotten = registry.forget(key).expect("forget");
    assert!(forgotten.closure().expect("reason").explain().contains("reset"));
    assert!(registry.is_empty());
    assert!(registry.live_for(device(DEV_A)).is_none());
}

#[test]
fn a_live_session_is_not_forgotten() {
    // ★ Forgetting a live one leaves its peer connected with nothing tracking it: no heartbeat, no timeout, no way
    // to close it. The refusal is what makes the caller close it first.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 0);
    match registry.forget(key) {
        Err(RegistryError::IllegalTransition { from, .. }) => {
            assert_eq!(from, LinkState::Connecting);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(registry.len(), 1);
}

#[test]
fn forgetting_every_closed_session_leaves_the_live_ones() {
    let mut registry = SessionRegistry::new();
    let a = opened(&mut registry, "a", 0);
    let b = opened(&mut registry, "b", 0);
    let c = opened(&mut registry, "c", 0);
    registry.close(a, ClosureReason::Peer { why: None }, 100);
    registry.close(b, ClosureReason::Peer { why: None }, 100);

    assert_eq!(registry.forget_closed(), 2);
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.get(c).expect("c").state(), LinkState::Connecting);
}

#[test]
fn forgetting_every_closed_session_removes_their_live_entries() {
    // ★ The two maps have to agree. A `live` entry pointing at a forgotten session is one where `live_for` returns
    // `None` while the map says the device has a session — so the next reconnect would find nothing to replace and
    // the device would appear twice after all.
    let mut registry = SessionRegistry::new();
    let key = opened(&mut registry, "a", 0);
    registry.close(key, ClosureReason::Peer { why: None }, 100);
    registry.forget_closed();

    assert!(registry.live_for(device(DEV_A)).is_none());
    // And a reconnect is a fresh open rather than a replacement.
    let (new, events) = registry.open(
        session_id(SESSION_TWO),
        device(DEV_A),
        PlatformKind::Desktop,
        200,
    );
    assert!(!events.iter().any(|event| matches!(event, RegistryEvent::Replaced { .. })));
    assert_eq!(registry.get(new).expect("new").state(), LinkState::Connecting);
}

#[test]
fn the_ready_list_is_the_sessions_that_accept_work() {
    // What a UI asks for when it wants to offer a device, and the one list that must not include a link whose
    // handshake has not finished or one that is draining.
    let mut registry = SessionRegistry::new();
    let connecting = opened(&mut registry, "a", 0);
    let ready = opened(&mut registry, "b", 0);
    let draining = opened(&mut registry, "c", 0);
    registry.agree(ready, agreed(), 10).expect("agree");
    registry.agree(draining, agreed(), 10).expect("agree");
    registry.begin_draining(draining, 20).expect("drain");

    let keys: Vec<SessionKey> = registry.ready().map(PeerSession::key).collect();
    assert_eq!(keys, vec![ready]);
    assert!(!keys.contains(&connecting));
}
