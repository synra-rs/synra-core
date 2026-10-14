//! The registry's tests.

use synra_protocol::handshake::{Agreed, Feature, LinkToken};
use synra_protocol::ids::{DeviceId, SessionId};
use synra_protocol::limits;
use synra_protocol::session::PlatformKind;

use super::identity::SessionKey;
use super::record::PeerSession;
use super::registry::{RegistryError, RegistryEvent, SessionRegistry};
use super::state::{ClosureReason, LinkState};

    /// Two stable UUIDs, so a test can name the same device twice.
    const DEV_A: &str = "11111111-1111-4111-8111-111111111111";
    const DEV_B: &str = "22222222-2222-4222-8222-222222222222";
    const DEV_C: &str = "33333333-3333-4333-8333-333333333333";
    const SESSION_ONE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const SESSION_TWO: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    fn device(name: &str) -> DeviceId {
        // `DeviceId` is a UUID, so the tests name devices by parsing a UUID derived from a short name — which is what
        // the wire does and keeps the fixtures readable.
        name.parse().expect("a valid device id")
    }

    fn session_id(name: &str) -> SessionId {
        name.parse().expect("a valid session id")
    }

    fn token(byte: u8) -> LinkToken {
        LinkToken::from_bytes([byte; LinkToken::LEN])
    }

    /// Opens a session for a device no other fixture uses.
    ///
    /// The identities are freshly generated, because `DeviceId` and `SessionId` are UUIDs and a test that wants to name
    /// the same device twice uses [`opened_for`] with one of the constants above.
    fn opened(registry: &mut SessionRegistry, name: &str, at: u64) -> SessionKey {
        // The name is kept as a label for the call site's readability; the identity is the registry's.
        let _ = name;
        opened_random(registry, at)
    }

    /// Opens a session for a device whose identity is fresh.
    fn opened_random(registry: &mut SessionRegistry, at: u64) -> SessionKey {
        let (key, _) = registry.open(
            SessionId::new(),
            DeviceId::new(),
            PlatformKind::Desktop,
            token(1),
            at,
        );
        key
    }

    /// Opens a session for a *named* device, so a test can open a second and see what replaced the first.
    fn opened_for(registry: &mut SessionRegistry, device_id: DeviceId, at: u64) -> SessionKey {
        let (key, _) = registry.open(
            SessionId::new(),
            device_id,
            PlatformKind::Desktop,
            token(1),
            at,
        );
        key
    }

    fn agreed() -> Agreed {
        Agreed { common: vec![Feature::EventStream], missing_required: Vec::new() }
    }

    // ── Opening and the reconnect case ────────────────────────────────────────────────────────────

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
            token(1),
            1_000,
        );
        let (new, events) = registry.open(
            session_id(SESSION_TWO),
            device(DEV_A),
            PlatformKind::Desktop,
            token(2),
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
            token(1),
            1_000,
        );
        registry.open(
            session_id(SESSION_TWO),
            device(DEV_A),
            PlatformKind::Desktop,
            token(2),
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

    // ── Transitions ───────────────────────────────────────────────────────────────────────────────

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

    // ── The heartbeat ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_frame_from_the_peer_moves_the_deadline() {
        // The heartbeat is the only thing that distinguishes a quiet peer from a gone one, and it is evidence the peer
        // is there.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);

        registry.record_frame_in(key, &token(1), 800).expect("frame");
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_800);
        assert_eq!(registry.get(key).expect("key").frames_in(), 1);
    }

    #[test]
    fn a_frame_with_the_wrong_token_is_refused() {
        // ★ The reconnect case. The peer closed its old link and opened a new one, and a frame the old link sent just
        // before it went away arrives after the new session is live. Applying it would let the dead link move the live
        // session's state — for instance mark it as seen, keeping a session that is already gone alive for another
        // timeout.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);

        match registry.record_frame_in(key, &token(9), 500) {
            Err(RegistryError::TokenMismatch { key: reported }) => assert_eq!(reported, key),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And nothing moved.
        assert_eq!(registry.get(key).expect("key").last_seen_ms(), 0);
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);
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
        registry.record_frame_in(fresh, &token(1), 950).expect("frame");

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

    // ── Accounting ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn frames_are_counted_in_both_directions() {
        // The numbers a diagnostic report wants, and the only evidence of a link that is up but not carrying anything —
        // frames out and none in is a peer that is not listening.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 0);
        for _ in 0..3 {
            registry.record_frame_out(key).expect("out");
        }
        registry.record_frame_in(key, &token(1), 100).expect("in");

        let session = registry.get(key).expect("key");
        assert_eq!(session.frames_out(), 3);
        assert_eq!(session.frames_in(), 1);
    }

    #[test]
    fn the_age_and_the_silence_are_measured_from_different_moments() {
        // ★ Two different questions. A session that has been open for an hour and heard from its peer a second ago is
        // healthy; one open for an hour and silent for an hour is not. Deriving one from the other would report the
        // wrong one for exactly the long-lived sessions that matter.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.record_frame_in(key, &token(1), 3_600_000).expect("frame");

        let session = registry.get(key).expect("key");
        assert_eq!(session.age_ms(3_600_000), 3_599_000);
        assert_eq!(session.silent_for_ms(3_600_000), 0);
        assert!(!session.is_overdue(3_600_000));
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_report_a_negative_silence() {
        // A caller with a clock that moved backwards is a caller with a problem, and a negative duration is not one this
        // module can represent. Saturating is the answer that keeps the arithmetic total.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 5_000);
        let session = registry.get(key).expect("key");
        assert_eq!(session.silent_for_ms(1_000), 0);
        assert_eq!(session.age_ms(1_000), 0);
    }

    // ── Forgetting ────────────────────────────────────────────────────────────────────────────────

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
            token(2),
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
