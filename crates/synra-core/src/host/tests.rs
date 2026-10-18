use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use synra_protocol::discovery::{DeviceAnnouncement, TrustLevel};
use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::handshake::{PROTOCOL_VERSION, PairingState};
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

use crate::discovery::{Absorbed, DiscoveryTable};
use crate::identity::Identity;
use crate::link::{LinkError, PeerLink};
use crate::peer::{Flags, HandshakeError, LocalPeer};
use crate::sessions::{LinkState, RegistryEvent, SessionRegistry};

use super::{Host, HostError, millis_reading, reading_millis, shared};

const A: &str = "11111111-1111-4111-8111-111111111111";
const B: &str = "22222222-2222-4222-8222-222222222222";

fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

/// A host with an identity and a local peer, and a migrated database behind the identity.
fn host(id: &str, name: &str) -> (Host, synra_store::SynraDb) {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    let mut identity = Identity::load(&db, "test", 1_000).expect("an identity");
    // The identity's generated id is a fresh UUID; the tests need known ones, so the row is rewritten.
    identity.device_id = device(id);
    identity.rename(&db, name, 1_000).expect("renames");
    let local = LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        PlatformKind::Desktop,
        "0.1.0-test",
    );
    (Host::with_flags(identity, local, Flags::no_timeout()), db)
}

/// A host that is listening, with its address.
fn listening(id: &str, name: &str) -> (Host, synra_store::SynraDb, SocketAddr) {
    let (mut host, db) = host(id, name);
    let address = host
        .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binds");
    (host, db, address)
}

// ── What the host holds ───────────────────────────────────────────────────────────────────────

#[test]
fn a_new_host_knows_itself_and_nobody_else() {
    let (host, _db) = host(A, "Laptop");
    assert_eq!(host.device_id(), device(A));
    assert_eq!(host.identity().display_name, "Laptop");
    assert!(host.discovery().is_empty());
    assert!(host.sessions().is_empty());
    assert!(host.listener.is_none());
    assert_eq!(host.sent(), 0);
}

#[test]
fn listening_reports_the_port_the_operating_system_chose() {
    // The port is read back rather than assumed: a caller that passed zero asked for any port, and the value it
    // needs is the one that was granted.
    let (mut host, _db) = host(A, "Laptop");
    let bound = host
        .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binds");
    assert_ne!(bound.port(), 0);
    assert!(host.listener.is_some());
}

#[test]
fn an_announcement_heard_over_the_network_becomes_a_candidate() {
    let (mut host, _db) = host(A, "Laptop");
    let announcement = DeviceAnnouncement {
        device_id: device(B),
        display_name: "Phone".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: 47100,
        platform: Some(PlatformKind::Android),
        app_version: Some("0.1.0".to_owned()),
        features: Vec::new(),
    };
    let result = host.heard(&announcement, SocketAddr::from(([10, 0, 0, 5], 5_4321)), 1_000);
    assert_eq!(result, Absorbed::New { device_id: device(B) });
    let candidate = host.discovery().get(device(B)).expect("a candidate");
    assert_eq!(candidate.trust, TrustLevel::Announced);
    assert_eq!(candidate.address.port(), 47100);
    // And it is not yet something the interface offers, because an announcement is a hint and not evidence.
    assert!(host.usable(1_000).is_empty());
}

// ── Two hosts, end to end ─────────────────────────────────────────────────────────────────────

#[test]
fn a_handshake_completes_over_a_conversation_on_two_threads() {
    // ★ The isolated question, with nothing else in it: does `dial` and `accept` complete when each side is on its own
    // thread? The daemon's test of the same path hangs, and this is what separates the handshake from everything the
    // daemon adds around it — a session registry, a discovery table, a listener that had to be set non-blocking.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");

    let accepting = std::thread::spawn(move || {
        server.accept(1_000, |_, _| PairingState::Unknown).map(|(link, _)| link.peer())
    });

    let dialled = client.dial(address, None, 1_000).map(|link| link.peer());
    let accepted = accepting.join().expect("the acceptor finished");

    assert_eq!(dialled.expect("dials"), device(A));
    assert_eq!(accepted.expect("accepts"), device(B));
}

#[test]
fn a_handshake_completes_when_both_sides_are_on_production_flags() {
    // ★ The second isolated question, and the one the daemon's failing test cannot separate: does a handshake still
    // complete when both ends have a **read timeout** on their sockets? `Flags::production` sets one, the daemon's
    // inbound handler sets another, and a deadline that fires *during* a handshake looks exactly like a peer that
    // connected and said nothing — which is the shape of the hang.
    let (mut host_a, _a_db, address) = listening(A, "Laptop");
    let (mut host_b, _b_db) = host(B, "Phone");
    // Both sides as a real pair: one process dials and the other answers, each with the protocol's own deadlines.
    host_a.set_flags(Flags::production());
    host_b.set_flags(Flags::production());

    let serving = std::thread::spawn(move || {
        host_a
            .accept(1_000, |_, _| PairingState::Unknown)
            .map(|(link, _)| link.peer())
    });
    let dialled = host_b
        .dial(address, None, 1_000)
        .map(|link| link.peer());

    assert_eq!(dialled.expect("dials with a production timeout"), device(A));
    assert_eq!(serving.join().expect("finished").expect("accepts"), device(B));
}

#[test]
fn a_non_blocking_listener_still_accepts_a_connection() {
    // ★ The isolated question, with no handshake and no threads: does a non-blocking listener accept a connection at
    // all? Three versions of a daemon test appeared to prove the opposite, and none of them could separate this from
    // the conversation that follows it.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds");
    let address = listener.local_addr().expect("an address");
    listener.set_nonblocking(true).expect("non-blocking");

    // Nothing is waiting yet, which is what makes `try_accept` a poll rather than a block.
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("expected a would-block on an idle listener, got {other:?}"),
    }

    // Somebody connects, and polling finds them.
    let _dialer = TcpStream::connect(address).expect("connects");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // And the mode can be turned back off on the accepted connection, which Windows requires before any
                // ordinary read on it will work.
                stream.set_nonblocking(false).expect("blocking");
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(other) => panic!("unexpected accept error: {other}"),
        }
        assert!(std::time::Instant::now() < deadline, "the connection was never accepted");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn two_hosts_complete_a_handshake_and_record_a_session() {
    // ★ The test this module exists for. Every piece here has its own tests, and what none of those can see is the
    // *order*: the session is created after the handshake, and the trust level rises only once the connection
    // completed.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");

    let serving = std::thread::spawn(move || {
        let (link, events) = server
            .accept(1_000, |_, _| PairingState::Unknown)
            .expect("accepts");
        (link, events, server)
    });

    let link = client.dial(address, None, 1_000).expect("dials");
    let (server_link, events, server) = serving.join().expect("the thread finished");

    // Both sides recorded a session for the other.
    assert_eq!(client.state_of(device(A)), Some(LinkState::Ready));
    assert_eq!(server.state_of(device(B)), Some(LinkState::Ready));
    assert!(events.iter().any(|event| matches!(event, RegistryEvent::Ready(_))));

    // And both links know both identifiers and who is on the other end.
    assert_eq!(client_link_peer(&link), device(A));
    assert_eq!(client_link_local(&link), device(B));
    assert_eq!(server_link.peer(), device(B));
    assert_eq!(server_link.local(), device(A));
}

#[test]
fn the_trust_level_rises_only_after_the_connection_completed() {
    // ★ A datagram is a hint and a connection is evidence. A host that raised the level when the announcement
    // arrived would offer the user a device it has never reached.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");

    let announcement = DeviceAnnouncement {
        device_id: device(A),
        display_name: "Laptop".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: address.port(),
        platform: Some(PlatformKind::Desktop),
        app_version: Some("0.1.0".to_owned()),
        features: Vec::new(),
    };
    client.heard(&announcement, address, 1_000);
    assert_eq!(
        client.discovery().get(device(A)).expect("a candidate").trust,
        TrustLevel::Announced
    );

    let serving = std::thread::spawn(move || {
        server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
    });
    client.dial(address, None, 1_000).expect("dials");
    serving.join().expect("finished");

    let candidate = client.discovery().get(device(A)).expect("a candidate");
    assert_eq!(candidate.trust, TrustLevel::Handshaked);
    // And now it is something the interface offers.
    assert_eq!(client.usable(1_000).len(), 1);
}

#[test]
fn the_recorded_address_is_the_one_the_connection_worked_at() {
    // ★ A handshake that completed proves the address the connection was made to works. Recording the *announced*
    // one instead would leave the next attempt dialling an address the peer has moved away from.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");

    // The announcement claims a port nothing is listening on.
    let announcement = DeviceAnnouncement {
        device_id: device(A),
        display_name: "Laptop".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: 1,
        platform: Some(PlatformKind::Desktop),
        app_version: None,
        features: Vec::new(),
    };
    client.heard(&announcement, address, 1_000);
    assert_eq!(client.discovery().get(device(A)).expect("c").address.port(), 1);

    let serving = std::thread::spawn(move || {
        server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
    });
    client.dial(address, None, 1_000).expect("dials");
    serving.join().expect("finished");

    assert_eq!(
        client.discovery().get(device(A)).expect("c").address.port(),
        address.port(),
        "the working port was not recorded"
    );
}

#[test]
fn an_envelope_travels_between_two_connected_hosts() {
    // The whole path: dial, handshake, session, envelope, and a session recorded on the receiving side.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (client, _client_db) = host(B, "Phone");
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut client = client.with_metrics(Arc::clone(&recorder));

    let serving = std::thread::spawn(move || {
        let (mut link, _) = server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
        let envelope = link.receive().expect("receives");
        (envelope, server)
    });

    let mut link = client.dial(address, None, 1_000).expect("dials");
    let envelope = Envelope::outbound(
        OutboundSpec {
            event: EventName::parse("device.ping").expect("a name"),
            target: device(A),
            from: device(B),
            trace_id: synra_protocol::ids::TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&serde_json::Value>,
    )
    .expect("builds");
    client.send(&mut link, &envelope).expect("sends");

    let (received, server) = serving.join().expect("finished");
    assert_eq!(received.event.as_str(), "device.ping");
    assert_eq!(received.from, device(B));
    assert_eq!(client.sent(), 1);
    // ★ 而同一个事实现在也说得出**说了什么** —— `frames_sent_total{event}`。
    // `sent()` 回答「说了多少」，而排查时要问的是「说了哪一类」。
    assert_eq!(
        recorder.snapshot().get("frames_sent_total{event=device.ping}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the frame was not counted by its event"
    );
    // ★ 而链路本身也是一个事实：`links_opened_total`。客户端的这一条是它拨号时开的，
    // 而 `adopt` 是拨入与接入**共同**经过的地方 —— 所以同一个计数也覆盖服务端那一侧。
    assert_eq!(
        recorder.snapshot().get("links_opened_total"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the client's link was not counted"
    );
    // The receiving host recorded the session too, which is what makes the envelope attributable.
    assert_eq!(server.state_of(device(B)), Some(LinkState::Ready));
}

#[test]
fn text_travels_from_one_host_to_another() {
    // ★ The end-to-end path `synra send` takes: resolve what the user typed, dial the address the kernel knows, and
    // put a clipboard envelope on the link. Every piece has its own tests; what none of those can see is the sequence.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");

    let serving = std::thread::spawn(move || {
        let (mut link, _) = server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
        let envelope = link.receive().expect("receives");
        let payload = envelope.payload.as_ref().expect("a payload").get().to_owned();
        (envelope, payload, server)
    });

    // The client learns about the server the way it would on a network, then resolves it by name.
    let announcement = DeviceAnnouncement {
        device_id: device(A),
        display_name: "Laptop".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: address.port(),
        platform: Some(PlatformKind::Desktop),
        app_version: None,
        features: Vec::new(),
    };
    client.heard(&announcement, address, 1_000);

    // ★ By name, which is what `--to Laptop` does, and the identifier is what it resolves to.
    let resolved = client.resolve("Laptop").expect("resolves");
    assert_eq!(resolved, device(A));
    assert_eq!(client.address_of(resolved), Some(address));

    let envelope = crate::messaging::text_to(
        client.device_id(),
        resolved,
        "hello from the phone",
        synra_protocol::ids::TraceId::new(),
        1_000,
    )
    .expect("builds");

    let mut link = client.dial(address, None, 1_000).expect("dials");
    client.send(&mut link, &envelope).expect("sends");

    let (received, payload, _server) = serving.join().expect("finished");
    assert_eq!(received.event.as_str(), synra_protocol::event::builtin::CLIPBOARD_RECEIVED);
    assert_eq!(received.from, device(B));
    // And the payload is the shape the receiver's own type parses.
    let parsed: crate::messaging::ClipboardText =
        serde_json::from_str(&payload).expect("parses");
    assert_eq!(parsed.text, "hello from the phone");
    assert_eq!(parsed.from_device_id, device(B));
}

#[test]
fn resolving_an_unknown_name_says_so_rather_than_dialling_nothing() {
    let (client, _db) = host(B, "Phone");
    match client.resolve("Nobody") {
        Err(HostError::NoSuchDevice { wanted }) => assert_eq!(wanted, "Nobody"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And an empty string is not a device name either.
    assert!(matches!(client.resolve("   "), Err(HostError::NoSuchDevice { .. })));
}

#[test]
fn resolving_an_ambiguous_name_is_refused_rather_than_guessed() {
    // ★ Picking one would send a message to a device the user did not choose, and the sender would never know: the
    // message would arrive, and it would look deliberate. An identifier is the way to disambiguate.
    let (mut client, _db) = host(B, "Phone");
    for id in [A, "33333333-3333-4333-8333-333333333333"] {
        client.heard(
            &DeviceAnnouncement {
                device_id: device(id),
                display_name: "Laptop".to_owned(),
                protocol: PROTOCOL_VERSION,
                port: 47_100,
                platform: None,
                app_version: None,
                features: Vec::new(),
            },
            SocketAddr::from(([10, 0, 0, 5], 1)),
            1_000,
        );
    }

    match client.resolve("Laptop") {
        Err(HostError::AmbiguousName { name, matches }) => {
            assert_eq!(name, "Laptop");
            assert_eq!(matches, 2);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And the identifier still works, which is what the message tells the user to use.
    assert_eq!(client.resolve(A).expect("resolves"), device(A));
}

#[test]
fn an_identifier_wins_over_a_name_that_happens_to_match_it() {
    // ★ An identifier is unambiguous by construction and a name is whatever the other device decided to call itself.
    // Checking identifiers first means a user who pasted an id gets the device they pasted rather than a device that
    // renamed itself to match.
    let (mut client, _db) = host(B, "Phone");
    client.heard(
        &DeviceAnnouncement {
            // A device whose *name* is another device's identifier.
            device_id: device("33333333-3333-4333-8333-333333333333"),
            display_name: A.to_owned(),
            protocol: PROTOCOL_VERSION,
            port: 47_100,
            platform: None,
            app_version: None,
            features: Vec::new(),
        },
        SocketAddr::from(([10, 0, 0, 5], 1)),
        1_000,
    );
    client.heard(
        &DeviceAnnouncement {
            device_id: device(A),
            display_name: "Real".to_owned(),
            protocol: PROTOCOL_VERSION,
            port: 47_100,
            platform: None,
            app_version: None,
            features: Vec::new(),
        },
        SocketAddr::from(([10, 0, 0, 6], 1)),
        1_000,
    );

    assert_eq!(client.resolve(A).expect("resolves"), device(A));
    // Case-insensitively too, because a user pasting a UUID may have a different case and nothing else it could mean.
    assert_eq!(client.resolve(&A.to_uppercase()).expect("resolves"), device(A));
}

#[test]
fn sending_on_a_link_the_host_has_no_session_for_is_refused() {
    // ★ A caller holding a link and a host that do not belong together is the case this refuses. Attributing an
    // envelope to the wrong session is a mistake with no symptom until the wrong device is blamed for something.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");
    let (mut other, _other_db) = host(
        "33333333-3333-4333-8333-333333333333",
        "Tablet",
    );

    let serving = std::thread::spawn(move || {
        server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
    });
    let mut link = client.dial(address, None, 1_000).expect("dials");
    serving.join().expect("finished");

    // `other` has no session with A, so it will not send on a link that belongs to `client`.
    let envelope = Envelope::outbound(
        OutboundSpec {
            event: EventName::parse("device.ping").expect("a name"),
            target: device(A),
            from: other.device_id(),
            trace_id: synra_protocol::ids::TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&serde_json::Value>,
    )
    .expect("builds");

    match other.send(&mut link, &envelope) {
        Err(HostError::NoSession(id)) => assert_eq!(id, device(A)),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_host_that_is_not_listening_cannot_accept() {
    // An honest refusal rather than a silent hang: a caller that forgot to listen is one waiting for a connection
    // that cannot come.
    let (mut host, _db) = host(A, "Laptop");
    match host.accept(1_000, |_, _| PairingState::Unknown) {
        Err(HostError::Bind { why, .. }) => assert!(why.contains("not listening"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── Expiry and sweeping ───────────────────────────────────────────────────────────────────────

#[test]
fn a_host_expires_candidates_and_reports_what_went() {
    let (mut host, _db) = host(A, "Laptop");
    let announcement = DeviceAnnouncement {
        device_id: device(B),
        display_name: "Phone".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: 47100,
        platform: None,
        app_version: None,
        features: Vec::new(),
    };
    host.heard(&announcement, SocketAddr::from(([10, 0, 0, 5], 1)), 0);

    // The default lifetime is 90 seconds, so an hour later it is long gone.
    let expired = host.expire(3_600_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].device_id, device(B));
    assert!(host.discovery().is_empty());
}

#[test]
fn sweeping_closes_a_session_whose_peer_went_quiet() {
    // The host's own sweep, through the registry — which is what makes a device that was unplugged disappear from
    // the list rather than staying selectable.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");
    // ★ The registry's timeout is set on the **client** before the session is opened, not after it exists: the first
    // version replaced the whole registry once the session was there, which discarded the very session the test then
    // swept for — so the sweep correctly found nothing and the assertion was about a fixture that had deleted its
    // own subject.
    client.sessions = SessionRegistry::with_heartbeat_timeout(1_000);

    let serving = std::thread::spawn(move || {
        server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
    });
    client.dial(address, None, 1_000).expect("dials");
    serving.join().expect("finished");

    // The session was opened at 1_000 with a one-second timeout, so at 5_000 it is long overdue.
    let events = client.sweep(5_000);
    assert!(!events.is_empty(), "the sweep closed nothing");
    assert!(client.state_of(device(A)).expect("a session").is_over());
}

#[test]
fn the_debug_form_names_what_the_host_holds() {
    // A host appears in a log line, and a handle that printed its socket would leak the path.
    let (host, _db) = host(A, "Laptop");
    let text = format!("{host:?}");
    assert!(text.contains("Laptop"), "{text}");
    assert!(text.contains("candidates"), "{text}");
    assert!(text.contains("listening"), "{text}");
}

#[test]
fn a_shared_host_can_be_reached_from_two_threads() {
    // The type's reason for existing: an accept loop and a caller are two threads over one host.
    let (host, _db) = host(A, "Laptop");
    let shared = shared(host);
    let cloned = Arc::clone(&shared);
    let handle = std::thread::spawn(move || cloned.lock().device_id());
    let from_thread = handle.join().expect("finished");
    assert_eq!(from_thread, device(A));
    assert_eq!(shared.lock().device_id(), device(A));
}

#[test]
fn the_clock_conversion_saturates_rather_than_wrapping() {
    // A `u64` beyond `i64::MAX` is a reading from a clock nobody has, and a cast would produce a negative time —
    // which the discovery table would read as "seen in the future".
    assert_eq!(millis_reading(0), 0);
    assert_eq!(millis_reading(1_000), 1_000);
    assert_eq!(millis_reading(u64::MAX), i64::MAX);
}

#[test]
fn the_other_direction_saturates_too() {
    // The pair to the test above, and the reason it exists: a negative reading is a clock before the epoch, and a cast
    // would turn it into a deadline in the far future — a session that never expires.
    assert_eq!(reading_millis(0), 0);
    assert_eq!(reading_millis(1_000), 1_000);
    assert_eq!(reading_millis(-1), 0);
    assert_eq!(reading_millis(i64::MIN), 0);
}

#[test]
fn the_two_directions_agree_on_every_reading_they_can_both_hold() {
    // A round trip is the property that matters, and it is the one a duplicated saturation rule breaks silently: two
    // copies can each look right and disagree only in the case neither was written for.
    for value in [0u64, 1, 1_000, 1_700_000_000_000, i64::MAX as u64] {
        assert_eq!(reading_millis(millis_reading(value)), value, "round trip of {value}");
    }
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        HostError::Bind { address: SocketAddr::from(([0, 0, 0, 0], 0)), why: "in use".to_owned() },
        HostError::Handshake(HandshakeError::Closed),
        HostError::Link(LinkError::Closed),
        HostError::Incompatible { missing: "[TransferResume]".to_owned() },
        HostError::NoSession(device(A)),
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

// ── Helpers for the link assertions ───────────────────────────────────────────────────────────

fn client_link_peer(link: &PeerLink) -> DeviceId {
    link.peer()
}

fn client_link_local(link: &PeerLink) -> DeviceId {
    link.local()
}

#[test]
fn a_table_with_a_chosen_lifetime_is_what_a_test_needs() {
    // The discovery table's lifetime is a value rather than a constant, which is what lets the expiry tests above
    // run without waiting ninety seconds.
    let table = DiscoveryTable::with_ttl(device(A), std::time::Duration::from_millis(10));
    assert_eq!(table.ttl(), std::time::Duration::from_millis(10));
}

// ── Renaming ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_rename_reaches_the_name_that_goes_into_a_handshake() {
    let (mut host, _db) = host(A, "Old name");
    host.rename_self("Kitchen tablet").expect("a rename");

    // Both copies, because the fault this method exists to prevent is one copy being updated and the other not — and
    // asserting on only the visible one is how that fault gets reintroduced.
    assert_eq!(host.identity().display_name, "Kitchen tablet", "the stored identity");
    assert_eq!(host.announced_name(), "Kitchen tablet", "the announced name");
}

#[test]
fn a_refused_rename_leaves_both_copies_untouched() {
    let (mut host, _db) = host(A, "Old name");
    let error = host.rename_self("   ").expect_err("a blank name");
    assert!(matches!(error, HostError::Unnameable { .. }));
    assert_eq!(host.identity().display_name, "Old name", "the stored identity");
    assert_eq!(host.announced_name(), "Old name", "the announced name");
}

#[test]
fn a_name_the_kernel_refuses_changes_nothing() {
    // ★ Refused by `check_display_name`, not by a rule of this module's own.
    //
    // The host and the identity must agree on what a name is; a host with its own stricter rule would accept a rename
    // the identity refuses, or the reverse, and the two copies would then disagree — which is the fault `rename_self`
    // exists to remove. So the cases below are the kernel's cases, not this test's.
    let (mut host, _db) = host(A, "Old name");
    let too_long = "a".repeat(crate::identity::MAX_DISPLAY_NAME_LEN + 1);
    for name in ["", "   ", &too_long, "with\nnewline"] {
        assert!(host.rename_self(name).is_err(), "{name:?} is not a name");
    }
    assert_eq!(host.announced_name(), "Old name", "nothing was half-applied");
}

#[test]
fn a_padded_name_lands_in_both_copies_trimmed_and_identically() {
    // ★ The trim, checked on both copies.
    //
    // `check_display_name` trims before it validates, so `" padded "` is a name whose checked form is `"padded"`.
    // `Identity::rename` stores the checked form; if `rename_self` stored what it was handed, the host would announce
    // `" padded "` and the identity would report `"padded"` — two devices disagreeing about this one's name, which is
    // the fault this method exists to prevent.
    let (mut host, _db) = host(A, "Old name");
    host.rename_self(" padded ").expect("a name of padding is a name");
    assert_eq!(host.announced_name(), "padded", "the announced name is the checked one");
    assert_eq!(host.identity().display_name, "padded", "and so is the stored one");
}

#[test]
fn the_refusal_echoes_only_enough_of_the_name_to_recognise_it() {
    // A user can paste four hundred characters of emoji; a log line that carries all of it is a problem of its own.
    let long = "🎉".repeat(400);
    let error = host(A, "Old name").0.rename_self(&long).expect_err("not a name");
    let echoed = match error {
        HostError::Unnameable { name } => name,
        other => panic!("expected a refusal, got {other}"),
    };
    assert!(
        echoed.chars().count() <= 24,
        "the echo is {} characters, not a bounded prefix",
        echoed.chars().count()
    );
}


#[test]
fn a_received_frame_is_counted_by_its_event() {
    // ★ 这条测的是 `Host::count_frame_received` **本身**，而不是「它被调用过」。
    //
    // 2026-10-19 起，帧计数搬到了 `PeerLink`：它见到**每一帧**，包括拨号链路上绕过 Host 写出的那些。所以这条
    // 测试现在钉的是 Host 自己的方法（壳的接线测试用它证明记录器接上了），而不是生产路径 —— 生产路径的断言在
    // `link.rs` 的 `a_link_with_a_recorder_counts_the_frames_it_moves` 里，同时覆盖收与发两个方向。
    let (host, _db) = host(A, "Laptop");
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut host = host.with_metrics(Arc::clone(&recorder));

    host.count_frame_received("device.ping");

    assert_eq!(
        recorder
            .snapshot()
            .get("frames_received_total{event=device.ping}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the frame was not counted by its event"
    );
    // ★ 而它记的是**接收**那一侧而不是发送：两个方向是分开的方法，
    // 因为「说得比听到的多」与「听到的比说得多」是两种不同的处境。
    assert_eq!(
        recorder.snapshot().get("frames_sent_total{event=device.ping}"),
        None,
        "receiving counted as sending"
    );
}
