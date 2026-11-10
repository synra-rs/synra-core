use std::net::{Ipv4Addr, TcpListener, TcpStream};
use synra_protocol::discovery::{DeviceAnnouncement, TrustLevel};
use synra_protocol::handshake::PROTOCOL_VERSION;
use synra_protocol::session::PlatformKind;
use crate::peer::Flags;
use crate::sessions::{LinkState, RegistryEvent};
use super::{A, B, device, host, network_now, listening, client_link_peer, client_link_local};

#[test]
fn a_handshake_completes_over_a_conversation_on_two_threads() {
    // ★ The isolated question, with nothing else in it: does `dial` and `accept` complete when each side is on its own
    // thread? The daemon's test of the same path hangs, and this is what separates the handshake from everything the
    // daemon adds around it — a session registry, a discovery table, a listener that had to be set non-blocking.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");

    let accepting =
        std::thread::spawn(move || server.accept(network_now()).map(|(link, _)| link.peer()));

    let dialled = client
        .dial(address, device(A), network_now())
        .map(|link| link.peer());
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

    let serving =
        std::thread::spawn(move || host_a.accept(network_now()).map(|(link, _)| link.peer()));
    let dialled = host_b
        .dial(address, device(A), network_now())
        .map(|link| link.peer());

    assert_eq!(dialled.expect("dials with a production timeout"), device(A));
    assert_eq!(
        serving.join().expect("finished").expect("accepts"),
        device(B)
    );
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
        assert!(
            std::time::Instant::now() < deadline,
            "the connection was never accepted"
        );
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
        let (link, events) = server.accept(network_now()).expect("accepts");
        (link, events, server)
    });

    let link = client
        .dial(address, device(A), network_now())
        .expect("dials");
    let (server_link, events, server) = serving.join().expect("the thread finished");

    // Both sides recorded a session for the other.
    assert_eq!(client.state_of(device(A)), Some(LinkState::Ready));
    assert_eq!(server.state_of(device(B)), Some(LinkState::Ready));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, RegistryEvent::Ready(_)))
    );

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
        client
            .discovery()
            .get(device(A))
            .expect("a candidate")
            .trust,
        TrustLevel::Announced
    );

    let serving = std::thread::spawn(move || {
        server.accept(network_now()).expect("accepts");
    });
    client
        .dial(address, device(A), network_now())
        .expect("dials");
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
    assert_eq!(
        client.discovery().get(device(A)).expect("c").address.port(),
        1
    );

    let serving = std::thread::spawn(move || {
        server.accept(network_now()).expect("accepts");
    });
    client
        .dial(address, device(A), network_now())
        .expect("dials");
    serving.join().expect("finished");

    assert_eq!(
        client.discovery().get(device(A)).expect("c").address.port(),
        address.port(),
        "the working port was not recorded"
    );
}
