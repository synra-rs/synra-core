use std::net::SocketAddr;
use std::sync::Arc;
use crate::link::LinkError;
use crate::peer::HandshakeError;
use crate::sessions::SessionRegistry;
use super::super::{HostError, millis_reading, reading_millis, shared};
use super::{A, B, device, host, network_now, listening};

#[test]
fn a_host_that_is_not_listening_cannot_accept() {
    // An honest refusal rather than a silent hang: a caller that forgot to listen is one waiting for a connection
    // that cannot come.
    let (mut host, _db) = host(A, "Laptop");
    match host.accept(network_now()) {
        Err(HostError::Bind { why, .. }) => assert!(why.contains("not listening"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
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
        server.accept(network_now()).expect("accepts");
    });
    client
        .dial(address, device(A), network_now())
        .expect("dials");
    serving.join().expect("finished");

    // Advance the explicit session clock beyond its one-second timeout without sleeping.
    let events = client.sweep(network_now() + 4_000);
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
        assert_eq!(
            reading_millis(millis_reading(value)),
            value,
            "round trip of {value}"
        );
    }
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        HostError::Bind {
            address: SocketAddr::from(([0, 0, 0, 0], 0)),
            why: "in use".to_owned(),
        },
        HostError::Handshake(HandshakeError::Closed),
        HostError::Link(LinkError::Closed),
        HostError::Incompatible {
            missing: "[TransferResume]".to_owned(),
        },
        HostError::NoSession(device(A)),
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
