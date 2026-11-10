use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use crate::discovery::Absorbed;
use crate::socket::DiscoverySocket;
use super::{A, B, announcement, device, host, service};

#[test]
fn the_responder_and_the_querier_are_different_sockets() {
    // ★ A reply is unicast back to **the address the query came from**. A device that queried from the well-known
    // port would have every answer arrive on the socket it shares with every other device on the machine — so the
    // two are separate, and this is the assertion that keeps them so.
    let service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let querier = service.querier_address().expect("an address");
    assert_ne!(responder.port(), querier.port());
    assert_ne!(responder.port(), 0);
    assert_ne!(querier.port(), 0);
}

#[test]
fn a_query_arriving_on_the_responder_becomes_a_candidate() {
    // The whole point: a device asks, and this kernel learns it exists. The answer is the caller's to send, because
    // it needs this device's own announcement.
    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");

    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    let candidate = kernel.discovery().get(device(B)).expect("a candidate");
    assert_eq!(candidate.display_name, "Phone");
    // The connection port, not the port the query came from.
    assert_eq!(candidate.address.port(), 47_101);
}

#[test]
fn an_answer_arriving_on_the_querier_becomes_a_candidate_too() {
    // ★ An answer is news about a device in exactly the way a query is. A service that only read the responder would
    // find only devices that happened to ask *it*, which is not discovery — it is waiting to be asked.
    let mut service = service(A, Duration::from_secs(60));
    let querier = service.querier_address().expect("an address");
    let mut kernel = host(A, "Laptop");

    let answerer =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an answerer");
    answerer
        .send_response(&announcement(B, "Phone", 47_101), querier)
        .expect("answers");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
}

#[test]
fn this_devices_own_broadcast_is_not_a_candidate() {
    // A device hears its own broadcast because that is what broadcasting means, and a table that counted it would
    // show the user their own machine as a peer.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    // Several ticks, because the querier is not connected to the responder and the broadcast goes to the broadcast
    // address rather than to this socket — so what is asserted is that nothing about this device ever appears.
    for i in 0..3 {
        service.tick(&mut kernel, 5_000 + i, Instant::now(), 0);
    }
    assert!(kernel.discovery().get(device(A)).is_none());
}

#[test]
fn a_datagram_that_is_not_an_announcement_ends_the_drain_without_a_fault() {
    // A well-known port is sent to by anything. A stray packet ends this pass and is not reported as a fault, because
    // a scan that failed because a printer answered would be one that fails on a real network.
    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");

    let stray = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a stray");
    stray
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("a real one first");
    // Then something that is not this protocol at all.
    let raw = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a raw socket");
    raw.send_to(b"not a synra datagram", responder)
        .expect("sends");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    // The good one was absorbed; the stray one stopped the drain rather than being reported.
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    assert!(ticked.errors.is_empty(), "{:?}", ticked.errors);
}
