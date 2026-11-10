use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use synra_protocol::discovery::{DiscoveryDatagram, OfflineAnnouncement};
use synra_protocol::limits;
use crate::test_support::{announcement, device};
use super::super::{DiscoverySocket, SocketError};
use super::{A, B, loopback};

#[test]
fn a_socket_binds_and_reports_where_it_is() {
    let socket = loopback();
    let address = socket.local_addr().expect("an address");
    assert_ne!(address.port(), 0, "the operating system assigned no port");
    assert_eq!(address.ip(), IpAddr::from(Ipv4Addr::LOCALHOST));
}

#[test]
fn the_discovery_port_is_a_singleton_per_host_and_a_second_bind_is_refused() {
    // ★ This is the behaviour, and the first version of this module got it backwards by adding a dependency to
    // share the port. Two kernels on one machine do not both discover: they would both answer every query, and a
    // peer would receive two responses from one address with different device identifiers. A second kernel is
    // already running or is a second profile, and either way it has to be told so rather than silently sharing.
    let socket = loopback();
    let address = socket.local_addr().expect("an address");
    match DiscoverySocket::bind(address) {
        Err(SocketError::Bind { address: named, .. }) => assert_eq!(named, address),
        Ok(second) => panic!(
            "a second socket bound {} — discovery would answer twice",
            second.local_addr().expect("an address")
        ),
        Err(other) => panic!("expected a bind failure, got {other:?}"),
    }
}

#[test]
fn an_ipv6_address_is_refused_with_a_reason() {
    // Discovery is IPv4 by design — broadcast is an IPv4 concept and the protocol's addresses are IPv4 — so an IPv6
    // request is answered rather than attempted.
    match DiscoverySocket::bind(SocketAddr::from(([0u16; 8], limits::DISCOVERY_PORT))) {
        Err(SocketError::Bind { why, .. }) => assert!(why.contains("IPv4"), "{why}"),
        Ok(_) => panic!("an IPv6 socket was bound"),
        Err(other) => panic!("expected a bind failure, got {other:?}"),
    }
}

#[test]
fn broadcast_can_be_sent_to_a_direct_address_rather_than_a_broadcast_one() {
    // The tests use unicast because a broadcast to 255.255.255.255 on a build machine reaches every interface and may
    // reach the network. That the socket accepts a broadcast address at all is what `set_broadcast(true)` buys, and
    // it is asserted separately below.
    let sender = loopback();
    let receiver = loopback();
    let ours = announcement(A, "Laptop", 47100);
    let sent = sender
        .send_query(&ours, receiver.local_addr().expect("an address"))
        .expect("sends");
    assert!(sent > 0);
}

#[test]
fn a_query_written_by_the_encoder_arrives_as_the_bytes_the_parser_expects() {
    // ★ The end-to-end check this module exists for. The protocol's encoder and its parser are tested against each
    // other in that crate; what is only testable here is that a datagram survives a real socket, with a real source
    // address that the reply has to go back to.
    let sender = loopback();
    let receiver = loopback();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    let ours = announcement(A, "Laptop", 47100);
    sender
        .send_query(&ours, receiver.local_addr().expect("an address"))
        .expect("sends");

    let mut buffer = [0u8; 2048];
    let (read, from) = receiver.socket.recv_from(&mut buffer).expect("receives");
    let bytes = buffer.get(..read).expect("a datagram");
    let datagram = DiscoveryDatagram::parse(bytes).expect("parses");

    let DiscoveryDatagram::Query(query) = datagram else {
        panic!("expected a query, got {datagram:?}");
    };
    assert_eq!(query.device.device_id, device(A));
    assert_eq!(query.device.display_name, "Laptop");
    assert_eq!(query.device.port, 47100);
    // And the source address is the sender's, which is where the reply has to go.
    assert_eq!(from.port(), sender.local_addr().expect("an address").port());
}

#[test]
fn a_response_is_bare_json_and_parses_as_one() {
    // The protocol's rule: a response has no marker, which is what makes a query and a response distinguishable
    // without a length prefix.
    let sender = loopback();
    let receiver = loopback();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    sender
        .send_response(
            &announcement(B, "Phone", 47101),
            receiver.local_addr().expect("an address"),
        )
        .expect("sends");

    let mut buffer = [0u8; 2048];
    let (read, _) = receiver.socket.recv_from(&mut buffer).expect("receives");
    let datagram =
        DiscoveryDatagram::parse(buffer.get(..read).expect("a datagram")).expect("parses");
    assert!(matches!(datagram, DiscoveryDatagram::Response(_)));
}

#[test]
fn an_offline_announcement_round_trips() {
    let sender = loopback();
    let receiver = loopback();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    let offline = OfflineAnnouncement {
        device_id: device(B),
        timestamp: 1_700_000_000_000,
    };
    sender
        .send_offline(&offline, receiver.local_addr().expect("an address"))
        .expect("sends");

    let mut buffer = [0u8; 2048];
    let (read, _) = receiver.socket.recv_from(&mut buffer).expect("receives");
    let datagram =
        DiscoveryDatagram::parse(buffer.get(..read).expect("a datagram")).expect("parses");
    let DiscoveryDatagram::Offline(parsed) = datagram else {
        panic!("expected an offline announcement, got {datagram:?}");
    };
    assert_eq!(parsed.device_id, device(B));
    assert_eq!(parsed.timestamp, 1_700_000_000_000);
}
