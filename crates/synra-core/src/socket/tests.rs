use super::*;
use crate::discovery::Absorbed;
use crate::host::Host;
use crate::identity::Identity;
use crate::peer::{Flags, LocalPeer};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use synra_protocol::handshake::PROTOCOL_VERSION;
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

const A: &str = "11111111-1111-4111-8111-111111111111";
const B: &str = "22222222-2222-4222-8222-222222222222";

fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

fn host(id: &str, name: &str) -> Host {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db.create_identity_if_absent(
        &synra_store::IdentityRow::from_columns(Some(id), Some(name), Some("test"), Some(1_000))
            .expect("identity row"),
    )
    .expect("initial identity");
    let identity = Identity::load(&db, "test", 1_000).expect("an identity");
    let local = LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        PlatformKind::Desktop,
        "0.1.0-test",
    );
    Host::with_flags(identity, local, Flags::no_timeout())
}

fn announcement(id: &str, name: &str, port: u16) -> DeviceAnnouncement {
    DeviceAnnouncement {
        device_id: device(id),
        display_name: name.to_owned(),
        protocol: PROTOCOL_VERSION,
        port,
        platform: Some(PlatformKind::Desktop),
        app_version: Some("0.1.0".to_owned()),
        features: Vec::new(),
    }
}

/// A socket on a port the operating system chose, so a test never collides with a running kernel.
fn loopback() -> DiscoverySocket {
    DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("binds")
}

// ── The socket itself ─────────────────────────────────────────────────────────────────────────

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

// ── Receiving into a host ─────────────────────────────────────────────────────────────────────

#[test]
fn a_received_query_becomes_a_candidate_on_the_receiving_host() {
    // The whole point of the layer: bytes on a socket become something the kernel knows about.
    let sender = loopback();
    let receiver = loopback();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    sender
        .send_query(
            &announcement(B, "Phone", 47101),
            receiver.local_addr().expect("an address"),
        )
        .expect("sends");

    let mut kernel = host(A, "Laptop");
    let absorbed = receiver
        .receive(&mut kernel, 5_000)
        .expect("receives")
        .expect("something about another device");

    assert_eq!(
        absorbed,
        Absorbed::New {
            device_id: device(B)
        }
    );
    let candidate = kernel.discovery().get(device(B)).expect("a candidate");
    assert_eq!(candidate.display_name, "Phone");
    // ★ The port is the one the peer said it listens on for **connections** — 47101 — and not the port the datagram
    // came from, which is ephemeral. Mixing them is the bug the protocol's own `announced_address` prevents.
    assert_eq!(candidate.address.port(), 47101);
}

#[test]
fn a_datagram_about_this_device_is_not_news() {
    // ★ A device hears its own broadcasts, because that is what broadcasting means. Reporting one as a candidate
    // would show the user their own machine as a peer.
    let sender = loopback();
    let receiver = loopback();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    sender
        .send_query(
            &announcement(A, "Laptop", 47100),
            receiver.local_addr().expect("an address"),
        )
        .expect("sends");

    let mut kernel = host(A, "Laptop");
    let absorbed = receiver.receive(&mut kernel, 5_000).expect("receives");
    // `absorb` reports it, and the host's own self-check discarded it — which is the same answer the discovery
    // table's tests assert, reached over a real socket.
    assert_eq!(absorbed, Some(Absorbed::SelfAnnouncement));
    assert!(kernel.discovery().is_empty());
}

#[test]
fn a_goodbye_ages_the_entry_out_rather_than_refreshing_it() {
    // ★ Treating a goodbye as news about where a device is would refresh the entry the device just asked to have
    // aged out — the opposite of what it said.
    let sender = loopback();
    let receiver = loopback();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    let mut kernel = host(A, "Laptop");
    kernel.heard(
        &announcement(B, "Phone", 47101),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1234)),
        1_000,
    );
    assert_eq!(kernel.discovery().len(), 1);

    sender
        .send_offline(
            &OfflineAnnouncement {
                device_id: device(B),
                timestamp: 5_000,
            },
            receiver.local_addr().expect("an address"),
        )
        .expect("sends");

    let absorbed = receiver.receive(&mut kernel, 5_000).expect("receives");
    assert_eq!(
        absorbed,
        Some(Absorbed::Offline {
            device_id: device(B)
        })
    );
    // The entry is still there — "it left" and "it was never here" are different — but it is no longer current.
    assert_eq!(kernel.discovery().len(), 1);
    assert_eq!(kernel.discovery().current(5_000).count(), 0);
}

#[test]
fn a_stray_packet_on_the_port_is_reported_as_malformed() {
    // ★ A well-known port is sent to by anything: a port scan, another product's discovery, a stray packet. A
    // datagram this build does not understand is *reported*, so a caller can count it — and it must not be confused
    // with a device that said something wrong.
    let sender = loopback();
    let receiver = loopback();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    sender
        .send_bytes(
            b"hello? is anyone there",
            receiver.local_addr().expect("an address"),
        )
        .expect("sends");

    let mut kernel = host(A, "Laptop");
    match receiver.receive(&mut kernel, 5_000) {
        Err(SocketError::Malformed { .. }) => {}
        other => panic!("expected a malformed datagram, got {other:?}"),
    }
    // And nothing was added to the host.
    assert!(kernel.discovery().is_empty());
}

#[test]
fn a_receive_that_times_out_is_reported_as_a_receive_failure() {
    // A caller that set a timeout asked for one and has to be able to tell it from a socket that broke. A scan
    // treats both the same; a caller reading one datagram at a time does not.
    let socket = loopback();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("a timeout");

    let mut kernel = host(A, "Laptop");
    match socket.receive(&mut kernel, 5_000) {
        Err(SocketError::Receive { .. }) => {}
        other => panic!("expected a timeout, got {other:?}"),
    }
}

// ── Scanning ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_scan_stops_at_its_deadline_and_returns_what_it_heard() {
    // The budget is what keeps "scanning" from being forever in the interface.
    let socket = loopback();
    let mut kernel = host(A, "Laptop");
    let started = Instant::now();
    let results = socket.scan_until(&mut kernel, 5_000, started + Duration::from_millis(120));
    assert!(
        results.is_empty(),
        "something answered a loopback port nothing is sending to"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(100),
        "the scan returned early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the scan overran its budget: {elapsed:?}"
    );
}

#[test]
fn a_scan_collects_a_query_that_arrives_while_it_runs() {
    // The realistic case: a scan is a wait, and a device that answers during the wait is found.
    let receiver = loopback();
    let target = receiver.local_addr().expect("an address");
    let sender = loopback();

    let sending = std::thread::spawn(move || {
        // Long enough for the scan to have started waiting, short enough to be inside its budget.
        std::thread::sleep(Duration::from_millis(40));
        sender
            .send_query(&announcement(B, "Phone", 47101), target)
            .expect("sends");
    });

    let mut kernel = host(A, "Laptop");
    let results = receiver.scan_until(
        &mut kernel,
        5_000,
        Instant::now() + Duration::from_millis(400),
    );
    sending.join().expect("finished");

    assert_eq!(
        results,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    assert!(kernel.discovery().get(device(B)).is_some());
}

// ── The addresses ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_limited_broadcast_address_is_always_asked() {
    // ★ It is the one address that needs no knowledge of the machine's interfaces, and a device on a network this
    // code cannot enumerate — a virtual adapter, a VPN, a container bridge — is reachable through it and not through
    // any computed address.
    let addresses = broadcast_addresses();
    assert!(
        addresses.contains(&SocketAddr::from((
            Ipv4Addr::BROADCAST,
            limits::DISCOVERY_PORT
        ))),
        "{addresses:?}"
    );
}

#[test]
fn every_broadcast_address_uses_the_discovery_port() {
    // A query sent to the right address on the wrong port reaches nothing, and nothing would say why.
    for address in broadcast_addresses() {
        assert_eq!(address.port(), limits::DISCOVERY_PORT, "{address}");
    }
}

#[test]
fn broadcast_destinations_are_unique() {
    let addresses = broadcast_addresses();
    let unique: std::collections::BTreeSet<_> = addresses.iter().collect();
    assert_eq!(unique.len(), addresses.len());
}

#[test]
fn a_broadcast_query_reports_what_it_reached_per_address() {
    // "Nothing was found" and "nothing could be asked" are different answers, and a caller that showed the user an
    // empty list for both would be one that cannot tell them their firewall is the problem. Each address gets its
    // own result rather than one overall verdict.
    let socket = loopback();
    let results = socket.broadcast_query(&announcement(A, "Laptop", 47100));
    assert_eq!(
        results.len(),
        1,
        "loopback cannot send on external interfaces"
    );
    // The ports are all the discovery port, whatever the sends returned — a build machine may have no route, and an
    // error is a legitimate outcome the caller has to be able to see.
    for (address, result) in &results {
        assert_eq!(address.port(), limits::DISCOVERY_PORT);
        if let Err(error) = result {
            assert!(!error.to_string().is_empty());
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_error_explains_itself() {
    let errors = [
        SocketError::Bind {
            address: SocketAddr::from(([0, 0, 0, 0], 32101)),
            why: "in use".to_owned(),
        },
        SocketError::Send {
            address: SocketAddr::from(([255, 255, 255, 255], 32101)),
            why: "no route".to_owned(),
        },
        SocketError::Receive {
            why: "timed out".to_owned(),
        },
        SocketError::Malformed {
            why: "not utf8".to_owned(),
        },
        SocketError::Encode {
            why: "name too long".to_owned(),
        },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And a bind failure names the address, because "already in use" leaves a user with nothing to act on.
    assert!(errors[0].to_string().contains("32101"), "{}", errors[0]);
}
