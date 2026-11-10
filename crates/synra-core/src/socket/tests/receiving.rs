use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use synra_protocol::discovery::OfflineAnnouncement;
use crate::discovery::Absorbed;
use crate::test_support::{announcement, device, host};
use super::super::SocketError;
use super::{A, B, loopback};

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
