use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use super::super::{
    HostFacts, ProbeStatus, probe_firewall_hint, probe_network_interfaces, probe_port_available,
    probe_udp_port_available,
};
use super::hosts;

#[test]
fn a_free_port_passes() {
    // Port zero asks the operating system for any free port, so this cannot fail for the reason under test.
    let result = probe_port_available("tcp_port_available", 0);
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
    assert!(result.detail.contains("free"));
}

#[test]
fn a_port_already_held_fails_with_advice() {
    // The failure a user actually hits: another copy of the application, or something else on the port.
    //
    // Bound to the wildcard address, because that is what the probe binds and what the real listener binds.
    // A holder on `127.0.0.1` alone does *not* conflict with a listener on `0.0.0.0` — the two can coexist
    // — so a test that used the loopback address would assert something the probe is right not to detect.
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .expect("binds an ephemeral port");
    let port = listener.local_addr().expect("has an address").port();

    let result = probe_port_available("tcp_port_available", port);
    assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
    assert!(result.suggestion.is_some());
    assert!(result.detail.contains(&port.to_string()));
    drop(listener);
}

#[test]
fn a_held_udp_port_fails_separately_from_tcp() {
    // Discovery is the feature that breaks when it is taken, and a process holding the UDP port does not
    // appear in the TCP probe.
    // The wildcard address again, for the same reason as the TCP case.
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .expect("binds an ephemeral port");
    let port = socket.local_addr().expect("has an address").port();

    let result = probe_udp_port_available(port);
    assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
    assert_eq!(result.name, "discovery_udp_available");
    drop(socket);
}

#[test]
fn the_network_stack_is_present_in_a_test_process() {
    // If this fails, the machine has no loopback, which is the case the probe exists to catch.
    let result = probe_network_interfaces();
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
}

#[test]
fn a_firewall_hint_is_a_warning_with_advice() {
    let host = HostFacts {
        firewall_hint: Some("Windows Defender may be blocking inbound connections".to_owned()),
        ..hosts()
    };
    let result = probe_firewall_hint(&host);
    assert_eq!(result.status, ProbeStatus::Warn);
    assert!(result.detail.contains("Windows Defender"));
    assert!(result.suggestion.is_some());
}

#[test]
fn no_firewall_hint_is_not_a_problem() {
    assert_eq!(probe_firewall_hint(&hosts()).status, ProbeStatus::Ok);
}
