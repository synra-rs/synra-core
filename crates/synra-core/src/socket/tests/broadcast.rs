use std::net::{Ipv4Addr, SocketAddr};
use synra_protocol::limits;
use crate::test_support::announcement;
use super::super::broadcast_addresses;
use super::{A, loopback};

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
