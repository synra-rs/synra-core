use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use crate::discovery::Absorbed;
use crate::socket::DiscoverySocket;
use super::{A, B, device, host, service};

#[test]
fn a_timeout_on_a_read_is_not_reported_as_a_fault() {
    // ★ Windows reports a socket read timeout as `WSAETIMEDOUT` (10060) rather than as a would-block, so a drain that
    // treated it as an error would return before it had read anything — which is what made this look like a responder
    // that never answered. A quiet tick reports no trouble, and that is asserted rather than assumed.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    for i in 0..3 {
        let ticked = service.tick(&mut kernel, 5_000 + i, Instant::now(), 0);
        assert!(ticked.errors.is_empty(), "{:?}", ticked.errors);
    }
}

#[test]
fn an_answer_reaches_the_device_that_asked() {
    // ★ The answer goes back to the address the query came from, because that is what the protocol says and because a
    // device cannot be found otherwise: it broadcasts from wherever it broadcasts, and only that address can receive.
    let service = service(A, Duration::from_secs(60));
    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    let sent = service
        .answer(asker.local_addr().expect("an address"))
        .expect("answers");
    assert!(sent > 0);

    // The asker reads it as a response carrying the answerer's own announcement.
    let mut kernel = host(B, "Phone");
    let absorbed = asker.receive(&mut kernel, 5_000).expect("receives");
    assert_eq!(
        absorbed,
        Some(Absorbed::New {
            device_id: device(A)
        })
    );
    let candidate = kernel.discovery().get(device(A)).expect("a candidate");
    assert_eq!(candidate.display_name, "Laptop");
    assert_eq!(candidate.address.port(), 47_100);
}

#[test]
fn a_goodbye_reaches_the_broadcast_addresses_and_reports_each() {
    // A device that is shutting down has no second chance, and every interface deserves its own attempt.
    let service = service(A, Duration::from_secs(60));
    let results = service.goodbye(1_700_000_000_000);
    assert_eq!(
        results.len(),
        1,
        "a loopback socket cannot broadcast on external interfaces"
    );
    for (address, result) in &results {
        assert_eq!(address.port(), synra_protocol::limits::DISCOVERY_PORT);
        if let Err(error) = result {
            assert!(!error.to_string().is_empty());
        }
    }
}
