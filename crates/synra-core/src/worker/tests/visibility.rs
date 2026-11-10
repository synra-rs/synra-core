use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use synra_protocol::discovery::TrustLevel;
use crate::discovery::{Absorbed, DiscoveryTable};
use crate::socket::DiscoverySocket;
use super::super::is_visible;
use super::super::runner::heard_now;
use super::{A, B, announcement, device, host, service};

#[test]
fn a_device_heard_over_the_network_is_not_visible_until_it_is_handshaked() {
    // ★ The protocol's own rule, reached through the service: an announced device is a *candidate*, and the interface
    // shows candidates under their own heading rather than among peers.
    let table = DiscoveryTable::new(device(A));
    assert!(!is_visible(&table, 0));

    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");
    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks");
    service.tick(&mut kernel, 5_000, Instant::now(), 0);

    assert_eq!(
        kernel
            .discovery()
            .get(device(B))
            .expect("a candidate")
            .trust,
        TrustLevel::Announced
    );
    assert!(
        !is_visible(kernel.discovery(), 5_000),
        "an announced device should not be visible"
    );
}

#[test]
fn the_callback_is_given_a_device_that_only_announced_itself() {
    // ★ The visibility rule and this are two different questions, and the callback used to answer the wrong one.
    //
    // `is_visible` is about a *screen*: an announced device is a candidate, shown under its own heading, not among
    // peers. The callback is about *memory*: it is "what did you hear", and the table both hosts write from it says
    // it holds a sighting of a device this kernel has not paired with. Fed from `usable`, which starts at
    // `Handshaked`, it was never told about a sighting.
    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");
    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    let heard = heard_now(&kernel, &ticked.absorbed);

    assert_eq!(heard.len(), 1, "the device that asked is what was heard");
    assert_eq!(heard[0].device_id, device(B));
    assert_eq!(
        heard[0].trust,
        TrustLevel::Announced,
        "and it is a sighting, not an identity"
    );
    // And the screen's rule is untouched: the same device is still not a peer.
    assert!(!is_visible(kernel.discovery(), 5_000));

    // Repeated announcements refresh presence even when the endpoint has not changed.
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks again");
    let again = service.tick(&mut kernel, 5_001, Instant::now(), 0);
    assert_eq!(
        again.absorbed,
        vec![Absorbed::Unchanged {
            device_id: device(B)
        }]
    );
    assert_eq!(heard_now(&kernel, &again.absorbed)[0].last_seen_ms, 5_001);
}

#[test]
fn a_service_debug_form_names_the_device_and_the_port() {
    // It appears in a log line, and a handle that printed a socket would leak the path.
    let service = service(A, Duration::from_secs(60));
    let text = format!("{service:?}");
    assert!(
        text.contains("Laptop") || text.contains("47100") || text.contains("47_100"),
        "{text}"
    );
    assert!(!text.contains("127.0.0.1"), "{text}");
}
