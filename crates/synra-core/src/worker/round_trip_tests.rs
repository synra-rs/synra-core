use super::tests::{A, B, announcement, device, host, service};
use super::*;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};

#[test]
fn discovery_replies_to_udp_source_and_keeps_tcp_endpoint() {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP listener");
    let tcp_address = tcp.local_addr().expect("TCP endpoint");
    let mut receiver = service(B, Duration::from_secs(60));
    let mut receiver_host = host(B, "Phone");
    let sender =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("UDP querier");
    let udp_address = sender.local_addr().expect("UDP source");
    sender
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("bounded receive");
    sender
        .send_query(
            &announcement(A, "Laptop", tcp_address.port()),
            receiver.responder_address().expect("responder"),
        )
        .expect("query");

    let ticked = receiver.tick(&mut receiver_host, 5_000, Instant::now(), 0);
    assert_eq!(ticked.askers, vec![udp_address]);
    assert_eq!(receiver_host.address_of(device(A)), Some(tcp_address));
    for (_, answer) in receiver.answer_pending(&ticked) {
        answer.expect("response");
    }
    let mut sender_host = host(A, "Laptop");
    assert_eq!(
        sender.receive(&mut sender_host, 5_000).expect("reply"),
        Some(Absorbed::New {
            device_id: device(B)
        })
    );

    // Discovery must answer a second scan even when the announcement is unchanged.
    sender
        .send_query(
            &announcement(A, "Laptop", tcp_address.port()),
            receiver.responder_address().expect("responder"),
        )
        .expect("repeat query");
    let again = receiver.tick(&mut receiver_host, 5_001, Instant::now(), 0);
    assert_eq!(again.askers, vec![udp_address]);
    assert!(matches!(
        again.absorbed.as_slice(),
        [Absorbed::Unchanged { .. }]
    ));
    for (_, answer) in receiver.answer_pending(&again) {
        answer.expect("repeat response");
    }
    sender
        .receive(&mut sender_host, 5_001)
        .expect("second scan reply");
}

#[test]
fn responses_and_goodbyes_do_not_start_response_loops() {
    let mut receiver = service(B, Duration::from_secs(60));
    let mut kernel = host(B, "Phone");
    let sender = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("sender");
    let destination = receiver.responder_address().expect("responder");
    sender
        .send_response(&announcement(A, "Laptop", 47_101), destination)
        .expect("response");
    sender
        .send_offline(
            &OfflineAnnouncement {
                device_id: device(A),
                timestamp: 5_001,
            },
            destination,
        )
        .expect("goodbye");
    assert!(
        receiver
            .tick(&mut kernel, 5_001, Instant::now(), 0)
            .askers
            .is_empty()
    );
}

#[test]
fn silence_and_goodbye_publish_offline_once_then_rediscovery_restores_presence() {
    use super::runner::presence_changes;
    let mut kernel = host(A, "Laptop");
    let mut present = std::collections::BTreeSet::new();
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000));
    let update = kernel.heard(&announcement(B, "Phone", 47_101), source, 5_000);
    assert_eq!(
        presence_changes(&kernel, &[update], 5_000, &mut present).len(),
        1
    );
    let expired = 5_000 + i64::try_from(kernel.discovery().ttl().as_millis()).expect("TTL");
    assert_eq!(
        presence_changes(&kernel, &[], expired, &mut present).len(),
        1
    );
    assert!(presence_changes(&kernel, &[], expired + 1, &mut present).is_empty());
    assert!(kernel.recent_address(device(B), expired).is_none());
    let update = kernel.heard(&announcement(B, "Phone", 47_102), source, expired + 2);
    assert_eq!(
        presence_changes(&kernel, &[update], expired + 2, &mut present).len(),
        1
    );
    assert_eq!(
        kernel
            .recent_address(device(B), expired + 2)
            .expect("online")
            .port(),
        47_102
    );
    let bye = kernel.went_offline(device(B), expired + 3);
    assert_eq!(
        presence_changes(&kernel, &[bye], expired + 3, &mut present).len(),
        1
    );
    assert!(kernel.recent_address(device(B), expired + 3).is_none());
    assert!(presence_changes(&kernel, &[], expired + 4, &mut present).is_empty());
}
