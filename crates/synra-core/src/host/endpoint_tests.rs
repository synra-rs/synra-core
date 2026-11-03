use super::*;

fn accept_bounded(mut server: Host) -> (Host, PeerLink) {
    server.listen_nonblocking().expect("nonblocking listener");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let stream = loop {
        if let Some(stream) = server.try_accept().expect("accept poll") {
            break stream;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no connection before deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let (parts, _) = server.dialling_parts();
    let dialled = parts
        .accept_stream(stream, Flags::production(), network_now())
        .expect("Hello");
    let link = server.adopt(dialled, network_now()).expect("session");
    (server, link)
}

#[test]
fn accepting_a_connection_preserves_the_announced_listening_port() {
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db, client_address) = listening(B, "Phone");
    client.set_flags(Flags::production());
    server.heard(
        &DeviceAnnouncement {
            device_id: device(B),
            display_name: "Phone".to_owned(),
            protocol: PROTOCOL_VERSION,
            port: client_address.port(),
            platform: Some(PlatformKind::Android),
            app_version: None,
            features: Vec::new(),
        },
        client_address,
        1_000,
    );
    let serving = std::thread::spawn(move || accept_bounded(server));
    let link = client.dial(address, device(A), network_now());
    let (server, _server_link) = serving.join().expect("finished");
    let link = link.expect("dials");
    assert_eq!(server.address_of(device(B)), Some(client_address));
    assert_eq!(
        client.address_of(device(A)),
        Some(address),
        "an outgoing dial records the listening endpoint"
    );
    drop(link);
}

#[test]
fn a_discovered_endpoint_cannot_answer_as_another_paired_device() {
    let (server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");
    client.set_flags(Flags::production());
    let serving = std::thread::spawn(move || accept_bounded(server));
    let expected = DeviceId::new();
    let result = client.dial(address, expected, network_now());
    serving.join().expect("finished");
    assert!(matches!(result, Err(HostError::Authentication { .. })));
    assert!(client.sessions().is_empty());
}
