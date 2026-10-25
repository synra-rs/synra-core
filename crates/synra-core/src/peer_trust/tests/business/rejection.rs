use super::*;

#[test]
fn hello_cannot_claim_a_different_identity_from_its_tls_certificate() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (outgoing, incoming) = sockets();
    let server = peer(&right);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            server.accept(
                incoming,
                1,
                u64::try_from(right.now_ms / 1000).unwrap(),
                TIMEOUT,
            )
        });
        let mut raw = AuthenticatedStream::connect(
            outgoing,
            &left.credentials,
            right.credentials.public_identity(),
            TIMEOUT,
        )
        .unwrap();
        raw.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut hello = profile(&left).hello(SessionNonce::random(), 1);
        hello.device_id = DeviceId::new();
        raw.write_all(&encoded(FrameKind::Hello, &hello)).unwrap();
        raw.flush().unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(SecurePeerError::Handshake(
                HandshakeError::Authorization { .. }
            ))
        ));
        assert!(matches!(raw.read(&mut [0; 1]), Ok(0) | Err(_)));
    });
}

#[test]
fn hello_ack_identity_profile_endpoints_and_pairing_state_are_checked() {
    for field in [
        "deviceId",
        "displayName",
        "appVersion",
        "endpoints",
        "pairing",
    ] {
        let left = Device::new();
        let right = Device::new();
        let _ = pair(&left, &right);
        let (outgoing, incoming) = sockets();
        let client = peer(&left);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let mut raw = AuthenticatedStream::accept(
                    incoming,
                    &right.credentials,
                    &[left.credentials.public_identity().clone()],
                    TIMEOUT,
                )
                .unwrap();
                raw.set_read_timeout(Some(TIMEOUT)).unwrap();
                let hello: Hello = read_message(&mut raw);
                let mut ack = profile(&right).hello_ack(hello.nonce, PairingState::Current, 1);
                match field {
                    "deviceId" => ack.device_id = DeviceId::new(),
                    "displayName" => ack.display_name = "x".repeat(65),
                    "appVersion" => ack.app_version = String::new(),
                    "endpoints" => {
                        ack.endpoints = vec!["127.0.0.1:1".to_owned(); Hello::MAX_ENDPOINTS + 1]
                    }
                    "pairing" => ack.pairing = PairingState::Unknown,
                    _ => unreachable!(),
                }
                raw.write_all(&encoded(FrameKind::HelloAck, &ack)).unwrap();
                raw.flush().unwrap();
            });
            assert!(
                client
                    .connect(outgoing, left.approvals().remove(0), 1, TIMEOUT)
                    .is_err(),
                "{field}"
            );
            worker.join().unwrap();
        });
    }
}

#[test]
fn revocation_during_hello_wait_prevents_a_link_from_being_returned() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (outgoing, incoming) = sockets();
    let server = peer(&right);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            server.accept(
                incoming,
                1,
                u64::try_from(right.now_ms / 1000).unwrap(),
                TIMEOUT,
            )
        });
        let mut raw = AuthenticatedStream::connect(
            outgoing,
            &left.credentials,
            right.credentials.public_identity(),
            TIMEOUT,
        )
        .unwrap();
        right.unpair(&left);
        let hello = profile(&left).hello(SessionNonce::random(), 1);
        let _ = raw.write_all(&encoded(FrameKind::Hello, &hello));
        let _ = raw.flush();
        assert!(worker.join().unwrap().is_err());
    });
}

#[test]
fn unapproved_tls_peers_cannot_enter_the_application_handshake() {
    let left = Device::new();
    let right = Device::new();
    let (outgoing, incoming) = sockets();
    let server = peer(&right);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            server.accept(
                incoming,
                1,
                u64::try_from(right.now_ms / 1000).unwrap(),
                TIMEOUT,
            )
        });
        assert!(
            AuthenticatedStream::connect(
                outgoing,
                &left.credentials,
                right.credentials.public_identity(),
                TIMEOUT
            )
            .is_err()
        );
        assert!(worker.join().unwrap().is_err());
    });
}

#[test]
fn a_valid_tls_peer_that_never_sends_hello_has_a_total_deadline() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (outgoing, incoming) = sockets();
    let server = peer(&right);
    let started = std::time::Instant::now();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            server.accept(
                incoming,
                1,
                u64::try_from(right.now_ms / 1000).unwrap(),
                Duration::from_millis(100),
            )
        });
        let _raw = AuthenticatedStream::connect(
            outgoing,
            &left.credentials,
            right.credentials.public_identity(),
            TIMEOUT,
        )
        .unwrap();
        assert!(worker.join().unwrap().is_err());
    });
    assert!(started.elapsed() < TIMEOUT);
}

#[test]
fn a_partial_business_frame_cannot_retry_past_the_total_frame_budget() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (outgoing, incoming) = sockets();
    let server = peer(&right);
    let (finished, result) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (mut link, _) = server
                .accept(
                    incoming,
                    1,
                    u64::try_from(right.now_ms / 1000).unwrap(),
                    TIMEOUT,
                )
                .unwrap();
            link.set_read_timeout(Some(Duration::from_millis(100)));
            finished.send(link.receive_inbound()).unwrap();
        });
        let mut raw = AuthenticatedStream::connect(
            outgoing,
            &left.credentials,
            right.credentials.public_identity(),
            TIMEOUT,
        )
        .unwrap();
        raw.set_read_timeout(Some(TIMEOUT)).unwrap();
        raw.write_all(&encoded(
            FrameKind::Hello,
            &profile(&left).hello(SessionNonce::random(), 1),
        ))
        .unwrap();
        raw.flush().unwrap();
        let _ack: synra_protocol::handshake::HelloAck = read_message(&mut raw);
        raw.write_all(&[0]).unwrap();
        raw.flush().unwrap();
        let outcome = result.recv_timeout(TIMEOUT);
        // Always release the socket before joining, even if a regression missed the deadline.
        drop(raw);
        worker.join().unwrap();
        assert!(matches!(outcome, Ok(Err(LinkError::TimedOut))));
    });
}

#[test]
fn local_profiles_must_match_their_credential_before_any_connection_attempt() {
    let local = Device::new();
    let credentials =
        DeviceCredentials::generate(local.id(), u64::try_from(local.now_ms / 1000).unwrap())
            .unwrap();
    let credentials = Arc::new(credentials);
    let mut ours = profile(&local);
    ours.device_id = DeviceId::new();
    assert!(matches!(
        AuthenticatedPeer::new(Arc::clone(&local.db), Arc::clone(&credentials), ours),
        Err(SecurePeerError::LocalProfile(_))
    ));
    let mut ours = profile(&local);
    ours.display_name.clear();
    assert!(matches!(
        AuthenticatedPeer::new(Arc::clone(&local.db), credentials, ours),
        Err(SecurePeerError::LocalProfile(_))
    ));
}
