use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConnection, StreamOwned};

use super::{
    AuthenticatedStream, AuthenticationError, DeviceCredentials, IO_TIMEOUT, exchange, identity,
    now, request, sockets,
};
use crate::authentication::{MAX_APPROVED_PEERS, credentials, handshake};

#[test]
fn unapproved_and_replaced_client_keys_never_reach_application_io() {
    for replace_same_id in [false, true] {
        let approved_client = identity();
        let unapproved_client = if replace_same_id {
            DeviceCredentials::generate(approved_client.public_identity().device_id(), now())
                .expect("replace")
        } else {
            identity()
        };
        let server = identity();
        let peer = server.public_identity().clone();
        let result = exchange(
            server,
            vec![approved_client.public_identity().clone()],
            |socket| {
                let mut stream =
                    AuthenticatedStream::connect(socket, &unapproved_client, &peer, IO_TIMEOUT)
                        .map_err(io::Error::other)?;
                request(&mut stream)
            },
        );
        assert!(!result.admitted);
        assert!(result.server.is_err());
        assert!(result.client.is_err());
    }
}

#[test]
fn replacing_the_server_key_with_the_same_device_id_is_rejected() {
    let original = identity();
    let replaced = DeviceCredentials::generate(original.public_identity().device_id(), now())
        .expect("replace");
    let client = identity();
    let result = exchange(replaced, vec![client.public_identity().clone()], |socket| {
        match AuthenticatedStream::connect(socket, &client, original.public_identity(), IO_TIMEOUT)
        {
            Ok(_) => panic!("replacement must not produce a stream"),
            Err(error) => Err(io::Error::other(error)),
        }
    });
    assert!(!result.admitted);
    assert!(result.client.is_err());
}

#[test]
fn anonymous_clients_and_missing_or_wrong_alpn_are_rejected() {
    for scenario in 0..3 {
        let client = identity();
        let server = identity();
        let peer = server.public_identity().clone();
        let mut config = handshake::client(&client, &peer).expect("config");
        match scenario {
            0 => {
                let anonymous = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS13")
                .with_root_certificates(
                    credentials::roots(std::iter::once(peer.certificate.clone())).expect("roots"),
                )
                .with_no_client_auth();
                config.client_auth_cert_resolver = anonymous.client_auth_cert_resolver;
            }
            1 => config.alpn_protocols.clear(),
            _ => config.alpn_protocols = vec![b"wrong/1".to_vec()],
        }
        let result = exchange(server, vec![client.public_identity().clone()], |socket| {
            let connection = ClientConnection::new(
                Arc::new(config),
                credentials::server_name(peer.device_id()).expect("name"),
            )
            .expect("client");
            request(&mut StreamOwned::new(connection, socket))
        });
        assert!(!result.admitted, "scenario {scenario}");
        assert!(result.server.is_err());
        assert!(result.client.is_err());
    }
}

#[test]
fn plaintext_application_messages_are_rejected_before_admission() {
    let client = identity();
    let result = exchange(
        identity(),
        vec![client.public_identity().clone()],
        |mut socket| {
            socket.write_all(b"{\"type\":\"Hello\",\"device_id\":\"attacker\"}")?;
            socket.flush()?;
            let mut reply = [0; 16];
            let _ = socket.read(&mut reply);
            Ok(())
        },
    );
    assert!(!result.admitted);
    assert!(result.server.is_err());
}

#[test]
fn tls12_only_clients_are_rejected_before_admission() {
    let client = identity();
    let server = identity();
    let peer = server.public_identity().clone();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .expect("TLS12 test client")
    .with_root_certificates(
        credentials::roots(std::iter::once(peer.certificate.clone())).expect("roots"),
    )
    .with_client_auth_cert(
        vec![client.public_identity().certificate.clone()],
        client.key(),
    )
    .expect("client key");
    let result = exchange(server, vec![client.public_identity().clone()], |socket| {
        let connection = ClientConnection::new(
            Arc::new(config),
            credentials::server_name(peer.device_id()).expect("name"),
        )
        .expect("client");
        request(&mut StreamOwned::new(connection, socket))
    });
    assert!(!result.admitted);
    assert!(result.server.is_err());
    assert!(result.client.is_err());
}

#[test]
fn empty_ambiguous_and_oversized_trust_snapshots_fail_closed() {
    let local = identity();
    let first = identity();
    let replacement =
        DeviceCredentials::generate(first.public_identity().device_id(), now()).expect("replace");
    for peers in [
        vec![],
        vec![
            first.public_identity().clone(),
            first.public_identity().clone(),
        ],
        vec![
            first.public_identity().clone(),
            replacement.public_identity().clone(),
        ],
        vec![first.public_identity().clone(); MAX_APPROVED_PEERS + 1],
    ] {
        let (_client, server) = sockets();
        assert!(matches!(
            AuthenticatedStream::accept(server, &local, &peers, IO_TIMEOUT),
            Err(AuthenticationError::InvalidPeerList(_))
        ));
    }
}

#[test]
fn silent_peer_and_zero_budget_do_not_leave_unbounded_handshakes() {
    let local = identity();
    let remote = identity();
    for incoming in [true, false] {
        let (_silent_peer, socket) = sockets();
        let started = Instant::now();
        let result = if incoming {
            AuthenticatedStream::accept(
                socket,
                &local,
                &[remote.public_identity().clone()],
                Duration::from_millis(100),
            )
        } else {
            AuthenticatedStream::connect(
                socket,
                &local,
                remote.public_identity(),
                Duration::from_millis(100),
            )
        };
        assert!(matches!(result, Err(AuthenticationError::TimedOut)));
        assert!(started.elapsed() < IO_TIMEOUT);
    }
    let (_peer, socket) = sockets();
    assert!(matches!(
        AuthenticatedStream::connect(socket, &local, remote.public_identity(), Duration::ZERO),
        Err(AuthenticationError::TimedOut)
    ));
}

#[test]
fn partial_tls_records_cannot_reset_the_total_deadline() {
    let local = identity();
    let remote = identity();
    let (mut attacker, socket) = sockets();
    // An incomplete 5000-byte handshake record; each subsequent byte arrives well within a one-second
    // per-read timeout. The stop channel bounds the worker and avoids depending on a narrow observer window.
    attacker
        .write_all(&[0x16, 0x03, 0x03, 0x13, 0x88])
        .expect("record header");
    let (stop, stopped) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        for _ in 0..50 {
            if stopped.recv_timeout(Duration::from_millis(100)).is_ok() {
                break;
            }
            if attacker.write_all(&[0]).is_err() {
                break;
            }
        }
    });
    let started = Instant::now();
    let result = AuthenticatedStream::accept(
        socket,
        &local,
        &[remote.public_identity().clone()],
        Duration::from_secs(1),
    );
    let elapsed = started.elapsed();
    let _ = stop.send(());
    worker.join().expect("attacker");
    assert!(matches!(result, Err(AuthenticationError::TimedOut)));
    assert!(
        elapsed < IO_TIMEOUT,
        "partial records extended deadline to {elapsed:?}"
    );
}
