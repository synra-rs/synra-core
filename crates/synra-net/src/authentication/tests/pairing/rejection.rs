use std::time::Instant;

use rustls::{ClientConnection, StreamOwned};
use serde_json::{Value, json};

use super::*;

type RawClient = StreamOwned<ClientConnection, TcpStream>;

fn raw_exchange(
    timeout: Duration,
    send: impl FnOnce(&mut RawClient, Value, &std::sync::mpsc::Receiver<()>),
) -> Result<MutualConsent, PairingError> {
    let client = identity();
    let server = identity();
    let local_id = client.public_identity().device_id();
    let peer = server.public_identity().clone();
    let approved = client.public_identity().clone();
    let (outgoing, incoming) = sockets();
    let (finished, stop) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = PairingChannel::accept(incoming, &server, &approved, IO_TIMEOUT)
            .and_then(|channel| channel.confirm(true, timeout));
        let _ = finished.send(());
        result
    });
    let mut config = crate::authentication::handshake::client(&client, &peer).expect("config");
    config.alpn_protocols = vec![b"synra/pairing/1".to_vec()];
    let connection = ClientConnection::new(
        Arc::new(config),
        crate::authentication::credentials::server_name(peer.device_id()).expect("name"),
    )
    .expect("client");
    let mut raw = StreamOwned::new(connection, outgoing);
    raw.conn.complete_io(&mut raw.sock).expect("TLS");
    let binding = raw
        .conn
        .export_keying_material([0; 32], b"EXPORTER-Channel-Binding", Some(&[]))
        .expect("RFC 9266 exporter");
    // Read the production peer's actual record before constructing the adversarial reply.
    let mut length = [0; 4];
    raw.read_exact(&mut length).expect("server prefix");
    let len = usize::try_from(u32::from_be_bytes(length)).expect("length");
    assert!(len <= crate::authentication::pairing::MAX_CONSENT_BYTES);
    let mut bytes = vec![0; len];
    raw.read_exact(&mut bytes).expect("server consent");
    let received: Value = serde_json::from_slice(&bytes).expect("server JSON");
    assert_eq!(received["binding"], json!(binding));
    send(
        &mut raw,
        json!({
            "version": 1, "from": local_id, "target": peer.device_id(),
            "binding": binding, "confirmed": true,
        }),
        &stop,
    );
    drop(raw);
    worker.join().expect("server")
}

fn write_message(client: &mut RawClient, message: &Value) {
    let bytes = serde_json::to_vec(message).expect("JSON");
    client
        .write_all(&u32::try_from(bytes.len()).expect("size").to_be_bytes())
        .expect("prefix");
    client.write_all(&bytes).expect("body");
    client.flush().expect("flush");
}

#[test]
fn consent_must_match_sender_target_version_and_schema() {
    for field in ["from", "target", "version", "unexpected"] {
        let result = raw_exchange(IO_TIMEOUT, |client, mut message, _| {
            message[field] = match field {
                "from" | "target" => json!(DeviceId::new()),
                _ => json!(2),
            };
            write_message(client, &message);
        });
        assert!(matches!(result, Err(PairingError::Rejected(_))), "{field}");
    }
}

#[test]
fn consent_from_a_previous_real_tls_session_cannot_be_replayed() {
    let (client, server) = channels(&identity(), &identity());
    let (previous, _) = consent(client, server);
    let result = raw_exchange(IO_TIMEOUT, |client, mut message, _| {
        message["binding"] = json!(previous.session_binding());
        write_message(client, &message);
    });
    assert!(matches!(result, Err(PairingError::Rejected(_))));
}

#[test]
fn a_received_negative_record_reports_peer_decline_without_evidence() {
    let result = raw_exchange(IO_TIMEOUT, |client, mut message, _| {
        message["confirmed"] = json!(false);
        write_message(client, &message);
    });
    assert!(matches!(result, Err(PairingError::PeerDeclined)));
}

#[test]
fn successful_consent_closes_the_pairing_connection_instead_of_exposing_business_io() {
    let result = raw_exchange(IO_TIMEOUT, |client, message, stop| {
        write_message(client, &message);
        stop.recv_timeout(IO_TIMEOUT)
            .expect("production peer finished");
        let read = client.read(&mut [0; 1]);
        assert!(
            matches!(read, Ok(0))
                || read.is_err_and(|error| error.kind() == io::ErrorKind::UnexpectedEof)
        );
    });
    assert!(result.is_ok());
}

#[test]
fn oversized_and_empty_frames_are_rejected_without_waiting_for_a_body() {
    for length in [0_u32, 1025, u32::MAX] {
        let result = raw_exchange(IO_TIMEOUT, |client, _, _| {
            client.write_all(&length.to_be_bytes()).expect("prefix");
            client.flush().expect("flush");
        });
        assert!(matches!(result, Err(PairingError::Rejected(_))), "{length}");
    }
}

#[test]
fn truncated_or_invalid_json_records_never_issue_consent_evidence() {
    for bytes in [
        b"{".as_slice(),
        b"null".as_slice(),
        b"{\"version\":1}".as_slice(),
    ] {
        let result = raw_exchange(IO_TIMEOUT, |client, _, _| {
            client
                .write_all(&u32::try_from(bytes.len()).expect("length").to_be_bytes())
                .expect("prefix");
            client.write_all(bytes).expect("body");
            client.flush().expect("flush");
        });
        assert!(matches!(result, Err(PairingError::Rejected(_))));
    }
    let disconnected = raw_exchange(IO_TIMEOUT, |_, _, _| {});
    assert!(disconnected.is_err());
}

#[test]
fn a_slow_partial_tls_record_cannot_extend_the_total_consent_budget() {
    let started = Instant::now();
    let result = raw_exchange(Duration::from_millis(120), |client, _, stop| {
        // Application-data header declaring 100 bytes; drip bytes without completing its record.
        client
            .sock
            .write_all(&[23, 3, 3, 0, 100])
            .expect("partial TLS header");
        for _ in 0..60 {
            if client.sock.write_all(&[0]).is_err() {
                break;
            }
            if stop.recv_timeout(Duration::from_millis(10)).is_ok() {
                break;
            }
        }
    });
    assert!(matches!(
        result,
        Err(PairingError::Authentication(AuthenticationError::TimedOut))
    ));
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "partial record extended the total deadline"
    );
}
