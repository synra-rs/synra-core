use super::*;
use crate::link::{LinkError, PeerLink};
use crate::peer::authenticated::{AuthenticatedPeer, SecurePeerError};
use crate::peer::{HandshakeError, LocalPeer};
use std::io::{Read, Write};
use synra_protocol::envelope::Envelope;
use synra_protocol::frame::{Frame, FrameBody, FrameDecoder, FrameEncoder, FrameKind};
use synra_protocol::handshake::{Hello, PairingState, SessionNonce};
use synra_protocol::session::PlatformKind;

mod rejection;

fn profile(device: &Device) -> LocalPeer {
    LocalPeer::new(device.id(), "test peer", PlatformKind::Desktop, "0.1.0")
}

fn peer(device: &Device) -> AuthenticatedPeer {
    let credentials = DeviceCredentials::restore(
        device.id(),
        device.credentials.public_identity().certificate_der(),
        device.credentials.private_key_der(),
        u64::try_from(device.now_ms / 1000).unwrap(),
    )
    .unwrap();
    AuthenticatedPeer::new(
        Arc::clone(&device.db),
        Arc::new(credentials),
        profile(device),
    )
    .unwrap()
}

fn links(left: &Device, right: &Device) -> (PeerLink, PeerLink) {
    let (outgoing, incoming) = sockets();
    let client = peer(left);
    let server = peer(right);
    let approval = left.approvals().remove(0);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            server
                .accept(
                    incoming,
                    1,
                    u64::try_from(right.now_ms / 1000).unwrap(),
                    TIMEOUT,
                )
                .unwrap()
        });
        let (link, info) = client.connect(outgoing, approval, 1, TIMEOUT).unwrap();
        let (other, remote) = worker.join().unwrap();
        assert_eq!(info.device_id, right.id());
        assert_eq!(remote.device_id, left.id());
        (link, other)
    })
}

fn envelope(from: DeviceId, target: DeviceId, event: &str) -> Envelope {
    Envelope::outbound(
        synra_protocol::envelope::OutboundSpec {
            event: synra_protocol::event::EventName::parse(event).unwrap(),
            from,
            target,
            trace_id: synra_protocol::TraceId::new(),
            sent_at_ms: 1,
            ttl_ms: None,
        },
        None::<&serde_json::Value>,
    )
    .unwrap()
}

fn encoded<T: serde::Serialize>(kind: FrameKind, message: &T) -> Vec<u8> {
    let bytes = bytes::Bytes::from(serde_json::to_vec(message).unwrap());
    let body = match kind {
        FrameKind::Hello => FrameBody::Hello(bytes),
        FrameKind::HelloAck => FrameBody::HelloAck(bytes),
        FrameKind::Envelope => FrameBody::Envelope(bytes),
        _ => panic!("unsupported test message"),
    };
    FrameEncoder::encode_to_vec(&Frame {
        kind,
        flags: 0,
        body,
    })
    .unwrap()
    .to_vec()
}

fn read_message<T: serde::de::DeserializeOwned>(stream: &mut AuthenticatedStream) -> T {
    let mut decoder = FrameDecoder::new();
    let mut bytes = [0; 8192];
    loop {
        if let Some(frame) = decoder.next_frame().unwrap() {
            let payload = match frame.body {
                FrameBody::Hello(bytes) | FrameBody::HelloAck(bytes) => bytes,
                _ => panic!("not Hello"),
            };
            return serde_json::from_slice(&payload).unwrap();
        }
        let length = stream.read(&mut bytes).unwrap();
        assert!(length > 0);
        decoder.push_slice(&bytes[..length]).unwrap();
    }
}

#[test]
fn authenticated_hello_builds_business_links_that_exchange_envelopes_and_chunks() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (mut client, mut server) = links(&left, &right);
    let request = envelope(left.id(), right.id(), "device.request");
    client.send(&request).unwrap();
    assert_eq!(server.receive().unwrap(), request);
    let reply = envelope(right.id(), left.id(), "device.reply");
    server.send(&reply).unwrap();
    assert_eq!(client.receive().unwrap(), reply);
    client.send_chunk(3, b"authenticated bytes").unwrap();
    match server.receive_inbound().unwrap() {
        crate::link::Inbound::Block { chunk_id, data } => {
            assert_eq!(chunk_id, 3);
            assert_eq!(data.as_ref(), b"authenticated bytes");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn revoked_connections_refuse_every_frame_and_same_key_repair_only_opens_new_links() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (mut client, mut server) = links(&left, &right);
    left.unpair(&right);
    right.unpair(&left);
    assert_eq!(
        client.send(&envelope(left.id(), right.id(), "device.request")),
        Err(LinkError::Unauthorized)
    );
    assert_eq!(
        client.send_chunk(0, b"forbidden"),
        Err(LinkError::Unauthorized)
    );
    assert_eq!(client.ping(), Err(LinkError::Unauthorized));
    assert!(matches!(
        server.receive_inbound(),
        Err(LinkError::Unauthorized)
    ));
    let _ = pair(&left, &right);
    assert_eq!(client.ping(), Err(LinkError::Unauthorized));
    let (mut fresh, mut other) = links(&left, &right);
    fresh
        .send(&envelope(left.id(), right.id(), "device.new"))
        .unwrap();
    assert_eq!(other.receive().unwrap().event.as_str(), "device.new");
}

#[test]
fn prefetched_frames_after_hello_are_retained_and_rechecked_after_revocation() {
    for revoke in [false, true] {
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
                let ack = profile(&right).hello_ack(hello.nonce, PairingState::Current, 1);
                let mut bytes = encoded(FrameKind::HelloAck, &ack);
                bytes.extend(encoded(
                    FrameKind::Envelope,
                    &envelope(right.id(), left.id(), "device.first"),
                ));
                bytes.extend(encoded(
                    FrameKind::Envelope,
                    &envelope(right.id(), left.id(), "device.second"),
                ));
                // One TLS write coalesces HelloAck and business frames into the same read ahead.
                raw.write_all(&bytes).unwrap();
                raw.flush().unwrap();
            });
            let (mut link, _) = client
                .connect(outgoing, left.approvals().remove(0), 1, TIMEOUT)
                .unwrap();
            worker.join().unwrap();
            link.set_read_timeout(Some(Duration::ZERO));
            assert_eq!(link.receive(), Err(LinkError::TimedOut));
            link.set_read_timeout(None);
            assert_eq!(link.receive().unwrap().event.as_str(), "device.first");
            if revoke {
                left.unpair(&right);
                assert_eq!(link.receive(), Err(LinkError::Unauthorized));
                assert_eq!(link.received(), 1);
            } else {
                assert_eq!(link.receive().unwrap().event.as_str(), "device.second");
            }
        });
    }
}

#[test]
fn a_database_failure_permanently_denies_the_existing_link() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (mut client, _server) = links(&left, &right);
    *left.db.lock() = SynraDb::open_in_memory().unwrap();
    assert!(matches!(
        client.ping(),
        Err(LinkError::AuthorizationUnavailable { .. })
    ));
    left.reopen(false);
    assert_eq!(left.approvals().len(), 1);
    assert_eq!(client.ping(), Err(LinkError::Unauthorized));
}
