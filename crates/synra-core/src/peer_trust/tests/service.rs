//! Production pairing tasks start without preapproved peers and then open real business TLS.

use super::*;
use crate::peer::authenticated::AuthenticatedPeer;
use std::net::SocketAddr;
use std::time::Instant;
use synra_protocol::TraceId;
use synra_protocol::pairing::{PairingPhase, PairingSnapshot};

fn credentials(device: &Device) -> Arc<DeviceCredentials> {
    Arc::new(
        DeviceCredentials::restore(
            device.id(),
            device.credentials.public_identity().certificate_der(),
            device.credentials.private_key_der(),
            u64::try_from(device.now_ms / 1000).unwrap(),
        )
        .unwrap(),
    )
}

fn service(device: &Device) -> Arc<PairingService> {
    Arc::new(PairingService::new(
        Arc::clone(&device.db),
        credentials(device),
        Arc::new(synra_store::sqlite::now_ms),
    ))
}

fn network(device: &Device) -> AuthenticatedPeer {
    AuthenticatedPeer::new(
        Arc::clone(&device.db),
        credentials(device),
        crate::LocalPeer::new(
            device.id(),
            "Peer",
            synra_protocol::session::PlatformKind::Desktop,
            "0.1.0",
        ),
    )
    .unwrap()
}

fn wait(service: &PairingService, predicate: impl Fn(&PairingSnapshot) -> bool) -> PairingSnapshot {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let snapshot = service.snapshot().unwrap();
        if predicate(&snapshot) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "pairing did not progress: {snapshot:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn terminal(service: &PairingService) -> PairingSnapshot {
    wait(service, |state| state.phase.is_terminal())
}

fn local_address() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[test]
fn two_explicit_oob_imports_create_durable_trust_and_enable_business_connections() {
    let left = Device::new();
    let right = Device::new();
    let initiator = service(&left);
    let responder = service(&right);
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
    let listening = responder
        .listen(
            left.id(),
            &initiator.invitation().unwrap(),
            local_address(),
            TIMEOUT,
        )
        .unwrap();
    let connecting = initiator
        .connect(
            right.id(),
            listening.reply.as_deref().unwrap(),
            local_address(),
            TIMEOUT,
        )
        .unwrap();
    assert_eq!(terminal(&initiator).phase, PairingPhase::Paired);
    assert_eq!(terminal(&responder).phase, PairingPhase::Paired);
    for (device, task) in [(&left, &connecting), (&right, &listening)] {
        let approvals = device.approvals();
        assert_eq!(approvals.len(), 1);
        let metadata = device.db.lock().paired_devices().unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(
            metadata.first().unwrap().device_id,
            task.peer_id.to_string()
        );
        let db = SynraDb::open(&device.path).unwrap();
        let grant = db
            .trusted_peer_records(
                &device.id().to_string(),
                device.credentials.public_identity().certificate_der(),
            )
            .unwrap();
        assert_eq!(
            grant.first().unwrap().generation,
            task.request_id.to_string()
        );
    }
    let (socket, incoming) = sockets();
    let local_id = left.id();
    std::thread::scope(|scope| {
        let peer = network(&right);
        let worker = scope.spawn(move || {
            let (mut link, _) = peer
                .accept(
                    incoming,
                    1,
                    synra_store::sqlite::now_ms() as u64 / 1000,
                    TIMEOUT,
                )
                .unwrap();
            assert_eq!(link.receive().unwrap().from, local_id);
        });
        let peer = network(&left);
        let (mut link, _) = peer
            .connect(socket, left.approvals().remove(0), 1, TIMEOUT)
            .unwrap();
        let envelope = crate::messaging::text_to(
            left.id(),
            right.id(),
            "first authenticated message",
            TraceId::new(),
            1,
        )
        .unwrap();
        link.send(&envelope).unwrap();
        worker.join().unwrap();
    });
    assert!(matches!(
        responder.listen(
            left.id(),
            &initiator.invitation().unwrap(),
            local_address(),
            TIMEOUT
        ),
        Err(PairingServiceError::AlreadyPaired)
    ));
}

#[test]
fn cancelling_a_silent_tls_handshake_releases_the_slot_without_granting_trust() {
    let left = Device::new();
    let right = Device::new();
    let initiator = service(&left);
    let responder = service(&right);
    let snapshot = responder
        .listen(
            left.id(),
            &initiator.invitation().unwrap(),
            local_address(),
            TIMEOUT,
        )
        .unwrap();
    let port: u16 = snapshot
        .reply
        .as_deref()
        .unwrap()
        .strip_prefix("synra-pair-reply:1:")
        .unwrap()
        .split_once(':')
        .unwrap()
        .0
        .parse()
        .unwrap();
    let socket =
        TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), TIMEOUT).unwrap();
    wait(&responder, |state| state.phase == PairingPhase::Connecting);
    assert!(matches!(
        responder.listen(
            left.id(),
            &initiator.invitation().unwrap(),
            local_address(),
            TIMEOUT
        ),
        Err(PairingServiceError::Busy)
    ));
    let started = Instant::now();
    responder.cancel(snapshot.request_id).unwrap();
    assert_eq!(terminal(&responder).phase, PairingPhase::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(socket);
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
    let replacement = responder
        .listen(
            left.id(),
            &initiator.invitation().unwrap(),
            local_address(),
            TIMEOUT,
        )
        .unwrap();
    assert_ne!(replacement.request_id, snapshot.request_id);
    assert!(matches!(
        responder.cancel(snapshot.request_id),
        Err(PairingServiceError::NotRunning)
    ));
    responder.cancel(replacement.request_id).unwrap();
    assert_eq!(terminal(&responder).phase, PairingPhase::Cancelled);
}

#[test]
fn a_listener_expires_without_promoting_its_public_invitation() {
    let left = Device::new();
    let right = Device::new();
    let responder = service(&right);
    responder
        .listen(
            left.id(),
            &service(&left).invitation().unwrap(),
            local_address(),
            Duration::from_millis(30),
        )
        .unwrap();
    assert_eq!(terminal(&responder).phase, PairingPhase::TimedOut);
    assert!(right.approvals().is_empty());
    assert!(right.db.lock().paired_devices().unwrap().is_empty());
}

#[test]
fn an_invitation_for_another_certificate_cannot_authenticate_the_responder() {
    let left = Device::new();
    let right = Device::new();
    let other = Device::new();
    let initiator = service(&left);
    let responder = service(&right);
    let snapshot = responder
        .listen(
            left.id(),
            &initiator.invitation().unwrap(),
            local_address(),
            TIMEOUT,
        )
        .unwrap();
    let port: u16 = snapshot
        .reply
        .as_deref()
        .unwrap()
        .strip_prefix("synra-pair-reply:1:")
        .unwrap()
        .split_once(':')
        .unwrap()
        .0
        .parse()
        .unwrap();
    let wrong = format!(
        "synra-pair-reply:1:{port}:{}",
        service(&other).invitation().unwrap()
    );
    initiator
        .connect(other.id(), &wrong, local_address(), TIMEOUT)
        .unwrap();
    assert_eq!(terminal(&initiator).phase, PairingPhase::Failed);
    assert_eq!(terminal(&responder).phase, PairingPhase::Failed);
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
    assert!(left.db.lock().paired_devices().unwrap().is_empty());
}

#[test]
fn revocation_before_tls_cannot_be_undone_by_a_late_connection() {
    let left = Device::new();
    let right = Device::new();
    let initiator = service(&left);
    let responder = service(&right);
    let listening = responder
        .listen(
            left.id(),
            &initiator.invitation().unwrap(),
            local_address(),
            TIMEOUT,
        )
        .unwrap();
    assert!(
        right
            .db
            .lock()
            .unpair_device(&left.id().to_string())
            .unwrap(),
        "revocation must find the durable reservation before any TLS client arrives"
    );
    initiator
        .connect(
            right.id(),
            listening.reply.as_deref().unwrap(),
            local_address(),
            TIMEOUT,
        )
        .unwrap();
    assert_ne!(terminal(&initiator).phase, PairingPhase::Paired);
    assert_ne!(terminal(&responder).phase, PairingPhase::Paired);
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
    assert!(right.db.lock().paired_devices().unwrap().is_empty());
}
