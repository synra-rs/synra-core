use super::*;
use crate::peer::authenticated::RequestAuthority;

fn received(left: &Device, right: &Device) -> (RequestAuthority, Envelope, PeerLink, PeerLink) {
    let (mut client, mut server) = links(left, right);
    client
        .send(&envelope(left.id(), right.id(), "device.request"))
        .unwrap();
    let request = server.receive().unwrap();
    let authority = server.request_authority().unwrap();
    authority.authorize(&request).unwrap();
    (authority, request, client, server)
}

#[test]
fn captured_authority_crosses_threads_without_retaining_the_socket_or_refreshing_approval() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (authority, request, client, server) = received(&left, &right);
    assert_eq!(authority.local(), right.id());
    assert_eq!(authority.peer(), left.id());
    assert_eq!(
        authority.generation(),
        right.approvals().remove(0).generation()
    );
    drop((client, server));
    let worker = std::thread::spawn(move || authority.authorize(&request));
    assert_eq!(worker.join().unwrap(), Ok(()));
}

#[test]
fn captured_authority_rejects_a_foreign_sender_or_target() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (authority, request, _client, _server) = received(&left, &right);
    for forged in [
        envelope(DeviceId::new(), right.id(), "device.request"),
        envelope(left.id(), DeviceId::new(), "device.request"),
    ] {
        assert_eq!(authority.authorize(&forged), Err(LinkError::Unauthorized));
    }
    assert_eq!(authority.authorize(&request), Ok(()));
}

#[test]
fn queued_authority_never_adopts_a_new_approval_after_same_key_pairing() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (authority, request, _client, mut server) = received(&left, &right);
    let old_generation = authority.generation();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let queued = authority.clone();
    let worker = std::thread::spawn(move || {
        wait.recv_timeout(TIMEOUT).unwrap();
        queued.authorize(&request)
    });
    left.unpair(&right);
    right.unpair(&left);
    let _ = pair(&left, &right);
    assert_ne!(right.approvals().remove(0).generation(), old_generation);
    release.send(()).unwrap();
    assert_eq!(worker.join().unwrap(), Err(LinkError::Unauthorized));
    assert_eq!(server.ping(), Err(LinkError::Unauthorized));
    assert_eq!(authority.generation(), old_generation);
    let (fresh, request, _client, _server) = received(&left, &right);
    assert_ne!(fresh.generation(), old_generation);
    assert_eq!(fresh.authorize(&request), Ok(()));
}

#[test]
fn queued_database_failure_permanently_denies_its_clones_and_original_connection() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (authority, request, _client, mut server) = received(&left, &right);
    let cloned = authority.clone();
    *right.db.lock() = SynraDb::open_in_memory().unwrap();
    assert!(matches!(
        authority.authorize(&request),
        Err(LinkError::AuthorizationUnavailable { .. })
    ));
    right.reopen(false);
    assert_eq!(cloned.authorize(&request), Err(LinkError::Unauthorized));
    assert_eq!(server.ping(), Err(LinkError::Unauthorized));
    let (fresh, request, _client, _server) = received(&left, &right);
    assert_eq!(fresh.authorize(&request), Ok(()));
}

#[test]
fn a_frame_failure_also_invalidates_previously_captured_authority() {
    let left = Device::new();
    let right = Device::new();
    let _ = pair(&left, &right);
    let (authority, request, _client, mut server) = received(&left, &right);
    *right.db.lock() = SynraDb::open_in_memory().unwrap();
    assert!(matches!(
        server.ping(),
        Err(LinkError::AuthorizationUnavailable { .. })
    ));
    right.reopen(false);
    assert_eq!(authority.authorize(&request), Err(LinkError::Unauthorized));
}

#[test]
fn plaintext_and_memory_links_cannot_supply_business_authority() {
    fn refused(stream: impl crate::link::LinkStream + 'static) {
        let link = PeerLink::new(
            stream,
            DeviceId::new(),
            DeviceId::new(),
            synra_protocol::handshake::Agreed {
                common: Vec::new(),
                missing_required: Vec::new(),
            },
            crate::peer::Flags {
                timeout: Some(TIMEOUT),
            },
        );
        assert!(matches!(
            link.request_authority(),
            Err(LinkError::Unauthorized)
        ));
    }
    let (memory, _other) = crate::link::memory::MemoryStream::pair();
    let (socket, _incoming) = sockets();
    refused(memory);
    refused(socket);
}
