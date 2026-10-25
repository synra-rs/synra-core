use super::*;

#[test]
fn consent_alone_never_authorizes_and_completed_grants_survive_reopen() {
    let left = Device::new();
    let right = Device::new();
    let (client, server) = tasks(&left, &right);
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
    let (client, server) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
        let result = client.finish(true, TIMEOUT, || {
            // Every clock callback runs outside the database guard, including commit rechecks.
            assert!(left.db.try_lock().is_some());
            left.now_ms
        });
        (result.unwrap(), worker.join().unwrap().unwrap())
    });
    left.reopen(false);
    right.reopen(false);
    let left_grants = left.approvals();
    let right_grants = right.approvals();
    assert_eq!(left_grants.len(), 1);
    assert_eq!(right_grants.len(), 1);
    assert_eq!(left_grants[0].generation(), client.generation());
    assert_eq!(right_grants[0].generation(), server.generation());
    assert_eq!(
        left_grants[0].identity(),
        right.credentials.public_identity()
    );
    let (stream, remote) = business(&left, &right);
    assert!(client.allows(&left.db, &stream, right.id()).unwrap());
    assert!(server.allows(&right.db, &remote, left.id()).unwrap());
    assert!(!client.allows(&left.db, &stream, DeviceId::new()).unwrap());
    // An approval cannot be used with the opposite endpoint of an otherwise valid TLS session.
    assert!(!client.allows(&left.db, &remote, right.id()).unwrap());
}

#[test]
fn revocation_and_same_certificate_repair_never_resurrect_an_old_connection() {
    let left = Device::new();
    let right = Device::new();
    let (old, _) = pair(&left, &right);
    let (stream, _remote) = business(&left, &right);
    assert!(old.allows(&left.db, &stream, right.id()).unwrap());
    left.unpair(&right);
    right.unpair(&left);
    assert!(!old.allows(&left.db, &stream, right.id()).unwrap());
    let (new, _) = pair(&left, &right);
    assert_ne!(old.generation(), new.generation());
    assert_eq!(old.identity(), new.identity());
    assert!(!old.allows(&left.db, &stream, right.id()).unwrap());
    let (new_stream, _remote) = business(&left, &right);
    assert!(new.allows(&left.db, &new_stream, right.id()).unwrap());
}

#[test]
fn dropping_an_old_owner_cannot_cancel_its_replacement() {
    let left = Device::new();
    let right = Device::new();
    let (old, other) = tasks(&left, &right);
    let old_id = old.request_id().to_owned();
    assert!(left.db.lock().cancel_peer_attempt(&old_id).unwrap());
    drop(other);
    let (new, peer) = tasks(&left, &right);
    assert_ne!(old_id, new.request_id());
    drop(old);
    assert!(
        left.db
            .lock()
            .peer_attempt_current(&new.attempt, left.now_ms)
            .unwrap()
    );
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| peer.finish(true, TIMEOUT, || right.now_ms));
        assert!(new.finish(true, TIMEOUT, || left.now_ms).is_ok());
        assert!(worker.join().unwrap().is_ok());
    });
}

#[test]
fn restart_with_only_prepared_consent_does_not_grant_or_resume_old_authorization() {
    let left = Device::new();
    let right = Device::new();
    let (mut client, mut server) = tasks(&left, &right);
    let (local_exchange, remote_exchange) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            server
                .channel
                .take()
                .unwrap()
                .confirm(true, TIMEOUT)
                .unwrap()
        });
        let local = client
            .channel
            .take()
            .unwrap()
            .confirm(true, TIMEOUT)
            .unwrap();
        (local, worker.join().unwrap())
    });
    validate(local_exchange.consent(), &client.attempt, left.now_ms).unwrap();
    assert!(
        left.db
            .lock()
            .store_peer_consent(&client.attempt, left.now_ms)
            .unwrap()
    );
    assert!(
        right
            .db
            .lock()
            .store_peer_consent(&server.attempt, right.now_ms)
            .unwrap()
    );
    // Separate real connections model a restart observer before old task cleanup has run.
    let restarted = Mutex::new(SynraDb::open(&left.path).unwrap());
    assert!(
        approved_peers(
            &restarted,
            &left.credentials,
            u64::try_from(left.now_ms / 1000).unwrap()
        )
        .unwrap()
        .is_empty()
    );
    drop((local_exchange, remote_exchange, client, server));
    left.reopen(false);
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
    let _ = pair(&left, &right);
}

#[test]
fn independent_database_connections_cannot_replace_a_live_task() {
    let left = Device::new();
    let right = Device::new();
    let (client, _server) = tasks(&left, &right);
    let observer = SynraDb::open(&left.path).unwrap();
    let mut competitor = client.attempt.clone();
    competitor.request_id = RequestId::new().to_string();
    assert!(
        !observer
            .claim_peer_trust(&competitor, left.now_ms, MAX_APPROVED_PEERS)
            .unwrap()
    );
    assert!(
        observer
            .peer_attempt_current(&client.attempt, left.now_ms)
            .unwrap()
    );
    // Expired replacement is allowed, but old writes and old cleanup cannot affect the winner.
    let after_expiry = client.attempt.expires_at_ms;
    competitor.expires_at_ms = after_expiry + 1000;
    assert!(
        observer
            .claim_peer_trust(&competitor, after_expiry, MAX_APPROVED_PEERS)
            .unwrap()
    );
    assert!(
        !observer
            .store_peer_consent(&client.attempt, after_expiry)
            .unwrap()
    );
    drop(client);
    assert!(
        observer
            .peer_attempt_current(&competitor, after_expiry)
            .unwrap()
    );
}
