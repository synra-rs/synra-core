use std::time::Duration;

use super::*;

#[test]
fn failed_or_lost_writes_leave_incomplete_markers_without_replacing_keys() {
    for mode in [FAIL_BEFORE_WRITE, CORRUPT_WRITE, LOSE_WRITE] {
        let fixture = Fixture::new();
        let backend = FaultBackend::default();
        backend.mode.store(mode, Ordering::SeqCst);
        assert!(enroll(&fixture.db, &backend, fixture.id, NOW).is_err());
        let before = fixture.record();
        assert!(!before.ready());
        backend.mode.store(NORMAL, Ordering::SeqCst);
        assert!(enroll(&fixture.db, &backend, fixture.id, NOW).is_err());
        assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.record(), before);
    }
}

#[test]
fn restart_recovers_a_secret_written_before_an_error_was_reported() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    backend.mode.store(FAIL_AFTER_WRITE, Ordering::SeqCst);
    assert!(matches!(
        enroll(&fixture.db, &backend, fixture.id, NOW),
        Err(CredentialError::Secret(_))
    ));
    let before = fixture.record();
    assert!(!before.ready());
    drop(fixture.db);
    let reopened = Mutex::new(SynraDb::open(&fixture.path).expect("reopen"));
    let loaded = load(&reopened, &backend, fixture.id, NOW).expect("recover same key");
    assert_eq!(
        loaded.public_identity().certificate_der(),
        before.certificate()
    );
    assert!(
        reopened
            .lock()
            .device_credential()
            .expect("read")
            .expect("marker")
            .ready()
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_database_commit_can_recover_on_the_next_writable_restart() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    let generated = DeviceCredentials::generate(fixture.id, NOW).expect("generate");
    assert!(
        fixture
            .db
            .lock()
            .claim_device_credential(
                &fixture.id.to_string(),
                generated.public_identity().certificate_der(),
                backend.kind().as_str()
            )
            .expect("claim")
    );
    backend
        .values
        .set(
            &key(&generated),
            &SecretBytes::new(generated.private_key_der().to_vec()),
        )
        .expect("secret written");
    drop(fixture.db);
    let readonly = Mutex::new(SynraDb::open_read_only(&fixture.path).expect("readonly"));
    assert!(matches!(
        load(&readonly, &backend, fixture.id, NOW),
        Err(CredentialError::Database(_))
    ));
    assert!(
        !readonly
            .lock()
            .device_credential()
            .expect("read")
            .expect("marker")
            .ready()
    );
    drop(readonly);
    let reopened = Mutex::new(SynraDb::open(&fixture.path).expect("writable"));
    let recovered = load(&reopened, &backend, fixture.id, NOW).expect("finish");
    assert_eq!(recovered.public_identity(), generated.public_identity());
}

#[test]
fn a_local_identity_change_during_secret_io_cannot_commit_a_stale_credential() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    let original = enroll(&fixture.db, &backend, fixture.id, NOW).expect("enroll");
    let path = fixture.path.clone();
    let changed_id = DeviceId::new();
    *backend.before_get.lock() = Some(Box::new(move || {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE identity SET device_id = ?1",
                [changed_id.to_string()],
            )
            .unwrap();
    }));
    assert!(matches!(
        load(&fixture.db, &backend, fixture.id, NOW),
        Err(CredentialError::IdentityChanged)
    ));
    assert!(matches!(
        load(&fixture.db, &backend, changed_id, NOW),
        Err(CredentialError::IdentityChanged)
    ));
    assert_eq!(
        fixture.record().certificate(),
        original.public_identity().certificate_der()
    );
}

#[test]
fn competing_database_connections_cannot_overwrite_an_enrollment_in_progress() {
    let fixture = Fixture::new();
    let contender = Mutex::new(SynraDb::open(&fixture.path).expect("second connection"));
    let backend = Arc::new(FaultBackend::default());
    let (started, progress) = std::sync::mpsc::channel();
    let (finish, released) = std::sync::mpsc::channel();
    *backend.before_set.lock() = Some(Box::new(move || {
        started.send(()).expect("started");
        released
            .recv_timeout(Duration::from_secs(3))
            .expect("release");
    }));
    let db = Arc::clone(&fixture.db);
    let writer_backend = Arc::clone(&backend);
    let id = fixture.id;
    let writer = std::thread::spawn(move || enroll(&db, writer_backend.as_ref(), id, NOW));
    progress
        .recv_timeout(Duration::from_secs(3))
        .expect("durable claim reached secret store");
    let observed = contender
        .lock()
        .device_credential()
        .expect("read")
        .expect("marker");
    assert!(!observed.ready());
    assert!(matches!(
        enroll(&contender, backend.as_ref(), id, NOW),
        Err(CredentialError::OperationBusy)
    ));
    finish.send(()).expect("finish write");
    let winner = writer.join().expect("thread").expect("enroll");
    let loser = enroll(&contender, backend.as_ref(), id, NOW).expect("reuse winner");
    assert_eq!(winner.public_identity(), loser.public_identity());
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
}
