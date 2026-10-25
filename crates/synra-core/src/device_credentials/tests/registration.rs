use super::*;

fn damage(fixture: &Fixture, sql: &str) {
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection.execute_batch(sql).unwrap();
}

#[test]
fn lost_registration_or_identity_never_silently_reenrolls_and_explicit_repair_survives_restart() {
    for sql in ["DELETE FROM device_credentials", "DELETE FROM identity"] {
        let fixture = Fixture::new();
        let backend = FaultBackend::default();
        let old = enroll(&fixture.db, &backend, fixture.id, NOW).unwrap();
        let expected = repair_fingerprint(old.public_identity().certificate_der());
        damage(&fixture, sql);
        let restored = Identity::load(&fixture.db.lock(), "test", 2).unwrap();
        assert_eq!(restored.device_id, fixture.id);
        for result in [
            enroll(&fixture.db, &backend, fixture.id, NOW),
            load(&fixture.db, &backend, fixture.id, NOW),
        ] {
            assert!(matches!(result, Err(CredentialError::MissingRegistration)));
        }
        assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
        let status = credential_snapshot(
            &fixture.db,
            fixture.id,
            Some(*old.public_identity().fingerprint()),
        )
        .unwrap();
        assert!(status.enrollment.is_none());
        assert_eq!(status.recovery.unwrap().fingerprint, expected);
        assert!(!status.runtime_ready);
        assert!(repair(&fixture.db, &backend, fixture.id, "stale", NOW).is_err());
        assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
        let repaired = repair(&fixture.db, &backend, fixture.id, &expected, NOW).unwrap();
        assert_ne!(
            old.public_identity(),
            repaired.credentials.public_identity()
        );
        assert_eq!(repaired.cleanup.unwrap(), 0);
        assert!(backend.get(&key(&old)).unwrap().is_none());
        let reopened = Mutex::new(SynraDb::open(&fixture.path).unwrap());
        let loaded = enroll(&reopened, &backend, fixture.id, NOW).unwrap();
        assert_eq!(
            loaded.public_identity(),
            repaired.credentials.public_identity()
        );
        let status = credential_snapshot(
            &reopened,
            fixture.id,
            Some(*old.public_identity().fingerprint()),
        )
        .unwrap();
        assert!(status.recovery.is_none());
        assert!(!status.runtime_ready);
        assert!(status.restart_required);
        assert_eq!(backend.writes.load(Ordering::SeqCst), 2);
        assert!(repair(&reopened, &backend, fixture.id, &expected, NOW).is_err());
    }
}

#[test]
fn failed_registration_recovery_retains_only_the_committed_replacement() {
    for mode in [
        FAIL_BEFORE_WRITE,
        FAIL_AFTER_WRITE,
        CORRUPT_WRITE,
        LOSE_WRITE,
    ] {
        let fixture = Fixture::new();
        let backend = FaultBackend::default();
        let old = enroll(&fixture.db, &backend, fixture.id, NOW).unwrap();
        let expected = repair_fingerprint(old.public_identity().certificate_der());
        damage(&fixture, "DELETE FROM device_credentials");
        backend.mode.store(mode, Ordering::SeqCst);
        assert!(repair(&fixture.db, &backend, fixture.id, &expected, NOW).is_err());
        let replacement = fixture.record();
        assert_ne!(
            replacement.certificate(),
            old.public_identity().certificate_der()
        );
        assert!(!replacement.ready());
        backend.mode.store(NORMAL, Ordering::SeqCst);
        let reopened = Mutex::new(SynraDb::open(&fixture.path).unwrap());
        let result = enroll(&reopened, &backend, fixture.id, NOW);
        if mode == FAIL_AFTER_WRITE {
            assert_eq!(
                result.unwrap().public_identity().certificate_der(),
                replacement.certificate()
            );
        } else {
            assert!(result.is_err());
        }
        assert_eq!(backend.writes.load(Ordering::SeqCst), 2);
        // Losing the replacement marker still cannot permit a third automatic key.
        damage(&fixture, "DELETE FROM device_credentials");
        let status = credential_snapshot(&reopened, fixture.id, None).unwrap();
        assert_eq!(
            status.recovery.unwrap().fingerprint,
            repair_fingerprint(replacement.certificate())
        );
        assert!(enroll(&reopened, &backend, fixture.id, NOW).is_err());
        assert_eq!(backend.writes.load(Ordering::SeqCst), 2);
    }
}

#[test]
fn missing_identity_and_history_require_a_trusted_backup_without_any_secret_write() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    enroll(&fixture.db, &backend, fixture.id, NOW).unwrap();
    damage(
        &fixture,
        "DELETE FROM identity; DELETE FROM device_identity_history;",
    );
    let reopened = SynraDb::open(&fixture.path).unwrap();
    assert!(Identity::load(&reopened, "test", 2).is_err());
    assert!(reopened.identity().unwrap().is_none());
    assert!(enroll(&fixture.db, &backend, fixture.id, NOW).is_err());
    assert!(repair(&fixture.db, &backend, fixture.id, "anything", NOW).is_err());
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
}
