use super::*;

fn fingerprint(record: &DeviceCredentialRecord) -> String {
    repair_fingerprint(record.certificate())
}

#[test]
fn explicit_repair_replaces_a_missing_key_and_survives_reopening_the_database() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    let old = enroll(&fixture.db, &backend, fixture.id, NOW).unwrap();
    let expected = fixture.record();
    backend.delete(&key(&old)).unwrap();
    assert!(matches!(
        load(&fixture.db, &backend, fixture.id, NOW),
        Err(CredentialError::MissingKey)
    ));
    let repaired = repair(
        &fixture.db,
        &backend,
        fixture.id,
        &fingerprint(&expected),
        NOW,
    )
    .unwrap();
    assert_ne!(
        old.public_identity(),
        repaired.credentials.public_identity()
    );
    assert_eq!(repaired.cleanup.unwrap(), 0);
    let reopened = Mutex::new(SynraDb::open(&fixture.path).unwrap());
    let loaded = load(&reopened, &backend, fixture.id, NOW).unwrap();
    assert_eq!(
        loaded.public_identity(),
        repaired.credentials.public_identity()
    );
    assert!(matches!(
        repair(
            &reopened,
            &backend,
            fixture.id,
            &fingerprint(&expected),
            NOW
        ),
        Err(CredentialError::RepairRefused)
    ));
}

#[test]
fn replacement_write_failure_never_restores_the_old_ready_marker_or_generates_on_load() {
    for mode in [
        FAIL_BEFORE_WRITE,
        FAIL_AFTER_WRITE,
        CORRUPT_WRITE,
        LOSE_WRITE,
    ] {
        let fixture = Fixture::new();
        let backend = FaultBackend::default();
        let old = enroll(&fixture.db, &backend, fixture.id, NOW).unwrap();
        let expected = fixture.record();
        backend.mode.store(mode, Ordering::SeqCst);
        assert!(
            repair(
                &fixture.db,
                &backend,
                fixture.id,
                &fingerprint(&expected),
                NOW
            )
            .is_err()
        );
        let replacement = fixture.record();
        assert_ne!(
            replacement.certificate(),
            old.public_identity().certificate_der()
        );
        assert!(!replacement.ready());
        backend.mode.store(NORMAL, Ordering::SeqCst);
        let reopened = Mutex::new(SynraDb::open(&fixture.path).unwrap());
        let result = load(&reopened, &backend, fixture.id, NOW);
        if mode == FAIL_AFTER_WRITE {
            assert_eq!(
                result.unwrap().public_identity().certificate_der(),
                replacement.certificate()
            );
        } else {
            assert!(result.is_err());
        }
        assert_eq!(backend.writes.load(Ordering::SeqCst), 2);
        assert_eq!(cleanup_retired(&reopened, &backend).unwrap(), 0);
        assert!(backend.get(&key(&old)).unwrap().is_none());
    }
}

#[test]
fn competing_repair_while_secret_io_runs_is_refused_without_a_database_lock() {
    let fixture = Fixture::new();
    let backend = Arc::new(FaultBackend::default());
    let old = enroll(&fixture.db, backend.as_ref(), fixture.id, NOW).unwrap();
    let expected = fixture.record();
    let other_db = Arc::new(Mutex::new(SynraDb::open(&fixture.path).unwrap()));
    let other_backend = Arc::clone(&backend);
    let id = fixture.id;
    *backend.before_set.lock() = Some(Box::new(move || {
        // The outer operation has durably claimed its candidate, with no DB mutex held during IO.
        let marker = other_db.lock().device_credential().unwrap().unwrap();
        assert!(matches!(
            repair(
                &other_db,
                other_backend.as_ref(),
                id,
                &fingerprint(&marker),
                NOW
            ),
            Err(CredentialError::OperationBusy)
        ));
    }));
    assert!(
        repair(
            &fixture.db,
            backend.as_ref(),
            fixture.id,
            &fingerprint(&expected),
            NOW
        )
        .is_ok()
    );
    assert!(load(&fixture.db, backend.as_ref(), fixture.id, NOW).is_ok());
    assert_ne!(
        fixture.record().certificate(),
        old.public_identity().certificate_der()
    );
}

#[test]
fn cleanup_failure_is_separate_from_replacement_and_is_retried_after_reopening() {
    for mode in [FAIL_BEFORE_WRITE, FAIL_AFTER_WRITE, LOSE_WRITE] {
        let fixture = Fixture::new();
        let backend = FaultBackend::default();
        let old = enroll(&fixture.db, &backend, fixture.id, NOW).unwrap();
        let expected = fixture.record();
        backend.delete_mode.store(mode, Ordering::SeqCst);
        let repaired = repair(
            &fixture.db,
            &backend,
            fixture.id,
            &fingerprint(&expected),
            NOW,
        )
        .unwrap();
        assert!(repaired.cleanup.is_err());
        assert!(fixture.record().ready());
        assert_eq!(
            fixture
                .db
                .lock()
                .retired_device_credentials()
                .unwrap()
                .len(),
            1
        );
        backend.delete_mode.store(NORMAL, Ordering::SeqCst);
        let reopened = Mutex::new(SynraDb::open(&fixture.path).unwrap());
        assert_eq!(cleanup_retired(&reopened, &backend).unwrap(), 0);
        assert!(backend.get(&key(&old)).unwrap().is_none());
        assert!(backend.get(&key(&repaired.credentials)).unwrap().is_some());
        assert_eq!(
            load(&reopened, &backend, fixture.id, NOW)
                .unwrap()
                .public_identity(),
            repaired.credentials.public_identity()
        );
    }
}

#[test]
fn credential_operation_child_process() {
    let Some(path) = std::env::var_os("SYNRA_TEST_CREDENTIAL_LOCK_DB") else {
        return;
    };
    let db = Mutex::new(SynraDb::open(std::path::Path::new(&path)).unwrap());
    let result = operation::acquire(&db);
    if std::env::var_os("SYNRA_TEST_CREDENTIAL_LOCK_BUSY").is_some() {
        assert!(matches!(result, Err(CredentialError::OperationBusy)));
    } else {
        let _held_until_process_exit = result.unwrap();
        // Intentionally bypass Rust destructors: the OS must release the actual file lock.
        std::process::exit(0);
    }
}

#[test]
fn operation_lock_excludes_another_process_and_is_released_after_process_exit() {
    fn child(path: &std::path::Path, expect_busy: bool) {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "device_credentials::tests::repair::credential_operation_child_process",
            ])
            .env("SYNRA_TEST_CREDENTIAL_LOCK_DB", path);
        if expect_busy {
            command.env("SYNRA_TEST_CREDENTIAL_LOCK_BUSY", "1");
        }
        let mut process = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = process.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                process.kill().unwrap();
                process.wait().unwrap();
                panic!("credential child process exceeded its deadline");
            }
            std::thread::yield_now();
        }
    }
    let fixture = Fixture::new();
    let operation = operation::acquire(&fixture.db).unwrap();
    child(&fixture.path, true);
    drop(operation);
    child(&fixture.path, false);
    let reacquired = operation::acquire(&fixture.db).unwrap();
    drop(reacquired);
}
