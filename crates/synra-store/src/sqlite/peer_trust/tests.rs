use super::*;

fn fixture() -> (tempfile::TempDir, SynraDb, PeerTrustAttempt) {
    let directory = tempfile::tempdir().unwrap();
    let mut db = SynraDb::open(&directory.path().join("trust.sqlite")).unwrap();
    db.migrate().unwrap();
    let attempt = seed(&db);
    (directory, db, attempt)
}

fn seed(db: &SynraDb) -> PeerTrustAttempt {
    db.connection.execute(
        "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) VALUES (1, 'local', 'test', 'test', 1)", [],
    ).unwrap();
    db.connection.execute(
        "INSERT INTO device_credentials (id, device_id, certificate, backend, ready) VALUES (1, 'local', X'01', 'test', 1)", [],
    ).unwrap();
    PeerTrustAttempt {
        request_id: "first".to_owned(),
        local_id: "local".to_owned(),
        local_certificate: vec![1],
        peer_id: "peer".to_owned(),
        peer_certificate: vec![2],
        binding: [3; 32],
        expires_at_ms: 100,
    }
}

#[test]
fn writable_connections_enforce_commit_sync_including_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("trust.sqlite");
    for _ in 0..2 {
        let db = SynraDb::open(&path).unwrap();
        let synchronous: i64 = db
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(
            synchronous, 2,
            "FULL is required for durable receipts and revocation"
        );
    }
}

#[test]
fn activation_failure_rolls_back_both_task_phase_and_grant() {
    let (_directory, db, attempt) = fixture();
    assert!(db.claim_peer_trust(&attempt, 1, 1).unwrap());
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    db.connection.execute_batch(
        "CREATE TRIGGER fail_grant BEFORE INSERT ON peer_trust BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;",
    ).unwrap();
    assert!(db.activate_peer_trust(&attempt, 1).is_err());
    assert!(db.trusted_peer_records("local", &[1]).unwrap().is_empty());
    let phase: i64 = db
        .connection
        .query_row("SELECT phase FROM pairing_attempt", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        phase, 1,
        "failed insertion must roll back the completed marker too"
    );
    db.connection
        .execute_batch("DROP TRIGGER fail_grant")
        .unwrap();
    assert!(db.activate_peer_trust(&attempt, 1).unwrap());
}

#[test]
fn listing_failure_cannot_leave_an_authorized_peer_without_its_committed_pairing() {
    let (_directory, db, attempt) = fixture();
    assert!(db.claim_peer_trust(&attempt, 1, 1).unwrap());
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    db.connection.execute_batch(
        "CREATE TRIGGER fail_listing BEFORE INSERT ON paired_devices BEGIN SELECT RAISE(ABORT, 'injected listing failure'); END;",
    ).unwrap();
    assert!(db.activate_peer_trust(&attempt, 1).is_err());
    assert!(db.trusted_peer_records("local", &[1]).unwrap().is_empty());
    assert!(db.paired_devices().unwrap().is_empty());
    let phase: i64 = db
        .connection
        .query_row("SELECT phase FROM pairing_attempt", [], |row| row.get(0))
        .unwrap();
    assert_eq!(phase, 1);
    db.connection
        .execute_batch("DROP TRIGGER fail_listing")
        .unwrap();
    assert!(db.activate_peer_trust(&attempt, 1).unwrap());
    assert_eq!(
        db.paired_devices().unwrap().first().unwrap().device_id,
        attempt.peer_id
    );
}

#[test]
fn an_expired_monotonic_commit_budget_rolls_back_an_otherwise_current_attempt() {
    let (_directory, db, attempt) = fixture();
    assert!(db.claim_peer_trust(&attempt, 1, 1).unwrap());
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    assert!(
        !db.activate_peer_trust_until(&attempt, 1, std::time::Instant::now())
            .unwrap()
    );
    assert!(db.trusted_peer_records("local", &[1]).unwrap().is_empty());
    assert!(db.paired_devices().unwrap().is_empty());
    let phase: i64 = db
        .connection
        .query_row("SELECT phase FROM pairing_attempt", [], |row| row.get(0))
        .unwrap();
    assert_eq!(phase, 1);
}

#[test]
fn capacity_and_existing_grants_refuse_overwrite_until_explicit_revocation() {
    let (_directory, db, mut attempt) = fixture();
    assert!(!db.claim_peer_trust(&attempt, 1, 0).unwrap());
    assert!(db.claim_peer_trust(&attempt, 1, 1).unwrap());
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    assert!(db.activate_peer_trust(&attempt, 1).unwrap());
    let old = db.trusted_peer_records("local", &[1]).unwrap().remove(0);
    attempt.request_id = "second".to_owned();
    attempt.peer_certificate = vec![4];
    assert!(
        !db.claim_peer_trust(&attempt, 1, 2).unwrap(),
        "same id cannot replace a pin"
    );
    attempt.peer_id = "another".to_owned();
    assert!(
        !db.claim_peer_trust(&attempt, 1, 1).unwrap(),
        "capacity is checked atomically"
    );
    attempt.peer_id = "peer".to_owned();
    assert!(db.unpair_device("peer").unwrap());
    assert!(db.claim_peer_trust(&attempt, 1, 1).unwrap());
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    assert!(db.activate_peer_trust(&attempt, 1).unwrap());
    assert!(!db.peer_trust_current("local", &[1], &old).unwrap());
    let new = db.trusted_peer_records("local", &[1]).unwrap().remove(0);
    assert_eq!(new.certificate, [4]);
    assert_eq!(new.generation, "second");
}

#[test]
fn a_changed_local_enrollment_invalidates_prepared_tasks_and_existing_grants() {
    let (_directory, db, mut attempt) = fixture();
    assert!(db.claim_peer_trust(&attempt, 1, 2).unwrap());
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    assert!(db.activate_peer_trust(&attempt, 1).unwrap());
    let old = db.trusted_peer_records("local", &[1]).unwrap().remove(0);
    attempt.peer_id = "another".to_owned();
    attempt.request_id = "second".to_owned();
    assert!(db.claim_peer_trust(&attempt, 1, 2).unwrap());
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    db.connection
        .execute("UPDATE device_credentials SET certificate = X'05'", [])
        .unwrap();
    assert!(!db.activate_peer_trust(&attempt, 1).unwrap());
    assert!(!db.peer_trust_current("local", &[1], &old).unwrap());
    assert!(db.trusted_peer_records("local", &[1]).unwrap().is_empty());
    assert!(!db.claim_peer_trust(&attempt, 1, 2).unwrap());
}

#[test]
fn concurrent_independent_writers_have_exactly_one_task_winner() {
    let (_source_directory, db, first) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("race.sqlite");
    db.backup_to(&path).unwrap();
    let left = SynraDb::open(&path).unwrap();
    let right = SynraDb::open(&path).unwrap();
    let mut second = first.clone();
    second.request_id = "competitor".to_owned();
    let barrier = std::sync::Barrier::new(2);
    let (left_won, right_won) = std::thread::scope(|scope| {
        let gate = &barrier;
        let first = &first;
        let worker = scope.spawn(move || {
            gate.wait();
            left.claim_peer_trust(first, 1, 1).unwrap()
        });
        barrier.wait();
        let won = right.claim_peer_trust(&second, 1, 1).unwrap();
        (worker.join().unwrap(), won)
    });
    assert_ne!(left_won, right_won);
    assert_eq!(right.peer_attempt_current(&first, 1).unwrap(), left_won);
    assert_eq!(right.peer_attempt_current(&second, 1).unwrap(), right_won);
}

#[test]
fn memory_and_weakened_commit_settings_cannot_issue_persistence_receipts() {
    let mut memory = SynraDb::open_in_memory().unwrap();
    memory.migrate().unwrap();
    let attempt = seed(&memory);
    assert!(memory.claim_peer_trust(&attempt, 1, 1).is_err());
    let (_directory, db, attempt) = fixture();
    assert!(db.claim_peer_trust(&attempt, 1, 1).unwrap());
    db.connection
        .pragma_update(None, "synchronous", "NORMAL")
        .unwrap();
    assert!(db.store_peer_consent(&attempt, 1).is_err());
    db.connection
        .pragma_update(None, "synchronous", "FULL")
        .unwrap();
    assert!(db.store_peer_consent(&attempt, 1).unwrap());
    db.connection
        .pragma_update(None, "synchronous", "NORMAL")
        .unwrap();
    assert!(db.activate_peer_trust(&attempt, 1).is_err());
    assert!(db.trusted_peer_records("local", &[1]).unwrap().is_empty());
}
