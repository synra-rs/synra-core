use super::*;
use crate::IdentityRow;

fn fixture() -> (tempfile::TempDir, SynraDb, DeviceCredentialRecord) {
    let directory = tempfile::tempdir().unwrap();
    let mut db = SynraDb::open(&directory.path().join("identity.sqlite")).unwrap();
    db.migrate().unwrap();
    db.create_identity_if_absent(
        &IdentityRow::from_columns(Some("local"), Some("Local"), Some("test"), Some(1)).unwrap(),
    )
    .unwrap();
    assert!(
        db.claim_device_credential("local", b"original", "test")
            .unwrap()
    );
    let expected = db.device_credential().unwrap().unwrap();
    db.finish_device_credential(&expected).unwrap();
    let expected = db.device_credential().unwrap().unwrap();
    (directory, db, expected)
}

fn seed_authority(db: &SynraDb) {
    db.connection.execute_batch(
        "INSERT INTO peer_trust VALUES ('peer', 'local', x'01', x'02', 'generation', zeroblob(32), 1);
         INSERT INTO pairing_attempt VALUES (1, 'attempt', 'local', x'01', 'pending', x'03', NULL, 10, -1);
         INSERT INTO paired_devices (device_id, display_name, platform, features, link_token, paired_at_ms)
             VALUES ('peer', 'Peer', 'test', '[]', '', 1);",
    ).unwrap();
}

fn count(db: &SynraDb, table: &str) -> i64 {
    db.connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn replacement_revokes_grants_metadata_and_unbound_pairing_in_the_same_commit() {
    let (_directory, db, expected) = fixture();
    seed_authority(&db);
    assert!(
        db.replace_device_credential(&expected, b"new", "test")
            .unwrap()
    );
    assert!(!db.device_credential().unwrap().unwrap().ready());
    for table in ["peer_trust", "paired_devices", "pairing_attempt"] {
        assert_eq!(count(&db, table), 0);
    }
    assert_eq!(db.retired_device_credentials().unwrap().len(), 1);
    assert!(!db.finish_device_credential(&expected).unwrap());
}

#[test]
fn competing_connection_and_retired_certificate_cannot_replace_the_winner() {
    let (directory, db, expected) = fixture();
    let other = SynraDb::open(&directory.path().join("identity.sqlite")).unwrap();
    assert!(
        db.replace_device_credential(&expected, b"winner", "test")
            .unwrap()
    );
    assert!(
        !other
            .replace_device_credential(&expected, b"loser", "test")
            .unwrap()
    );
    let winner = other.device_credential().unwrap().unwrap();
    assert!(
        !other
            .replace_device_credential(&winner, b"original", "test")
            .unwrap()
    );
    assert_eq!(winner.certificate(), b"winner");
}

#[test]
fn revocation_failure_rolls_back_the_new_marker_and_cleanup_record() {
    let (_directory, db, expected) = fixture();
    seed_authority(&db);
    db.connection
        .execute_batch(
            "CREATE TRIGGER reject_revoke BEFORE DELETE ON peer_trust
         BEGIN SELECT RAISE(ABORT, 'injected revocation failure'); END;",
        )
        .unwrap();
    assert!(
        db.replace_device_credential(&expected, b"new", "test")
            .is_err()
    );
    assert_eq!(db.device_credential().unwrap().unwrap(), expected);
    assert!(db.retired_device_credentials().unwrap().is_empty());
    assert_eq!(count(&db, "peer_trust"), 1);
    assert_eq!(count(&db, "pairing_attempt"), 1);
}

#[test]
fn cleanup_capacity_refuses_more_replacements_without_changing_the_current_identity() {
    let (_directory, db, _) = fixture();
    for index in 0..MAX_RETIRED_DEVICE_CREDENTIALS {
        let current = db.device_credential().unwrap().unwrap();
        assert!(
            db.replace_device_credential(
                &current,
                format!("replacement-{index}").as_bytes(),
                "test"
            )
            .unwrap()
        );
    }
    let current = db.device_credential().unwrap().unwrap();
    assert!(
        !db.replace_device_credential(&current, b"overflow", "test")
            .unwrap()
    );
    assert_eq!(db.device_credential().unwrap().unwrap(), current);
    assert_eq!(
        db.retired_device_credentials().unwrap().len(),
        MAX_RETIRED_DEVICE_CREDENTIALS as usize
    );
}

#[test]
fn maintenance_reads_never_mix_a_certificate_with_another_replacements_cleanup_count() {
    let (directory, db, _) = fixture();
    let writer = SynraDb::open(&directory.path().join("identity.sqlite")).unwrap();
    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let finished = &done;
        scope.spawn(move || {
            for index in 0..MAX_RETIRED_DEVICE_CREDENTIALS {
                let expected = writer.device_credential().unwrap().unwrap();
                assert!(
                    writer
                        .replace_device_credential(
                            &expected,
                            format!("generation-{index}").as_bytes(),
                            "test"
                        )
                        .unwrap()
                );
            }
            finished.store(true, std::sync::atomic::Ordering::Release);
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = db.device_credential_state().unwrap().unwrap();
            let record = state.enrollment.unwrap();
            let certificate = std::str::from_utf8(record.certificate()).unwrap();
            let expected = certificate
                .strip_prefix("generation-")
                .map_or(0, |number| number.parse::<u32>().unwrap() + 1);
            assert_eq!(state.retired_keys, expected);
            if done.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writer did not finish"
            );
        }
    });
}
