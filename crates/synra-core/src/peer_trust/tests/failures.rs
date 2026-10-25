use super::*;
use std::cell::Cell;

#[test]
fn cancellation_before_consent_denies_both_sides() {
    let left = Device::new();
    let right = Device::new();
    let (client, server) = tasks(&left, &right);
    left.unpair(&right);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
        assert!(matches!(
            client.finish(true, TIMEOUT, || left.now_ms),
            Err(TrustError::Stale)
        ));
        assert!(worker.join().unwrap().is_err());
    });
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
}

#[test]
fn decline_never_persists_a_grant() {
    let left = Device::new();
    let right = Device::new();
    let (client, server) = tasks(&left, &right);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
        assert!(client.finish(false, TIMEOUT, || left.now_ms).is_err());
        assert!(worker.join().unwrap().is_err());
    });
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
}

#[test]
fn failed_consent_write_sends_no_success_receipt_and_never_grants_after_restart() {
    let left = Device::new();
    let right = Device::new();
    let (client, server) = tasks(&left, &right);
    left.reopen(true);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
        assert!(matches!(
            client.finish(true, TIMEOUT, || left.now_ms),
            Err(TrustError::Database(_))
        ));
        assert!(worker.join().unwrap().is_err());
    });
    left.reopen(false);
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
}

#[test]
fn revocation_and_expiry_at_each_commit_boundary_refuse_late_activation() {
    for phase in [2, 3] {
        for expire in [false, true] {
            let left = Device::new();
            let right = Device::new();
            let (client, server) = tasks(&left, &right);
            let expired = client.attempt.expires_at_ms;
            let samples = Cell::new(0);
            let result = std::thread::scope(|scope| {
                let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
                let result = client.finish(true, TIMEOUT, || {
                    let sample = samples.get() + 1;
                    samples.set(sample);
                    if sample == phase {
                        if expire {
                            return expired;
                        }
                        left.unpair(&right);
                    }
                    left.now_ms
                });
                let remote = worker.join().unwrap();
                if phase == 2 {
                    assert!(remote.is_err());
                }
                result
            });
            assert!(matches!(result, Err(TrustError::Stale)), "phase {phase}");
            assert!(left.approvals().is_empty());
            left.reopen(false);
            assert!(left.approvals().is_empty());
        }
    }
}

#[test]
fn activation_write_failure_after_receipts_cannot_create_a_local_grant() {
    let left = Device::new();
    let right = Device::new();
    let (client, server) = tasks(&left, &right);
    let samples = Cell::new(0);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
        let result = client.finish(true, TIMEOUT, || {
            samples.set(samples.get() + 1);
            if samples.get() == 3 {
                left.reopen(true);
            }
            left.now_ms
        });
        assert!(matches!(result, Err(TrustError::Database(_))));
        // Receipt delivery cannot guarantee that the other peer's final commit also succeeds.
        let _ = worker.join().unwrap();
    });
    left.reopen(false);
    assert!(left.approvals().is_empty());
}

#[test]
fn changing_the_local_identity_during_consent_denies_commit() {
    let left = Device::new();
    let right = Device::new();
    let (client, server) = tasks(&left, &right);
    let samples = Cell::new(0);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
        let result = client.finish(true, TIMEOUT, || {
            samples.set(samples.get() + 1);
            if samples.get() == 2 {
                let db = left.db.lock();
                let mut identity = db.identity().unwrap().unwrap();
                identity.device_id = DeviceId::new().to_string();
                db.write_identity(&identity).unwrap();
            }
            left.now_ms
        });
        assert!(matches!(result, Err(TrustError::Stale)));
        assert!(worker.join().unwrap().is_err());
    });
    assert!(left.approvals().is_empty());
    assert!(right.approvals().is_empty());
}

#[test]
fn authorization_database_errors_never_become_permission() {
    let left = Device::new();
    let right = Device::new();
    let (approval, _) = pair(&left, &right);
    let (stream, _remote) = business(&left, &right);
    let unreadable = Mutex::new(SynraDb::open_in_memory().unwrap());
    assert!(matches!(
        approval.allows(&unreadable, &stream, right.id()),
        Err(TrustError::Database(_))
    ));
}

#[test]
fn approval_checks_the_actual_local_tls_certificate_not_just_its_id() {
    let mut left = Device::new();
    let right = Device::new();
    let (approval, _) = pair(&left, &right);
    left.credentials =
        DeviceCredentials::generate(left.id(), u64::try_from(left.now_ms / 1000).unwrap()).unwrap();
    let (stream, _remote) = business(&left, &right);
    assert!(!approval.allows(&left.db, &stream, right.id()).unwrap());
}
