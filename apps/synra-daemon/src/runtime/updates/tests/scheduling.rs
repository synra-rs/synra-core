use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use synra_core::plugin_updates::CHECK_EVERY_MS;
use synra_core::supervisor::{Cancellation, Supervisor};
use super::{Registry, configure, installed, signed_source};
use super::super::{check_all, start};
use parking_lot::Mutex;

#[test]
fn failed_downloads_back_off_across_restart_and_preserve_the_installed_version() {
    let root = crate::runtime::tests::TempDir::new("bounded-update-retries");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    *registry.tarball.lock() = (503, b"unavailable".to_vec());
    configure(&runtime, &registry, "auto-all", false);
    let cancel = Cancellation::new();
    assert_eq!(check_all(&runtime, 100, &cancel).len(), 1);
    let saved = runtime
        .db()
        .plugin_update_check("@acme/hello")
        .expect("read")
        .expect("check");
    assert_eq!(saved.attempts, 1);
    let backup = root.path().join("retry-restart.sqlite3");
    runtime.db().backup_to(&backup).expect("snapshot");
    let mut restarted = crate::runtime::tests::runtime(root.path());
    restarted.db = Arc::new(Mutex::new(
        synra_store::SynraDb::open(&backup).expect("reopen"),
    ));
    let mut next_attempt = saved.retry_at_ms.expect("deadline");
    for attempt in 2..=3 {
        let requests = registry.requests.load(Ordering::SeqCst);
        assert!(check_all(&restarted, next_attempt - 1, &cancel).is_empty());
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            requests,
            "no request before the retry deadline"
        );
        assert_eq!(check_all(&restarted, next_attempt, &cancel).len(), 1);
        assert!(registry.requests.load(Ordering::SeqCst) > requests);
        let saved = restarted
            .db()
            .plugin_update_check("@acme/hello")
            .expect("read")
            .expect("check");
        assert_eq!(saved.attempts, attempt);
        next_attempt = saved
            .retry_at_ms
            .unwrap_or(saved.checked_at_ms + CHECK_EVERY_MS);
        assert_eq!(saved.retry_at_ms.is_none(), attempt == 3);
    }
    let requests = registry.requests.load(Ordering::SeqCst);
    assert!(check_all(&restarted, next_attempt - 1, &cancel).is_empty());
    assert_eq!(
        registry.requests.load(Ordering::SeqCst),
        requests,
        "the daily check takes over"
    );
    assert_eq!(
        restarted
            .db()
            .active_plugin("@acme/hello")
            .expect("read")
            .expect("installed")
            .version,
        "1.0.0"
    );
}

#[test]
fn successful_checks_survive_restart_and_offline_failures_keep_the_last_answer() {
    let root = crate::runtime::tests::TempDir::new("update-restart");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "notify-only", false);
    assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
    let backup = root.path().join("restart.sqlite3");
    runtime.db().backup_to(&backup).expect("snapshot");
    let mut restarted = crate::runtime::tests::runtime(root.path());
    restarted.db = Arc::new(Mutex::new(
        synra_store::SynraDb::open(&backup).expect("reopen"),
    ));
    assert!(check_all(&restarted, 100 + CHECK_EVERY_MS - 1, &Cancellation::new()).is_empty());
    assert_eq!(registry.requests.load(Ordering::SeqCst), 1);
    *registry.document.lock() = (503, "offline".to_owned());
    assert!(check_all(&restarted, 100 + CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        restarted
            .db()
            .plugin_update_check("@acme/hello")
            .expect("saved")
            .expect("check")
            .available_version
            .as_deref(),
        Some("1.1.0")
    );
    registry.publish(&next, "1.0.0", false);
    assert!(check_all(&restarted, 100 + CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert!(
        restarted
            .db()
            .plugin_update_check("@acme/hello")
            .expect("negative")
            .expect("check")
            .available_version
            .is_none()
    );
}

#[test]
fn a_registered_worker_runs_and_shutdown_interrupts_its_five_minute_wait() {
    let root = crate::runtime::tests::TempDir::new("update-worker");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "notify-only", false);
    let runtime = Arc::new(runtime);
    let supervisor = Arc::new(Supervisor::new(1));
    let worker = start(&runtime, &supervisor).expect("registered worker");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while runtime
        .db()
        .plugin_update_check("@acme/hello")
        .expect("saved")
        .is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "worker checked before deadline"
        );
        std::thread::yield_now();
    }
    let stopped = std::time::Instant::now();
    let _ = supervisor.begin_shutdown();
    while !worker.is_finished() {
        assert!(stopped.elapsed() < Duration::from_secs(5));
        std::thread::yield_now();
    }
    worker.join().expect("worker stopped");
    assert_eq!(registry.requests.load(Ordering::SeqCst), 1);
}
