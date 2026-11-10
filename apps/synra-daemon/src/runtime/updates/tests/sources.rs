use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use synra_core::plugin_updates::{AUTO_UPDATE_KEY, CHECK_EVERY_MS};
use synra_protocol::PluginId;
use synra_core::supervisor::Cancellation;
use super::{Registry, configure, installed, signed_source};
use super::super::{check_all, source};

#[test]
fn real_downloads_keep_binary_bytes_and_refuse_http_errors() {
    use crate::runtime::registry_install::{Fetch as _, NetworkFetch};
    let registry = Registry::start();
    let bytes: Vec<u8> = (0..=255).collect();
    *registry.tarball.lock() = (200, bytes.clone());
    assert!(
        NetworkFetch::default()
            .get(&format!("{}/hello.tgz", registry.base))
            .is_err(),
        "unconfigured loopback is refused"
    );
    assert_eq!(registry.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        NetworkFetch {
            allow_loopback: true
        }
        .get(&format!("{}/hello.tgz", registry.base))
        .expect("binary"),
        bytes
    );
    *registry.tarball.lock() = (403, b"forbidden".to_vec());
    assert!(
        NetworkFetch {
            allow_loopback: true
        }
        .get(&format!("{}/hello.tgz", registry.base))
        .expect_err("HTTP error")
        .contains("403")
    );
}

#[test]
fn mirrors_retry_network_failures_but_not_integrity_or_authorization_failures() {
    let root = crate::runtime::tests::TempDir::new("update-mirrors");
    let runtime = installed(root.path());
    let first = Registry::start();
    let second = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    first.publish(&next, "1.1.0", false);
    second.publish(&next, "1.1.0", false);
    runtime
        .db()
        .set_config(
            source::REGISTRY_KEY,
            &serde_json::json!([first.base, second.base]),
            1,
        )
        .expect("mirrors");
    runtime
        .db()
        .set_config(AUTO_UPDATE_KEY, &serde_json::json!("auto-all"), 1)
        .expect("policy");
    first.tarball.lock().1.push(0);
    assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        0,
        "bad integrity never falls back"
    );
    *first.tarball.lock() = (403, Vec::new());
    assert_eq!(
        check_all(&runtime, 100 + CHECK_EVERY_MS, &Cancellation::new()).len(),
        1
    );
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        0,
        "authorization never falls back"
    );
    *first.document.lock() = (503, "offline".to_owned());
    assert!(check_all(&runtime, 100 + 2 * CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        2,
        "a working mirror supplies metadata and bytes"
    );
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.1.0")
    );
    *first.document.lock() = (200, "malformed metadata".to_owned());
    assert!(check_all(&runtime, 100 + 3 * CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        3,
        "a malformed mirror falls back to a fresh negative check"
    );
}

#[test]
fn a_waiting_registry_does_not_hold_the_database_or_plugin_lock() {
    let root = crate::runtime::tests::TempDir::new("update-locks");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "notify-only", false);
    let runtime = Arc::new(runtime);
    let held = registry.document.lock();
    let (done, finished) = std::sync::mpsc::channel();
    let worker = {
        let runtime = Arc::clone(&runtime);
        std::thread::spawn(move || {
            done.send(check_all(&runtime, 100, &Cancellation::new()))
                .expect("result")
        })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while registry.requests.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(
        runtime.db.try_lock().is_some(),
        "network requests release the store"
    );
    assert!(
        runtime.plugins.try_lock().is_some(),
        "network requests release the engine"
    );
    drop(held);
    assert_eq!(
        finished
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded result")
            .len(),
        1
    );
    worker.join().expect("worker");
}
