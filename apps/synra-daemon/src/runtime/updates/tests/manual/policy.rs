use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use synra_protocol::PluginId;
use synra_protocol::error::ErrorCode;
use super::super::{Registry, configure, installed, signed_source};
use synra_control::Kernel as _;

#[test]
fn a_source_changed_during_download_is_refused_before_the_old_instance_stops() {
    let root = crate::runtime::tests::TempDir::new("manual-source-race");
    let runtime = Arc::new(installed(root.path()));
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "never", false);
    let held = registry.tarball.lock();
    let (done, finished) = std::sync::mpsc::channel();
    let kernel = Arc::clone(&runtime);
    let worker = std::thread::spawn(move || {
        done.send(kernel.plugin_update("@acme/hello", None))
            .expect("result");
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while registry.requests.load(Ordering::SeqCst) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "download did not start"
        );
        std::thread::yield_now();
    }
    assert!(
        runtime.db.try_lock().is_some(),
        "download must release the store"
    );
    assert!(
        runtime.plugins.try_lock().is_some(),
        "download must release the engine"
    );
    runtime
        .plugin_registry(Some(&["https://replacement.example".to_owned()]))
        .expect("change source");
    drop(held);
    let refused = finished
        .recv_timeout(Duration::from_secs(5))
        .expect("bounded result")
        .expect_err("source changed");
    worker.join().expect("update joined");
    assert!(refused.message.contains("registry changed"));
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.0.0")
    );
    assert_eq!(
        runtime
            .db()
            .active_plugin("@acme/hello")
            .expect("row")
            .expect("installed")
            .version,
        "1.0.0"
    );
}

#[test]
fn explicit_updates_cannot_bypass_safe_mode_or_candidate_revocation() {
    for safe_mode in [true, false] {
        let root = crate::runtime::tests::TempDir::new(&format!("manual-revoked-{safe_mode}"));
        let mut runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, "1.1.0", 7, false);
        registry.publish(&next, "1.1.0", false);
        configure(&runtime, &registry, "never", false);
        if safe_mode {
            runtime.plugin_loads.lock().safe_mode = Some("safe mode".to_owned());
        } else {
            runtime.revocations = synra_plugin_api::revocation::RevocationList::parse(r#"{"revoked":[{"plugin":"@acme/hello","versions":["1.1.0"],"reason":"withdrawn"}]}"#).expect("revocation");
        }
        assert!(runtime.plugin_update("@acme/hello", None).is_err());
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            usize::from(!safe_mode)
        );
        assert_eq!(
            runtime
                .plugins
                .lock()
                .version(&PluginId::parse("@acme/hello").expect("id")),
            Some("1.0.0")
        );
    }
}

#[test]
fn manual_updates_reset_consent_for_new_permissions_and_refuse_key_changes_or_tampering() {
    for (label, seed, extra, tamper) in [
        ("caps", 7, true, false),
        ("faulted", 7, true, false),
        ("key", 9, false, false),
        ("tamper", 7, false, true),
    ] {
        let root = crate::runtime::tests::TempDir::new(&format!("manual-{label}"));
        let runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, "1.1.0-beta.1", seed, extra);
        registry.publish(&next, "1.1.0-beta.1", false);
        configure(&runtime, &registry, "never", false);
        if label == "faulted" {
            let id = PluginId::parse("@acme/hello").expect("id");
            synra_core::plugin::deactivate(&mut runtime.plugins.lock(), &id, 1);
            runtime
                .plugin_loads
                .lock()
                .record_refused("@acme/hello", "old activation failed".to_owned());
        }
        if tamper {
            registry.tarball.lock().1.push(0);
            assert_eq!(
                runtime
                    .plugin_update("@acme/hello", None)
                    .expect_err("integrity")
                    .code,
                ErrorCode::IntegrityMismatch
            );
            assert_eq!(
                runtime
                    .plugins
                    .lock()
                    .version(&PluginId::parse("@acme/hello").expect("id")),
                Some("1.0.0")
            );
        } else if seed != 7 {
            let refused = runtime
                .plugin_update("@acme/hello", Some("1.1.0-beta.1"))
                .expect_err("changed signer");
            assert!(refused.message.contains("publisher-trust"));
            assert_eq!(
                runtime
                    .plugins
                    .lock()
                    .version(&PluginId::parse("@acme/hello").expect("id")),
                Some("1.0.0")
            );
        } else {
            let updated = runtime
                .plugin_update("@acme/hello", Some("1.1.0-beta.1"))
                .expect("manual prerelease");
            assert_eq!(updated["loaded"], false);
            assert_eq!(updated["enabled"], false);
            assert!(
                updated["activationError"].is_null(),
                "old activation failures must not describe the new version"
            );
            let row = runtime.db().plugins().expect("plugins").remove(0);
            assert!(!row.enabled && !row.trusted);
            assert!(
                !runtime
                    .plugins
                    .lock()
                    .contains(&PluginId::parse("@acme/hello").expect("id"))
            );
        }
        let staging = runtime.paths.cache_dir().join("registry");
        assert!(
            !staging.exists()
                || std::fs::read_dir(staging)
                    .expect("staging")
                    .next()
                    .is_none()
        );
    }
}
