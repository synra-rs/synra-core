use std::sync::atomic::Ordering;
use synra_protocol::PluginId;
use synra_core::supervisor::Cancellation;
use super::{Registry, configure, installed, signed_source};
use super::super::check_all;
use synra_control::Kernel as _;

#[test]
fn both_registry_formats_apply_only_policy_and_signature_admitted_updates() {
    for (index, (version, policy, seed, extra, is_static, applies)) in [
        ("1.0.1", "auto-minor", 7, false, false, true),
        ("1.1.0", "auto-minor", 7, false, true, true),
        ("2.0.0", "auto-all", 7, false, false, true),
        ("2.0.0", "auto-minor", 7, false, false, false),
        ("1.1.0", "auto-all", 9, false, false, false),
        ("1.1.0", "auto-all", 7, true, false, false),
        ("1.1.0", "notify-only", 7, false, false, false),
        ("1.1.0", "never", 7, false, false, false),
    ]
    .into_iter()
    .enumerate()
    {
        let root = crate::runtime::tests::TempDir::new(&format!("update-matrix-{index}"));
        let runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, version, seed, extra);
        registry.publish(&next, version, is_static);
        configure(&runtime, &registry, policy, is_static);
        let updates = check_all(&runtime, 100, &Cancellation::new());
        let expected = if applies { version } else { "1.0.0" };
        assert_eq!(
            runtime
                .db()
                .active_plugin("@acme/hello")
                .expect("row")
                .expect("installed")
                .version,
            expected,
            "case {index}"
        );
        assert_eq!(
            runtime
                .plugins
                .lock()
                .version(&PluginId::parse("@acme/hello").expect("id")),
            Some(expected),
            "running case {index}"
        );
        assert_eq!(updates.is_empty(), applies || policy == "never");
        if !applies && policy != "never" {
            let listing = runtime.plugins().expect("report");
            assert_eq!(listing["plugins"][0]["update"]["version"], version);
            assert_eq!(listing["plugins"][0]["updateCheckedAtMs"], 100);
        }
        if policy == "notify-only" {
            assert_eq!(registry.requests.load(Ordering::SeqCst), 1);
        }
        if policy == "never" {
            assert_eq!(registry.requests.load(Ordering::SeqCst), 0);
        }
        let cache = runtime.paths.cache_dir().join("registry");
        assert!(
            !cache.exists() || cache.read_dir().expect("cache").next().is_none(),
            "download cleanup"
        );
    }
}

#[test]
fn safe_mode_and_known_revocations_preserve_the_installed_running_version() {
    for safe_mode in [true, false] {
        let root = crate::runtime::tests::TempDir::new(&format!("update-revoked-{safe_mode}"));
        let mut runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, "1.1.0", 7, false);
        registry.publish(&next, "1.1.0", false);
        configure(&runtime, &registry, "auto-all", false);
        if safe_mode {
            runtime.plugin_loads.lock().safe_mode = Some("safe mode".to_owned());
        } else {
            runtime.revocations = synra_plugin_api::revocation::RevocationList::parse(r#"{"revoked":[{"plugin":"@acme/hello","versions":["1.1.0"],"reason":"withdrawn"}]}"#).expect("revocation");
        }
        assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            1,
            "no download for a forbidden replacement"
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
fn revoking_a_publisher_stops_its_installed_plugin() {
    // ★ The revocation is about the running code, not only the row the installer consults. v1 keeps one key per
    // publisher, so the installed manifest's publisher id names the same set the signature would.
    let root = crate::runtime::tests::TempDir::new("publisher-revoke");
    let runtime = installed(root.path());
    let fingerprint = runtime.db().publishers().expect("publishers")[0]
        .fingerprint
        .clone();
    let id = PluginId::parse("@acme/hello").expect("a plugin id");
    assert!(
        runtime.plugins.lock().contains(&id),
        "the fixture starts loaded"
    );

    runtime
        .plugin_publisher_decide("@acme", &fingerprint, "revoked")
        .expect("revoke the key");

    let row = runtime
        .db()
        .plugins()
        .expect("plugins")
        .into_iter()
        .find(|row| row.plugin_id == "@acme/hello")
        .expect("the plugin row");
    assert!(!row.enabled, "a revoked publisher's plugin is switched off");
    assert!(!row.trusted, "and its trust goes with the key");
    assert!(
        !runtime.plugins.lock().contains(&id),
        "the running instance is unloaded"
    );
}
