use std::sync::atomic::Ordering;
use synra_protocol::error::ErrorCode;
use super::super::{Registry, configure, installed, signed_source};
use synra_control::Kernel as _;

#[test]
fn invalid_settings_and_missing_targets_have_no_installation_side_effects() {
    let root = crate::runtime::tests::TempDir::new("manual-invalid");
    let runtime = installed(root.path());
    for url in [
        "http://example.com",
        "ftp://example.com",
        "https://user@example.com",
        "https://example.com/path",
        "static:https://example.com?token=secret",
    ] {
        assert!(
            runtime.plugin_registry(Some(&[url.to_owned()])).is_err(),
            "{url}"
        );
    }
    assert!(runtime.plugin_update_policy(Some("yes")).is_err());
    assert!(runtime.db().config().expect("config").is_empty());
    let registry = Registry::start();
    configure(&runtime, &registry, "never", false);
    assert_eq!(
        runtime
            .plugin_check_updates(Some("@acme/missing"))
            .expect_err("missing")
            .code,
        ErrorCode::PluginNotInstalled
    );
    assert_eq!(
        runtime
            .plugin_update("@acme/missing", None)
            .expect_err("missing")
            .code,
        ErrorCode::PluginNotInstalled
    );
    assert_eq!(registry.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn checks_preserve_cached_answers_and_report_per_plugin_network_failures() {
    let root = crate::runtime::tests::TempDir::new("manual-offline");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "never", false);
    let first = crate::runtime::updates::manual::check(&runtime, None, 100).expect("check");
    *registry.document.lock() = (503, "offline".to_owned());
    let offline = crate::runtime::updates::manual::check(&runtime, None, 200).expect("report");
    assert_eq!(first["updateChecks"], offline["updateChecks"]);
    assert_eq!(offline["failures"].as_array().expect("failures").len(), 1);
}
