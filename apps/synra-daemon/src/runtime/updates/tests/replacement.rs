use std::sync::Arc;
use parking_lot::Mutex;
use synra_core::plugin_updates::CHECK_EVERY_MS;
use synra_protocol::PluginId;
use synra_plugin_api::update::UpdatePolicy;
use synra_core::supervisor::Cancellation;
use super::{Registry, configure, installed, signed_source};
use super::super::{apply, check_all, registry_setting, source};
use synra_control::Kernel as _;

#[test]
fn a_refused_commit_restores_the_old_files_permissions_and_running_instance() {
    let root = crate::runtime::tests::TempDir::new("update-rollback");
    let mut runtime = installed(root.path());
    let registry = Registry::start();
    configure(&runtime, &registry, "auto-all", false);
    let previous = runtime.db().plugin_grants("@acme/hello").expect("grants");
    let raw = registry_setting(&runtime.db()).expect("registry");
    let backup = root.path().join("read-only.sqlite3");
    runtime.db().backup_to(&backup).expect("backup");
    runtime.db = Arc::new(Mutex::new(
        synra_store::SynraDb::open_read_only(&backup).expect("read-only database"),
    ));
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    assert!(
        apply::directory(
            &runtime,
            ("@acme/hello", "1.1.0"),
            &next,
            raw.as_deref(),
            UpdatePolicy::AutoAll,
            100,
            &Cancellation::new()
        )
        .is_err()
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
    assert_eq!(
        runtime.db().plugin_grants("@acme/hello").expect("grants"),
        previous
    );
    let manifest = std::fs::read_to_string(runtime.plugins_dir.join("acme+hello/manifest.json"))
        .expect("restored manifest");
    assert_eq!(
        synra_plugin_api::Manifest::from_json(&manifest)
            .expect("manifest")
            .version,
        "1.0.0"
    );
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.0.0")
    );
    assert_eq!(runtime.plugin_loads.lock().len(), 1);
}

#[test]
fn cancellation_and_changed_policy_registry_or_target_do_not_stop_the_old_instance() {
    let root = crate::runtime::tests::TempDir::new("update-cancel");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    for (policy, cancelled, changed_registry, plugin, version) in [
        ("never", false, false, "@acme/hello", "1.1.0"),
        ("auto-all", true, false, "@acme/hello", "1.1.0"),
        ("auto-all", false, true, "@acme/hello", "1.1.0"),
        ("auto-all", false, false, "@acme/other", "1.1.0"),
        ("auto-all", false, false, "@acme/hello", "2.0.0"),
    ] {
        configure(&runtime, &registry, policy, false);
        let raw = registry_setting(&runtime.db()).expect("registry");
        if changed_registry {
            runtime
                .db()
                .set_config(
                    source::REGISTRY_KEY,
                    &serde_json::json!("https://changed.example"),
                    1,
                )
                .expect("changed registry");
        }
        let cancel = Cancellation::new();
        if cancelled {
            cancel.cancel();
        }
        assert!(
            apply::directory(
                &runtime,
                (plugin, version),
                &next,
                raw.as_deref(),
                UpdatePolicy::AutoAll,
                100,
                &cancel
            )
            .is_err()
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
fn migration_failures_keep_the_old_version_and_activation_failures_report_the_committed_one() {
    use synra_plugin_host::{Backend, Scripted, ScriptedBackend, Work};
    let root = crate::runtime::tests::TempDir::new("update-lifecycle");
    let mut runtime = installed(root.path());
    let engine = ScriptedBackend::new();
    let host = Arc::clone(runtime.plugins.lock().host());
    runtime.plugins = Arc::new(Mutex::new(synra_core::dispatch::PluginSet::new(
        Backend::new(Arc::new(engine.clone())),
        host,
    )));
    runtime
        .plugin_set_enabled("@acme/hello", true)
        .expect("old instance");
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "auto-all", false);
    let migrate = Work::Migrate {
        from_version: "1.0.0".to_owned(),
        to_version: "1.1.0".to_owned(),
    };
    engine.script_for(
        "@acme/hello",
        &migrate,
        Scripted::Failed {
            code: "migration".to_owned(),
            message: "cannot migrate".to_owned(),
            details: None,
        },
    );
    assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
    assert_eq!(
        runtime
            .db()
            .active_plugin("@acme/hello")
            .expect("row")
            .expect("installed")
            .version,
        "1.0.0"
    );
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.0.0")
    );
    engine.script_for("@acme/hello", &migrate, Scripted::Ok("null".to_owned()));
    let config_json = synra_core::plugin::activation_config(runtime.plugins.lock().host().as_ref());
    engine.script_for(
        "@acme/hello",
        &Work::Activate { config_json },
        Scripted::Failed {
            code: "activation".to_owned(),
            message: "cannot activate".to_owned(),
            details: None,
        },
    );
    assert!(check_all(&runtime, 100 + CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        runtime
            .db()
            .active_plugin("@acme/hello")
            .expect("row")
            .expect("installed")
            .version,
        "1.1.0"
    );
    assert!(
        runtime
            .plugin_loads
            .lock()
            .refusal_for("@acme/hello")
            .expect("activation refusal")
            .contains("cannot activate")
    );
}
