use super::*;

#[test]
fn a_ui_only_plugin_is_refused_because_it_has_no_headless_half() {
    let root = scratch("ui-only");
    let plugins = root.join("plugins");
    let directory = plugin_dir(&plugins, "@acme/hello");
    std::fs::create_dir_all(&directory).expect("a plugin directory");
    // The headless half is what a loader can instantiate; a UI bundle is served by the shell instead.
    let text = format!(
        r#"{{"id": "@acme/hello", "version": "1.0.0", "title": "Hello", "publisher": {{"id": "@acme"}},
            "sdk": {{"min": "0.1.0"}}, "wit": "{}",
            "capabilities": [{{"cap": "log:info"}}],
            "runtime": {{"ui": {{"artifact": "ui.zip", "entry": "index.html"}}}}}}"#,
        synra_plugin_host::host_world()
    );
    std::fs::write(directory.join("manifest.json"), &text).expect("a manifest");
    let db = database();
    install(&db, "@acme/hello", true, true);
    db.record_grants("@acme/hello", &[("log:info".to_owned(), true)], 200, &synra_plugin_api::manifest_digest(&text))
        .expect("the decisions");

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal");
    assert!(reason.contains("headless"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_plugin_that_is_not_enabled_is_neither_loaded_nor_refused() {
    let root = scratch("disabled");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", false, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty());
    assert!(summary.refused.is_empty(), "a decision the user made is not a failure: {:?}", summary.refused);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn loading_one_plugin_records_it_without_claiming_the_rest() {
    let root = scratch("one");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let mut summary = LoadedSummary::default();
    let id = load_plugin(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        "@acme/hello",
        &synra_plugin_api::revocation::RevocationList::empty(),
    )
    .expect("it loads");
    summary.record_loaded(id);
    assert_eq!(summary.len(), 1);
    let plugin = PluginId::try_from("@acme/hello".to_owned()).expect("an id");
    assert!(summary.contains(&plugin));
    // ★ The loader drives the ladder to its last rung: granted, then active. A set that stops at `Granted` cannot tell a
    // plugin that answered `activate` from one that never ran, and that difference is the card's whole state.
    let lifecycle = set.lifecycle(&plugin).expect("the lifecycle was dropped with the load");
    assert!(lifecycle.is_running(), "it is loaded but not marked active: {:?}", lifecycle.state());
    assert!(lifecycle.granted_digest().is_some(), "the manifest the user confirmed is not recorded");

    // A refusal recorded later replaces the claim for that plugin rather than leaving two answers.
    summary.record_refused("@acme/hello", "the engine refused it".to_owned());
    assert!(summary.is_empty());
    assert_eq!(summary.refusal_for("@acme/hello"), Some("the engine refused it"));

    // Unloading forgets both, because a disabled plugin is neither a success nor a failure.
    let id = PluginId::try_from("@acme/hello".to_owned()).expect("an id");
    summary.record_unloaded(&id);
    assert!(summary.is_empty());
    assert_eq!(summary.refusal_for("@acme/hello"), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_missing_artifact_is_refused_with_the_reason_the_author_needs() {
    let root = scratch("missing-artifact");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    std::fs::remove_file(plugin_dir(&plugins, "@acme/hello").join("plugin.wasm")).expect("the artifact is removed");
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal");
    assert!(reason.contains("artifact"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}
