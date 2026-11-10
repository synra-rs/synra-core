use super::*;

#[test]
fn a_fresh_installation_has_no_plugins_and_that_is_not_an_error() {
    // A missing directory is the state of every fresh installation, so it is an answer rather than a refusal.
    let dir = TempDir::new("plugins-empty");
    let value = runtime(dir.path()).plugins().expect("plugins");
    assert_eq!(value["plugins"].as_array().map(Vec::len), Some(0));
    // And it says nothing is loaded, so a client does not present an installed plugin as one that is running.
    assert_eq!(value["loaded"], false);
}

#[test]
fn listing_plugins_sets_the_installed_and_active_gauges() {
    // ★ The daemon side of the two plugin gauges. The window sets them in its own `plugins_list`; a daemon that never set
    // them reported nothing about a machine where the same plugins are installed, and the panel could only be read as
    // "this kernel has no plugins". Two rows with different `enabled` flags, so a single gauge fed both would be caught.
    use synra_observe::metrics::Value;

    let dir = TempDir::new("plugins-gauges");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/enabled", 1, 1);
    install(&runtime, "@acme/off", 0, 0);

    let _ = runtime.plugins().expect("plugins");

    let snapshot = runtime.metrics.snapshot();
    assert_eq!(snapshot.get("plugins_installed"), Some(&Value::Gauge(2)));
    assert_eq!(
        snapshot.get("plugins_active"),
        Some(&Value::Gauge(1)),
        "only the enabled one"
    );
}

#[test]
fn an_installed_plugin_is_reported_from_the_database() {
    // ★ The database is the source of truth for what is *installed*. The first version of this listed the plugins
    // directory, which answered a different question: a plugin whose directory is there but whose row is not has
    // never been installed by the kernel.
    let dir = TempDir::new("plugins-one");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/hello", 1, 1);

    let value = runtime.plugins().expect("plugins");
    let plugins = value["plugins"].as_array().expect("a list");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0]["id"], "@acme/hello");
    assert_eq!(plugins[0]["enabled"], true);
    assert_eq!(plugins[0]["trusted"], true);
    assert_eq!(plugins[0]["health"], "healthy");
    // And it says the artifact is not on disk, which it is not — a row without a directory is one the host would
    // fail to load, and a user needs to see that rather than discover it at the next call.
    assert_eq!(plugins[0]["artifactPresent"], false);
}

#[test]
fn a_plugin_whose_artifact_is_on_disk_says_so() {
    let dir = TempDir::new("plugins-artifact");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/hello", 1, 1);
    let plugin_dir = plugin_dir(&runtime.plugins_dir, "@acme/hello");
    std::fs::create_dir_all(&plugin_dir).expect("a plugin directory");
    std::fs::write(
        plugin_dir.join("manifest.json"),
        r#"{"id": "@acme/hello", "title": "Hello"}"#,
    )
    .expect("a manifest");

    let value = runtime.plugins().expect("plugins");
    assert_eq!(value["plugins"][0]["artifactPresent"], true);
    // The title comes from the manifest, which is the one thing the directory is read for.
    assert_eq!(value["plugins"][0]["title"], "Hello");
}

#[test]
fn a_plugin_the_user_never_trusted_is_reported_as_untrusted() {
    // ★ Enabled and trusted are two questions, and the report carries both: `should_run` is `enabled && trusted`, so
    // a plugin that is on but never confirmed is one nobody approved capabilities for.
    let dir = TempDir::new("plugins-untrusted");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/hello", 1, 0);

    let value = runtime.plugins().expect("plugins");
    assert_eq!(value["plugins"][0]["enabled"], true);
    assert_eq!(value["plugins"][0]["trusted"], false);
}

#[test]
fn an_empty_plugins_table_is_an_empty_list() {
    let dir = TempDir::new("plugins-none");
    let value = runtime(dir.path()).plugins().expect("plugins");
    assert_eq!(value["plugins"].as_array().map(Vec::len), Some(0));
    // And it says nothing is loaded, so a client does not present an installed plugin as one that is running.
    assert_eq!(value["loaded"], false);
    assert_eq!(value["loadedCount"], 0);
}

#[test]
fn the_plugins_come_back_in_a_stable_order() {
    // Two runs of `synra plugin list` have to agree, or a diff of two reports is noise.
    let dir = TempDir::new("plugins-order");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/zeta", 1, 1);
    install(&runtime, "@acme/alpha", 1, 1);

    let ids: Vec<String> = runtime.plugins().expect("plugins")["plugins"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|plugin| plugin["id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(ids, vec!["@acme/alpha", "@acme/zeta"]);
}

#[test]
fn the_plugin_report_carries_the_live_rung_as_well_as_the_row() {
    // """ + S + """ The reader the ladder did not have.
    //
    // `PluginSet::health_of` exists because round 114 made a trap count towards the health ladder and then found that
    // nothing could read the result: the daemon reported the **database row**, which is what was recorded at install time
    // and never moves. This asserts the report now carries both, and that the live one is a real answer rather than `null`
    // — which is what an accessor that always returned `None` would look like.
    let dir = TempDir::new("report-live-health");
    let runtime = runtime(dir.path());
    let id = "@acme/notes";
    write_plugin(&runtime.plugins_dir, id, r#"{"cap": "log:info"}"#);
    install(&runtime, id, 1, 1);
    consent(&runtime, id, &["log:info"]);

    // Loaded into the runtime's **own** set, because that is the one the report reads.
    let _ = crate::runtime::load_installed(
        &mut runtime.plugins.lock(),
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let value = runtime.plugins_value().expect("the report");
    let listed = value["plugins"].as_array().expect("a list");
    let row = listed
        .iter()
        .find(|entry| entry["id"] == id)
        .expect("the plugin is listed");

    // The recorded row, unchanged by anything that happened at runtime.
    assert_eq!(row["health"], "healthy", "{row}");
    // And the live rung, which is `good` for a plugin that has just been loaded and has done nothing.
    assert_eq!(row["liveHealth"], "good", "{row}");
}
