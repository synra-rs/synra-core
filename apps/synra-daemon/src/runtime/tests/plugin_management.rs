use super::*;

// ── Plugins ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn removing_a_plugin_takes_the_row_and_the_artifacts_and_reports_the_bytes() {
    // ★ The CLI's `plugin remove` was refused in words that named a decision nobody had made. The decision exists now —
    // keep the data by default, delete it only when asked — so the daemon has to be able to perform both halves and say
    // what it freed. Measured before the removal, or the number is a zero dressed as a measurement.
    let dir = TempDir::new("plugins-remove");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/hello", 1, 1);
    let artifacts = runtime.paths.plugin_dir("@acme/hello");
    std::fs::create_dir_all(&artifacts).expect("the artifacts");
    std::fs::write(artifacts.join("manifest.json"), b"12345").expect("an artifact file");
    let data = runtime.paths.plugin_sandbox_dir("@acme/hello");
    std::fs::create_dir_all(&data).expect("the sandbox");
    std::fs::write(data.join("cache.bin"), b"123").expect("a data file");

    let report = runtime
        .plugin_remove("@acme/hello", false)
        .expect("removes");

    assert_eq!(
        report["bytesFreed"], 5,
        "the artifact's bytes, not the sandbox's"
    );
    assert_eq!(report["dataKept"], true);
    assert!(
        runtime.db().plugins().expect("rows").is_empty(),
        "the row is gone"
    );
    assert!(!artifacts.exists(), "and the artifacts with it");
    assert!(data.exists(), "the data stays unless asked");
}

#[test]
fn removing_a_plugin_that_is_not_installed_is_a_refusal() {
    let dir = TempDir::new("plugins-remove-absent");
    let refused = runtime(dir.path())
        .plugin_remove("@acme/absent", false)
        .expect_err("nothing is installed as that");
    assert_eq!(refused.code, ErrorCode::PluginNotInstalled);
}

#[test]
fn enabling_a_plugin_writes_the_flag_and_says_so() {
    // ★ The write that had no caller.
    //
    // `set_plugin_enabled` existed in the store and was tested there, and **nothing in production called it** — so
    // `synra plugin enable` could not have worked even once the CLI asked for it. This is the other end of that wire.
    let dir = TempDir::new("enable-plugin");
    let runtime = runtime(dir.path());
    let plugin = "@acme/switchable";
    install(&runtime, plugin, 0, 0);

    runtime
        .plugin_set_enabled(plugin, true)
        .expect("enabling an installed plugin succeeds");

    // ★ Asserted in the database, not from the answer.
    //
    // The answer is the plugin list, so asserting on it would pass against an implementation that reported a list without
    // writing anything — which is the exact shape of the defect this test exists for. `plugins()` re-reads the row.
    let row = runtime
        .db()
        .plugins()
        .expect("plugins")
        .into_iter()
        .find(|row| row.plugin_id == plugin)
        .expect("the row is still there");
    assert!(row.enabled, "the flag was not written: {row:?}");

    // And the answer is the list it now stands in, so a caller does not have to ask twice.
    let listed = runtime.plugin_set_enabled(plugin, false).expect("the list");
    assert!(
        listed.to_string().contains(plugin),
        "the answer is the plugin list: {listed}"
    );
}

#[test]
fn enabling_a_confirmed_plugin_loads_it_without_a_restart() {
    // ★ The asymmetry this closes: the shell loaded one plugin on enable, and the daemon only wrote a flag — so
    // `synra plugin enable` answered that the plugin was on while it could not answer a share until the next start.
    let dir = TempDir::new("enable-loads");
    let runtime = runtime(dir.path());
    let plugin = "@acme/switchable";
    write_plugin(&runtime.plugins_dir, plugin, r#"{"cap": "log:info"}"#);
    install(&runtime, plugin, 0, 1);
    consent(&runtime, plugin, &["log:info"]);
    let id = synra_protocol::ids::PluginId::try_from(plugin.to_owned()).expect("an id");

    runtime
        .plugin_set_enabled(plugin, true)
        .expect("it enables and loads");
    assert!(
        runtime.plugins.lock().contains(&id),
        "enable wrote the flag but never loaded the plugin"
    );

    runtime
        .plugin_set_enabled(plugin, false)
        .expect("it disables and unloads");
    assert!(
        !runtime.plugins.lock().contains(&id),
        "disable left the compiled form in the set"
    );
}

#[test]
fn enabling_a_plugin_that_is_not_installed_is_a_refusal() {
    // ★ A typo and a no-op are different answers.
    //
    // `set_plugin_enabled` reports whether a row changed, so enabling an already-enabled plugin answers `false` — which
    // is a success with nothing to do. Reporting that as "no such plugin" would send a user looking for a mistake they did
    // not make; reporting a typo as a success would leave them believing it worked.
    let dir = TempDir::new("enable-plugin-typo");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/switchable", 1, 0);

    // Already enabled: a second enable is a success, because there is nothing to correct.
    assert!(runtime.plugin_set_enabled("@acme/switchable", true).is_ok());

    // Not installed at all: a refusal that names it, so the user can see their own typo.
    let refused = runtime
        .plugin_set_enabled("@acme/typo", true)
        .expect_err("no such plugin");
    assert!(refused.to_string().contains("@acme/typo"), "{refused}");
}
