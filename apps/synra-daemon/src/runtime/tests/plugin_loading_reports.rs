use super::*;

#[test]
fn safe_mode_loads_nothing_and_says_why() {
    // ★ The wiring this test exists for: `StartupVerdict::allows_plugins` was tested on its own and called from nowhere,
    // so a plugin that crashed this location three times running would be started a fourth. The settings screen the user
    // needs in order to switch it off is the thing safe mode protects, and nothing was protecting it.
    //
    // The plugin here is perfectly loadable — enabled, trusted, artifact present. It is not loaded, and that is the
    // assertion: safe mode has to stop a *good* plugin, because the daemon cannot know which one is crashing until it
    // starts them.
    let dir = TempDir::new("safe-mode");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@acme/hello", 1, 1);

    consent(&runtime, "@acme/hello", &["log:info"]);
    let (mut set, _backend) = loader();
    // ★ The verdict is reached the way the daemon reaches it — by writing crash reports and asking the store — rather
    // than by constructing `SafeMode` here. Hand-building the enum would test that `allows_plugins` returns false for a
    // value the test itself made up; this tests that three crashes in one place produce that value.
    let crashes = synra_observe::crash::CrashStore::new(dir.path());
    // ★ Distinct timestamps, because `CrashStore::write` names each file `crash-{at_ms}.json`. Three reports written
    // at the same millisecond land on one path and the last overwrites the other two — which is what this test did on
    // its first run, and the symptom was `recent_count: 1` for three crashes. Real panics are milliseconds apart, so
    // the fixture has to be too; the collision itself is noted in `write`'s own gap.
    for offset in 0..synra_observe::crash::SAFE_MODE_THRESHOLD {
        crashes
            .write(&synra_observe::crash::CrashReport::new(
                1_000 + i64::try_from(offset).expect("a small offset"),
                "1.0.0",
                Some("src/plugin.rs:42".to_owned()),
                Some("the plugin panicked".to_owned()),
                None,
                None,
                None,
            ))
            .expect("the report is written");
    }
    let safe = crashes.verdict(1_000);
    assert!(
        !safe.allows_plugins(),
        "three crashes in one location did not reach safe mode: {safe:?}"
    );

    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &safe,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(
        summary.is_empty(),
        "safe mode loaded something: {:?}",
        summary.loaded
    );
    // ★ Not in `refused`: this plugin did not fail, it was never examined. Reporting it as a refusal would put a plugin
    // author on a bug report for the daemon's own decision.
    assert!(
        summary.refused.is_empty(),
        "a plugin was blamed for a decision the daemon made: {:?}",
        summary.refused
    );
    // And the reason is carried out, so the daemon can print it rather than showing an empty list that reads as
    // "nothing is installed".
    let why = summary
        .safe_mode
        .as_deref()
        .expect("safe mode must explain itself");
    assert!(
        why.contains("src/plugin.rs:42"),
        "the explanation does not name the location: {why}"
    );
}

#[test]
fn one_broken_plugin_does_not_stop_the_others() {
    // ★ A machine with three plugins and one missing artifact must still run the other two. A loader that stopped at the
    // first failure would turn a plugin's problem into the kernel refusing to start.
    let dir = TempDir::new("load-broken");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/good", r#"{"cap": "log:info"}"#);
    // The broken one has a manifest and no artifact.
    let broken = plugin_dir(&runtime.plugins_dir, "@acme/broken");
    std::fs::create_dir_all(&broken).expect("a plugin directory");
    std::fs::write(
        broken.join("manifest.json"),
        manifest_json(
            "@acme/broken",
            "",
            r#"{"headless": {"artifact": "plugin.wasm", "stateful": false}}"#,
        ),
    )
    .expect("a manifest");
    install(&runtime, "@acme/broken", 1, 1);
    install(&runtime, "@acme/good", 1, 1);
    // `plugin_grants` has a foreign key onto `plugins`, so a decision cannot exist before the row it is about — which
    // is the schema saying the same thing the loader does: consent is about a plugin that is installed.
    consent(&runtime, "@acme/broken", &[]);
    consent(&runtime, "@acme/good", &["log:info"]);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert_eq!(summary.len(), 1, "the working plugin loaded");
    assert_eq!(
        summary.refused.len(),
        1,
        "and the broken one is accounted for"
    );
    assert_eq!(summary.refused[0].plugin_id, "@acme/broken");
    assert!(
        summary.refused[0].reason.contains("artifact"),
        "the reason names what is wrong: {}",
        summary.refused[0].reason
    );
}

#[test]
fn the_report_says_what_was_loaded_and_not_a_constant() {
    // ★ The assertion that would have caught the hardcoded `false`: after a load pass that loaded something, the report
    // has to say so. A field that cannot change with the system's state is decoration.
    let dir = TempDir::new("load-report");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@acme/hello", 1, 1);
    consent(&runtime, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    *runtime.plugin_loads.lock() = summary;

    let value = runtime.plugins().expect("plugins");
    assert_eq!(value["loaded"], true, "something is askable now");
    assert_eq!(value["loadedCount"], 1);
    assert_eq!(value["loadedIds"][0], "@acme/hello");
    assert_eq!(value["notLoaded"].as_array().map(Vec::len), Some(0));
}

#[test]
fn the_report_names_a_plugin_it_could_not_load() {
    // A user with one broken plugin can act on the reason; a user told only "nothing is loaded" cannot.
    let dir = TempDir::new("load-report-refused");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/absent", 1, 1);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert_eq!(
        summary.refused.len(),
        1,
        "the fixture has a row and no directory"
    );
    *runtime.plugin_loads.lock() = summary;

    let value = runtime.plugins().expect("plugins");
    assert_eq!(value["loaded"], false, "nothing loaded, and it says so");
    assert_eq!(value["notLoaded"][0]["id"], "@acme/absent");
    assert!(
        value["notLoaded"][0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("manifest")),
        "and the reason says what is missing: {value}"
    );
}
