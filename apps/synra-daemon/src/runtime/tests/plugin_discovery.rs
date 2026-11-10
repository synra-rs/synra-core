use super::*;

#[test]
fn a_plugin_directory_the_database_has_never_seen_is_recorded_and_left_off() {
    // ★ The step that was missing entirely, and the reason the whole plugin subsystem was unreachable.
    //
    // `insert_plugin` — the only writer of a `plugins` row — had no production caller. So `db.plugins()` was always
    // empty, so `load_installed` always loaded nothing, whatever was on disk. A user could put a plugin in the right
    // directory and the daemon would never know it existed.
    let dir = TempDir::new("discover-new");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1);
    let recorded = found.first().expect("one entry");
    assert_eq!(recorded.plugin_id, "@acme/hello");
    assert!(recorded.problem.is_none(), "{recorded:?}");

    // ★ And it is recorded **off**. Dropping a directory on disk is not a decision by anybody: the plugin directory is
    // writable by anything running as the user, so treating its contents as approved would make the filesystem the
    // privilege boundary. `should_run` is `enabled && trusted`, and neither is set.
    let rows = runtime.db().plugins().expect("rows");
    let row = rows.first().expect("the row this test just created");
    assert!(!row.enabled, "a discovered directory must not be enabled");
    assert!(!row.trusted, "a discovered directory must not be trusted");
    assert!(!row.should_run(), "so it does not run");
}

#[test]
fn a_plugin_directory_that_is_not_a_plugin_is_reported_rather_than_ignored() {
    // A half-copied install, a stray file, a build's output directory. The distinction a user needs is between "nothing
    // is installed" and "the installation is broken", and only one of those is worth acting on — so the reason is
    // carried out rather than dropped.
    let dir = TempDir::new("discover-broken");
    let runtime = runtime(dir.path());
    // ★ A direct child, because that is the only layout the installer writes: one sanitised directory per plugin.
    std::fs::create_dir_all(runtime.plugins_dir.join("half-copied")).expect("a directory");

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1);
    let reported = found.first().expect("one entry");
    assert_eq!(reported.plugin_id, "half-copied");
    assert!(
        reported
            .problem
            .as_deref()
            .is_some_and(|why| why.contains("manifest")),
        "the reason should name the manifest: {reported:?}"
    );
    // Nothing was recorded for it, so it cannot be enabled by accident later.
    assert!(runtime.db().plugins().expect("rows").is_empty());
}

#[test]
fn a_directory_named_differently_from_its_manifest_is_reported_rather_than_recorded() {
    // ★ A row whose directory the loader will never look in is worse than no row: the plugin is listed, can be enabled,
    // and fails every time. The installer names the directory after the sanitised id, so a hand-copied directory under
    // another name is refused here with the name it needs.
    let dir = TempDir::new("discover-wrong-name");
    let runtime = runtime(dir.path());
    let directory = runtime.plugins_dir.join("wrong-name");
    std::fs::create_dir_all(&directory).expect("a directory");
    std::fs::write(
        directory.join("manifest.json"),
        manifest_json(
            "@acme/hello",
            r#"{"cap": "log:info"}"#,
            r#"{"headless": {"artifact": "plugin.wasm", "stateful": false}}"#,
        ),
    )
    .expect("a manifest");
    std::fs::write(
        directory.join("plugin.wasm"),
        synra_testkit::component::inert_component().expect("a valid component"),
    )
    .expect("an artifact");

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].plugin_id, "@acme/hello");
    let problem = found[0].problem.as_deref().expect("a reason");
    assert!(
        problem.contains("acme+hello"),
        "the reason names the directory it needs: {problem}"
    );
    assert!(runtime.db().plugins().expect("rows").is_empty());
}

#[test]
fn discovering_a_plugin_twice_records_it_once() {
    // The daemon starts on every boot. Re-inserting would fail on the primary key, and "failed to record" printed at
    // every start would be noise that hides a real problem.
    let dir = TempDir::new("discover-twice");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );

    let first = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);
    assert_eq!(first.len(), 1, "the first pass records it");

    let second =
        crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 600);
    assert!(
        second.is_empty(),
        "the second pass should find nothing new: {second:?}"
    );
    assert_eq!(runtime.db().plugins().expect("rows").len(), 1);
}

#[test]
fn discovering_does_not_overwrite_a_decision_the_user_has_made() {
    // ★ The guard on the reconciliation being *additive*. A plugin the user enabled and trusted must come back from a
    // restart exactly as they left it — a reconciliation that re-inserted or reset flags would silently switch off every
    // plugin on every boot, which is the kind of bug that looks like "my plugins keep turning themselves off".
    let dir = TempDir::new("discover-existing");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@acme/hello", 1, 1);

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert!(found.is_empty(), "a known plugin is not new: {found:?}");
    let rows = runtime.db().plugins().expect("rows");
    let row = rows.first().expect("the row the user's decision is in");
    assert!(
        row.enabled && row.trusted,
        "the user's decision survived: {row:?}"
    );
}

#[test]
fn a_discovered_package_whose_signature_covers_other_bytes_is_not_recorded() {
    // ★ The second door into `plugins/`. `plugin install` runs the eleven checks; a directory copied in by hand was
    // recorded as installed on the strength of a manifest, so a replaced `plugin.wasm` beside a genuine
    // `signature.json` became a plugin the user would then be asked to approve — a prompt about a document nobody
    // had signed.
    let dir = TempDir::new("discover-signed-swapped");
    let runtime = runtime(dir.path());
    let plugin = "@acme/signed";
    write_plugin(&runtime.plugins_dir, plugin, r#"{"cap": "log:info"}"#);
    sign_plugin(&plugin_dir(&runtime.plugins_dir, plugin), true);

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1);
    let problem = found[0].problem.as_deref().expect("a reason");
    assert!(problem.contains("different bytes"), "{problem}");
    assert!(problem.contains("plugin.wasm"), "{problem}");
    assert!(
        !runtime.db().plugin_is_installed(plugin).expect("the table"),
        "it must not be recorded"
    );
}

#[test]
fn a_genuinely_signed_directory_is_recorded() {
    // The control. Without it, a check that refused every signed package would pass the test above.
    let dir = TempDir::new("discover-signed-good");
    let runtime = runtime(dir.path());
    let plugin = "@acme/signed";
    write_plugin(&runtime.plugins_dir, plugin, r#"{"cap": "log:info"}"#);
    sign_plugin(&plugin_dir(&runtime.plugins_dir, plugin), false);

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].problem, None, "{found:?}");
    assert!(runtime.db().plugin_is_installed(plugin).expect("the table"));
}

#[test]
fn a_signature_document_that_is_not_one_is_refused_at_discovery() {
    let dir = TempDir::new("discover-signed-broken");
    let runtime = runtime(dir.path());
    let plugin = "@acme/broken-signature";
    write_plugin(&runtime.plugins_dir, plugin, r#"{"cap": "log:info"}"#);
    std::fs::write(
        plugin_dir(&runtime.plugins_dir, plugin).join("signature.json"),
        "{}",
    )
    .expect("a file");

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0]
            .problem
            .as_deref()
            .is_some_and(|reason| reason.contains("signature")),
        "{found:?}"
    );
    assert!(!runtime.db().plugin_is_installed(plugin).expect("the table"));
}
