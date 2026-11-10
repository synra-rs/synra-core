use super::*;

#[test]
fn updating_replaces_the_copy_and_keeps_the_users_decision() {
    // ★ An update is not an install: the row and the enabled flag already exist, and re-inserting would silently switch a
    // running plugin off. What is replaced is the directory and the active version, and only after the new package has
    // passed every check.
    let dir = TempDir::new("install-update");
    let first = package(dir.path(), "first", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let mut db = database();
    from_directory(&mut db, &backend(), &plugins(dir.path()), &first, 1_000).expect("installs");
    db.set_plugin_enabled("@acme/hello", true, 1_500).expect("enabled");

    let second_manifest = manifest(&["log:*"], "plugin.wasm").replace("\"1.2.3\"", "\"2.0.0\"");
    let second = package(dir.path(), "second", &second_manifest, &[("plugin.wasm", wasm())]);

    let updated = synra_core::install::update_from_directory(
        &mut db,
        &backend(),
        &plugins(dir.path()),
        &second,
        2_000,
        HostFacts::headless(),
    )
    .expect("the update passes");

    assert_eq!(updated.version, "2.0.0");
    let row = db
        .plugins()
        .expect("rows")
        .into_iter()
        .find(|row| row.plugin_id == "@acme/hello")
        .expect("a row");
    assert!(row.enabled, "the user's decision survived the update");
    let (version, digest) = db.active_plugin_version("@acme/hello").expect("the active version").expect("one");
    assert_eq!(version, "2.0.0");
    assert!(!digest.is_empty(), "the new artifact's digest is recorded");
    // The update left no backup beside the plugin: the old directory is deleted only once the version row lands. The
    // installed directory is the **sanitised** identifier (`acme+hello`), so the assertion is about the backup's name
    // rather than about a prefix.
    assert!(
        std::fs::read_dir(plugins(dir.path())).expect("the plugins directory").all(|entry| {
            !entry.expect("an entry").file_name().to_string_lossy().starts_with("previous-")
        }),
        "an update backup was left behind"
    );
}

#[test]
fn an_update_that_asks_for_more_switches_the_plugin_off() {
    // ★ M3's "a permission change needs consent", applied to the update path: the old approval was about the old list.
    // The new version lands, but it comes back switched off and untrusted, so the consent screen has to ask again.
    let dir = TempDir::new("install-update-consent");
    let first = package(dir.path(), "first", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let mut db = database();
    from_directory(&mut db, &backend(), &plugins(dir.path()), &first, 1_000).expect("installs");
    db.set_plugin_enabled("@acme/hello", true, 1_500).expect("enabled");
    db.set_plugin_trusted("@acme/hello", true, 1_500).expect("trusted");

    let second_manifest =
        manifest(&["log:*", "device:send:*"], "plugin.wasm").replace("\"1.2.3\"", "\"2.0.0\"");
    let second = package(dir.path(), "second", &second_manifest, &[("plugin.wasm", wasm())]);
    synra_core::install::update_from_directory(
        &mut db,
        &backend(),
        &plugins(dir.path()),
        &second,
        2_000,
        HostFacts::headless(),
    )
    .expect("the update passes");

    let row = db
        .plugins()
        .expect("rows")
        .into_iter()
        .find(|row| row.plugin_id == "@acme/hello")
        .expect("a row");
    assert!(!row.enabled, "a new permission switches the plugin off until consent");
    assert!(!row.trusted, "the old approval did not cover the new list");
}
