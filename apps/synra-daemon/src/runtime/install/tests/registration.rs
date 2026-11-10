use super::*;

#[test]
fn a_verified_package_is_written_and_recorded_switched_off() {
    let dir = TempDir::new("install-ok");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let mut db = database();

    let installed =
        from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect("the package is installed");

    assert_eq!(installed.plugin_id, "@acme/hello");
    assert_eq!(installed.version, "1.2.3");
    assert!(installed.warnings.is_empty(), "{:?}", installed.warnings);
    assert!(installed.path.join("manifest.json").is_file());
    assert!(installed.path.join("plugin.wasm").is_file());

    // ★ Recorded and **not** trusted: installing is not approving. The design's `AwaitingConsent` is this row, and a
    // test that only checked "a row exists" would pass for an install that had approved the plugin on the user's behalf.
    let rows = db.plugins().expect("the table");
    let row = rows.iter().find(|row| row.plugin_id == "@acme/hello").expect("a row");
    assert!(!row.enabled, "installing must not switch a plugin on");
    assert!(!row.trusted, "installing must not trust a plugin's capabilities");
    assert!(!row.should_run(), "a plugin nobody approved must not run");

    // ★ And the row that says which version is in effect. `plugin_versions` had a reader (`active_plugin_version`) and no
    // production writer, so every plan built from it answered "nothing is installed". This is the install that fills it.
    let (version, digest) = db
        .active_plugin_version("@acme/hello")
        .expect("the active version can be read")
        .expect("the install records one");
    assert_eq!(version, "1.2.3");
    assert!(!digest.is_empty(), "the digest of the bytes that were written is recorded");
}
