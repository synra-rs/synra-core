use super::*;

#[test]
fn a_capability_the_host_does_not_know_stops_before_anything_is_written() {
    let dir = TempDir::new("install-bad-cap");
    let source =
        package(dir.path(), "source", &manifest(&["platform:teleport"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "capability-syntax", "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
    assert!(db.plugins().expect("the table").is_empty());
}

#[test]
fn an_artifact_name_that_leaves_the_package_is_refused() {
    let dir = TempDir::new("install-escape");
    // A manifest is third-party data: `../../outside.wasm` is a string that joins to a path, and reading it would be the
    // package deciding which file a host opens.
    let source = package(dir.path(), "source", &manifest(&["log:*"], "../outside.wasm"), &[]);
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "manifest", "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
}

#[test]
fn a_missing_artifact_is_refused_rather_than_installed_half_copied() {
    let dir = TempDir::new("install-missing-file");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[]);
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "read", "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
}

#[test]
fn a_second_install_is_refused_and_leaves_the_first_alone() {
    let dir = TempDir::new("install-twice");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let mut db = database();
    let first = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect("the first install");
    let written = std::fs::read(first.path.join("plugin.wasm")).expect("the artifact");

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 2_000).expect_err("refused");

    assert_eq!(refusal.stage, "install", "{}", refusal.reason);
    assert_eq!(std::fs::read(first.path.join("plugin.wasm")).expect("the artifact"), written);
}

#[test]
fn a_source_that_is_not_a_directory_is_refused_before_the_manifest_is_read() {
    let dir = TempDir::new("install-not-a-dir");
    let file = dir.path().join("not-a-package");
    std::fs::write(&file, b"not a directory").expect("a file");
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &file, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "source", "{}", refusal.reason);
}
