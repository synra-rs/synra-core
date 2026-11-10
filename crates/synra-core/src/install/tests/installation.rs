use std::path::PathBuf;
use synra_plugin_host::verify::HostFacts;
use super::super::{from_directory, from_package, package_directory, package_manifest, update_from_package};
use super::{backend, database, manifest_version, scratch, write_source};

#[test]
fn a_package_installs_what_the_directory_inside_it_would() {
    let root = scratch("valid");
    let source = root.join("source");
    write_source(&source);
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).expect("the plugins directory");
    let archive = root.join("hello.synra");
    package_directory(&source, &archive).expect("the package is written");

    let mut db = database();
    let installed =
        from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
            .expect("the package installs");

    assert_eq!(installed.plugin_id, "@acme/hello");
    assert_eq!(installed.version, "1.0.0");
    // ★ The sanitised name, which is what `Paths::plugin_dir`, the removal and the sweep all use. A scoped id used raw
    // put the artifact two levels down and made an uninstall delete a directory that never existed.
    assert_eq!(installed.path, plugins.join("acme+hello"));
    assert!(installed.path.join("manifest.json").is_file(), "the manifest was not written");
    assert!(installed.path.join("plugin.wasm").is_file(), "the artifact was not written");
    // ★ The origin travels with the copy: a backup can list the plugin, and only this note can say where to get it
    // back from on this host.
    let source_note: serde_json::Value = serde_json::from_slice(
        &std::fs::read(installed.path.join("source.json")).expect("the source note"),
    )
    .expect("source.json is JSON");
    let noted = PathBuf::from(
        source_note["path"].as_str().expect("a path in the source note"),
    );
    assert_eq!(
        std::fs::canonicalize(noted).expect("a canonical noted source"),
        std::fs::canonicalize(&archive).expect("a canonical archive"),
        "the source note names the unpacked temporary directory rather than the package"
    );
    assert!(
        !root.join(".install-staging").read_dir().expect("the staging directory").any(|_| true),
        "the unpacked archive was left behind"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_package_manifest_can_be_read_without_installing_it() {
    // ★ The update path needs the version before it replaces anything, and a package's manifest is inside the
    // archive. Reading it must not leave a plugin, a staging directory or an installed row behind.
    let root = scratch("package-inspect");
    let source = root.join("source");
    write_source(&source);
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).expect("the plugins directory");
    let archive = root.join("hello.synra");
    package_directory(&source, &archive).expect("the package");

    let manifest = package_manifest(&archive).expect("a readable manifest");

    assert_eq!(manifest.id.as_str(), "@acme/hello");
    assert_eq!(manifest.version, "1.0.0");
    assert!(plugins.read_dir().expect("the plugins directory").next().is_none(), "nothing was installed");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_package_can_replace_an_installed_plugin() {
    // ★ The update path for the interface's "install a package" flow: the same `.synra`, replacing the directory rather
    // than being refused because the identifier is already installed.
    let root = scratch("package-update");
    let first = root.join("first");
    write_source(&first);
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).expect("the plugins directory");
    let first_archive = root.join("hello-1.synra");
    package_directory(&first, &first_archive).expect("the first package");
    let mut db = database();
    from_package(&mut db, &backend(), &plugins, &first_archive, 1_000, HostFacts::headless())
        .expect("installs");

    let second = root.join("second");
    std::fs::create_dir_all(&second).expect("the second source");
    std::fs::write(second.join("manifest.json"), manifest_version("2.0.0"))
        .expect("a manifest");
    std::fs::write(
        second.join("plugin.wasm"),
        synra_testkit::component::inert_component().expect("a valid component"),
    )
    .expect("an artifact");
    let second_archive = root.join("hello-2.synra");
    package_directory(&second, &second_archive).expect("the second package");

    let updated = update_from_package(
        &mut db,
        &backend(),
        &plugins,
        &second_archive,
        2_000,
        HostFacts::headless(),
    )
    .expect("updates");
    assert_eq!(updated.version, "2.0.0");
    assert_eq!(
        db.active_plugin_version("@acme/hello").expect("a version").map(|(version, _)| version),
        Some("2.0.0".to_owned()),
        "the version row did not move"
    );
    let note: serde_json::Value = serde_json::from_slice(
        &std::fs::read(updated.path.join("source.json")).expect("the source note"),
    )
    .expect("source.json is JSON");
    assert_eq!(
        std::fs::canonicalize(PathBuf::from(note["path"].as_str().expect("a path"))).expect("canonical"),
        std::fs::canonicalize(&second_archive).expect("a canonical archive"),
        "the note should name the package that replaced the first one"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_directory_install_records_where_it_came_from() {
    // ★ The directory is the package the user still has; unlike the archive path, nothing removes it after the
    // install, so the note is a reinstall instruction rather than a name of something that is already gone.
    let root = scratch("directory-origin");
    let source = root.join("source");
    write_source(&source);
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).expect("the plugins directory");

    let installed = from_directory(&mut database(), &backend(), &plugins, &source, 1_000, HostFacts::headless())
        .expect("installs");
    let note: serde_json::Value = serde_json::from_slice(
        &std::fs::read(installed.path.join("source.json")).expect("the source note"),
    )
    .expect("source.json is JSON");
    let noted = PathBuf::from(note["path"].as_str().expect("a path"));
    assert_eq!(
        std::fs::canonicalize(noted).expect("a canonical noted source"),
        std::fs::canonicalize(&source).expect("a canonical source"),
        "the note does not name the directory it was installed from"
    );
    let _ = std::fs::remove_dir_all(&root);
}
