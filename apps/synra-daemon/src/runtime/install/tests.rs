//! Installing from a directory: what lands on disk, what is recorded, and what never does.

use std::path::{Path, PathBuf};

use synra_control::Kernel;
use synra_plugin_host::{Backend, ScriptedBackend};

use super::*;
use crate::runtime::tests::TempDir;

/// A backend that compiles a fixture artifact and reports no imports.
///
/// The imports a real component declares are the one thing this fake cannot produce, and the checks that need them are
/// driven in `synra-plugin-host`'s own tests against real components. What is tested here is the install path: the order
/// the pipeline runs in, what is written when it passes, and what is written when it does not — and those are questions
/// about this module rather than about the engine.
fn backend() -> Backend {
    Backend::new(std::sync::Arc::new(ScriptedBackend::new()))
}

fn database() -> synra_store::SynraDb {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db
}

/// A manifest that passes every check, with the given capabilities and artifact name.
fn manifest(capabilities: &[&str], artifact: &str) -> String {
    let declared: Vec<serde_json::Value> =
        capabilities.iter().map(|cap| serde_json::json!({ "cap": cap })).collect();
    serde_json::json!({
        "id": "@acme/hello",
        "version": "1.2.3",
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": synra_plugin_host::host_world(),
        "capabilities": declared,
        "runtime": { "headless": { "artifact": artifact, "stateful": false } }
    })
    .to_string()
}

/// A package directory: a manifest and, when the manifest names one, the artifact's bytes.
fn package(root: &Path, name: &str, manifest: &str, artifacts: &[(&str, &[u8])]) -> PathBuf {
    let directory = root.join(name);
    std::fs::create_dir_all(&directory).expect("a package directory");
    std::fs::write(directory.join("manifest.json"), manifest).expect("a manifest");
    for (file, bytes) in artifacts {
        std::fs::write(directory.join(file), bytes).expect("an artifact");
    }
    directory
}

fn wasm() -> &'static [u8] {
    b"\0asm\x01\0\0\0"
}

fn plugins(root: &Path) -> PathBuf {
    root.join("plugins")
}

// ── The path that works ─────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_verified_package_is_written_and_recorded_switched_off() {
    let dir = TempDir::new("install-ok");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let db = database();

    let installed =
        from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect("the package is installed");

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
}

#[test]
fn the_signature_file_travels_with_the_package() {
    let dir = TempDir::new("install-signed");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    // Not a valid document: this asserts that the file is *carried*, and a package that ships one is refused by the
    // pipeline rather than by this copy step — which is the next test's subject.
    std::fs::write(source.join("signature.json"), "{}").expect("a signature file");
    let db = database();

    let refusal = from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "signature");
    assert!(!plugins(dir.path()).join("@acme/hello").exists(), "a refused install writes nothing");
    assert!(db.plugins().expect("the table").is_empty(), "a refused install records nothing");
}

#[test]
fn a_signed_package_with_a_genuine_signature_installs() {
    // The control for the refusal below, and the one that caught a defect: the install pipeline computed the manifest's
    // digest as an SRI string while the CLI signs it in hex, so every genuinely signed package looked like one whose
    // signature covered a different document. Without this test the first signed install in the field would have been
    // the first time anyone found out.
    let dir = TempDir::new("install-signed-good");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    crate::runtime::tests::sign_plugin(&source, false);
    let db = database();

    let installed = from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect("installs");

    assert!(installed.path.join("signature.json").is_file(), "the signature travels with it");
    assert!(installed.warnings.is_empty(), "{:?}", installed.warnings);
}

#[test]
fn a_signed_package_whose_signature_covers_other_bytes_is_refused_at_the_signature() {
    let dir = TempDir::new("install-signed-swapped");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    crate::runtime::tests::sign_plugin(&source, true);
    let db = database();

    let refusal = from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "signature", "{}", refusal.reason);
    assert!(refusal.reason.contains("different bytes"), "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
    assert!(db.plugins().expect("the table").is_empty());
}

// ── The paths that do not ───────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_capability_the_host_does_not_know_stops_before_anything_is_written() {
    let dir = TempDir::new("install-bad-cap");
    let source =
        package(dir.path(), "source", &manifest(&["platform:teleport"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let db = database();

    let refusal = from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

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
    let db = database();

    let refusal = from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "manifest", "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
}

#[test]
fn a_missing_artifact_is_refused_rather_than_installed_half_copied() {
    let dir = TempDir::new("install-missing-file");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[]);
    let db = database();

    let refusal = from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "read", "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
}

#[test]
fn a_second_install_is_refused_and_leaves_the_first_alone() {
    let dir = TempDir::new("install-twice");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let db = database();
    let first = from_directory(&db, &backend(), &plugins(dir.path()), &source, 1_000).expect("the first install");
    let written = std::fs::read(first.path.join("plugin.wasm")).expect("the artifact");

    let refusal = from_directory(&db, &backend(), &plugins(dir.path()), &source, 2_000).expect_err("refused");

    assert_eq!(refusal.stage, "install", "{}", refusal.reason);
    assert_eq!(std::fs::read(first.path.join("plugin.wasm")).expect("the artifact"), written);
}

#[test]
fn a_source_that_is_not_a_directory_is_refused_before_the_manifest_is_read() {
    let dir = TempDir::new("install-not-a-dir");
    let file = dir.path().join("not-a-package");
    std::fs::write(&file, b"not a directory").expect("a file");
    let db = database();

    let refusal = from_directory(&db, &backend(), &plugins(dir.path()), &file, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "source", "{}", refusal.reason);
}

// ── Through the command ─────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_command_installs_and_answers_that_it_is_not_enabled() {
    // The whole path a client uses: `Request::PluginInstall` → `Kernel::plugin_install` → the pipeline → a row. What it
    // asserts is the answer, because a command that installed silently would leave the caller believing nothing happened.
    let dir = TempDir::new("install-command");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let runtime = crate::runtime::tests::runtime(dir.path());

    let answer = runtime
        .plugin_install(source.to_str().expect("a UTF-8 path"))
        .expect("the command installs");

    assert_eq!(answer["pluginId"], "@acme/hello");
    assert_eq!(answer["version"], "1.2.3");
    assert_eq!(answer["enabled"], false);
    assert!(answer["warnings"].as_array().is_some_and(Vec::is_empty));
}

#[test]
fn the_command_reports_a_refusal_as_an_invalid_argument() {
    let dir = TempDir::new("install-command-bad");
    let source =
        package(dir.path(), "source", &manifest(&["platform:teleport"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let runtime = crate::runtime::tests::runtime(dir.path());

    let refusal = runtime
        .plugin_install(source.to_str().expect("a UTF-8 path"))
        .expect_err("the command refuses");

    assert_eq!(refusal.code, synra_protocol::error::ErrorCode::InvalidArgument);
    assert!(refusal.message.contains("capability-syntax"), "{}", refusal.message);
}
