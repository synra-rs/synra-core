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

/// A manifest with a UI half, naming both artifacts.
fn ui_manifest(capabilities: &[&str], artifact: &str, ui: &str) -> String {
    let declared: Vec<_> =
        capabilities.iter().map(|cap| serde_json::json!({ "cap": cap })).collect();
    serde_json::json!({
        "id": "@acme/hello",
        "version": "1.2.3",
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": synra_plugin_host::host_world(),
        "capabilities": declared,
        "runtime": {
            "headless": { "artifact": artifact, "stateful": false },
            "ui": { "artifact": ui, "entry": "index.html" }
        }
    })
    .to_string()
}

/// A zip holding these entries, as the bytes a package ships.
fn ui_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;

    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        for (name, bytes) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("an entry");
            writer.write_all(bytes).expect("the bytes");
        }
        writer.finish().expect("a finished archive");
    }
    buffer.into_inner()
}

#[test]
fn installing_a_ui_plugin_unpacks_its_bundle_beside_the_artifact() {
    // ★ The step this asserts is the reason a UI plugin's page can be served at all: the zip is verified like any other
    // artifact, and then written out where the `synra-plugin://` handler will look — before the rename, so a bundle that
    // cannot be unpacked is a failed install rather than an installed plugin with a blank window.
    let dir = TempDir::new("install-ui");
    let ui = ui_zip(&[("index.html", b"<!doctype html>")]);
    let source = package(
        dir.path(),
        "source",
        &ui_manifest(&["log:*"], "plugin.wasm", "ui.zip"),
        &[("plugin.wasm", wasm()), ("ui.zip", &ui)],
    );
    let mut db = database();

    let installed =
        from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect("the package is installed");

    assert!(
        installed.path.join("ui").join("index.html").is_file(),
        "the page is unpacked under ui/: {:?}",
        installed.path
    );
}

fn plugins(root: &Path) -> PathBuf {
    root.join("plugins")
}

// ── The path that works ─────────────────────────────────────────────────────────────────────────────────────────

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

#[test]
fn the_signature_file_travels_with_the_package() {
    let dir = TempDir::new("install-signed");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    // Not a valid document: this asserts that the file is *carried*, and a package that ships one is refused by the
    // pipeline rather than by this copy step — which is the next test's subject.
    std::fs::write(source.join("signature.json"), "{}").expect("a signature file");
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

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
    let mut db = database();

    let installed = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect("installs");

    assert!(installed.path.join("signature.json").is_file(), "the signature travels with it");
    assert!(installed.warnings.is_empty(), "{:?}", installed.warnings);
    // ★ The publisher is recorded as "seen", not "trusted": the key signed this package, and only a user can decide
    // whether it is a key they trust.
    let publishers = db.publishers().expect("the publisher table");
    assert_eq!(publishers.len(), 1);
    assert_eq!(publishers[0].publisher_id, "@acme");
    assert_eq!(publishers[0].trust, synra_store::TRUST_SEEN);
}

#[test]
fn a_signed_package_whose_signature_covers_other_bytes_is_refused_at_the_signature() {
    let dir = TempDir::new("install-signed-swapped");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    crate::runtime::tests::sign_plugin(&source, true);
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "signature", "{}", refusal.reason);
    assert!(refusal.reason.contains("different bytes"), "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
    assert!(db.plugins().expect("the table").is_empty());
}

#[test]
fn a_revoked_publisher_is_refused_even_with_a_valid_signature() {
    // ★ A revocation is not a cryptographic fact — the signature is genuine — so it is checked at the publisher-trust
    // step, from the table. Without loading that table every revoked key would install again.
    let dir = TempDir::new("install-revoked");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    crate::runtime::tests::sign_plugin(&source, false);
    let mut db = database();

    let text = std::fs::read_to_string(source.join("signature.json")).expect("a signature");
    let document = synra_plugin_api::publisher::SignatureFile::parse(&text).expect("a document");
    let synra_plugin_api::publisher::VerifyOutcome::Good { fingerprint } =
        document.verify().expect("a genuine signature")
    else {
        panic!("the fixture must sign correctly");
    };
    db.record_publisher("@acme", fingerprint.as_str(), &document.pubkey, 1_000)
        .expect("the publisher is known");
    db.set_publisher_trust("@acme", synra_store::TRUST_REVOKED, 2_000)
        .expect("the key is revoked");

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 3_000)
        .expect_err("a revoked key must not install");

    assert_eq!(refusal.stage, "publisher-trust", "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
}

// ── The paths that do not ───────────────────────────────────────────────────────────────────────────────────────

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
