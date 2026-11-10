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
    static COMPONENT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    COMPONENT
        .get_or_init(|| synra_testkit::component::inert_component().expect("a valid component"))
        .as_slice()
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

fn plugins(root: &Path) -> PathBuf {
    root.join("plugins")
}

mod updates;
mod interface;
mod registration;
mod signatures;
mod refusals;
mod commands;
