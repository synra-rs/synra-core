//! The loader's own tests.
//!
//! A plugin row, a manifest, an artifact and a consent decision are enough to reach every refusal in [`super`], so these
//! tests use a real store and a real directory rather than a double: the loader's job is to read exactly those files, and
//! a fixture that replaced them would test a plugin host that does not exist.

use std::path::{Path, PathBuf};

use synra_plugin_host::testing::RefusingHost;
use synra_plugin_host::{Backend, Scripted, ScriptedBackend, Work};
use synra_protocol::ids::PluginId;

use super::{
    LoadedSummary, activation_config, load_installed, load_installed_with_config, load_plugin,
};

/// A scratch directory for one test, removed by the test.
fn scratch(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "synra-loader-{label}-{}-{}",
        std::process::id(),
        synra_store::sqlite::now_ms()
    ))
}

/// The manifest the tests write, with the capabilities they name.
fn manifest(plugin_id: &str, capabilities: &[&str]) -> String {
    let declared: Vec<String> = capabilities
        .iter()
        .map(|capability| format!("{{\"cap\": \"{capability}\"}}"))
        .collect();
    format!(
        r#"{{"id": "{plugin_id}", "version": "1.0.0", "title": "Hello",
            "publisher": {{"id": "@acme"}}, "sdk": {{"min": "0.1.0"}},
            "wit": "{}",
            "capabilities": [{}],
            "runtime": {{"headless": {{"artifact": "plugin.wasm", "stateful": false}}}}}}"#,
        synra_plugin_host::host_world(),
        declared.join(", ")
    )
}

/// Where the installer puts a plugin: the sanitised directory name, not the raw id.
fn plugin_dir(plugins: &Path, plugin_id: &str) -> PathBuf {
    plugins.join(synra_store::sanitise_component(plugin_id))
}

/// Writes a plugin the way an install leaves one: a manifest and an artifact.
fn write_plugin(plugins: &Path, plugin_id: &str, capabilities: &[&str]) -> String {
    let directory = plugin_dir(plugins, plugin_id);
    std::fs::create_dir_all(&directory).expect("a plugin directory");
    let text = manifest(plugin_id, capabilities);
    std::fs::write(directory.join("manifest.json"), &text).expect("a manifest");
    // The WebAssembly header, because the engine refuses anything else — a fixture that dodged that check would be
    // testing a path no plugin takes.
    std::fs::write(directory.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");
    text
}

fn database() -> synra_store::SynraDb {
    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    db
}

fn set() -> (crate::dispatch::PluginSet, ScriptedBackend) {
    use std::sync::Arc;
    let backend = ScriptedBackend::new();
    let set = crate::dispatch::PluginSet::new(
        Backend::new(Arc::new(backend.clone())),
        Arc::new(RefusingHost),
    );
    (set, backend)
}

/// Records the user's decision about every capability the manifest declares.
fn consent(db: &synra_store::SynraDb, plugins: &Path, plugin_id: &str, granted: &[&str]) {
    let text = std::fs::read_to_string(plugin_dir(plugins, plugin_id).join("manifest.json")).expect("the manifest");
    let manifest: synra_plugin_api::Manifest = serde_json::from_str(&text).expect("a manifest");
    let decisions: Vec<(String, bool)> = manifest
        .capabilities
        .iter()
        .map(|declared| (declared.cap.clone(), granted.contains(&declared.cap.as_str())))
        .collect();
    db.record_grants(plugin_id, &decisions, 200, &synra_plugin_api::manifest_digest(&text))
        .expect("the decisions");
}

fn install(db: &synra_store::SynraDb, plugin_id: &str, enabled: bool, trusted: bool) {
    db.insert_plugin(plugin_id, enabled, trusted, "healthy", 100, 200).expect("a plugin row");
}

mod activation;
mod consent;
mod outcomes;
