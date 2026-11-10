//! Installation fixtures and package handling scenarios.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use synra_plugin_host::Backend;

/// A scratch directory for one test, removed by the test.
fn scratch(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("synra-package-{label}-{}-{}", std::process::id(), crate::reading_millis(synra_store::sqlite::now_ms())))
}

/// A manifest naming one headless artifact, in the shape the verifier accepts.
fn manifest() -> String {
    manifest_version("1.0.0")
}

/// The same manifest at another version, for the update tests.
fn manifest_version(version: &str) -> String {
    format!(
        r#"{{"id": "@acme/hello", "version": "{version}", "title": "Hello",
            "publisher": {{"id": "@acme"}}, "sdk": {{"min": "0.1.0"}},
            "wit": "{}",
            "capabilities": [{{"cap": "log:*"}}],
            "runtime": {{"headless": {{"artifact": "plugin.wasm", "stateful": false}}}}}}"#,
        synra_plugin_host::host_world()
    )
}

/// A directory an installer would take: a manifest and one artifact.
fn write_source(directory: &Path) {
    std::fs::create_dir_all(directory).expect("the source directory");
    std::fs::write(directory.join("manifest.json"), manifest()).expect("a manifest");
    std::fs::write(
        directory.join("plugin.wasm"),
        synra_testkit::component::inert_component().expect("a valid component"),
    )
    .expect("an artifact");
}

fn backend() -> Backend {
    Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new()))
}

fn database() -> synra_store::SynraDb {
    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    db
}

mod installation;
mod integrity;
mod packaging;
