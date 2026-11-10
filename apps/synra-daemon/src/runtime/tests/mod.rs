use std::path::{Path, PathBuf};

use synra_control::Kernel;
use synra_core::{Host, Identity};
use synra_protocol::error::ErrorCode;

use synra_store::records::{AuditRecord, IntentRecord};
use synra_store::{Paired, Seen};

use super::{Runtime, now_ms};

/// A temporary directory that removes itself.
pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-rt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A runtime over a migrated in-memory database, and a plugins directory under `dir`.
pub(super) fn runtime(dir: &Path) -> Runtime {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    runtime_over(dir, std::sync::Arc::new(parking_lot::Mutex::new(db)))
}

/// A runtime and the database it was built over, so a test can build a **second** one over the same store.
fn runtime_shared(
    dir: &Path,
) -> (
    Runtime,
    std::sync::Arc<parking_lot::Mutex<synra_store::SynraDb>>,
) {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    let shared = std::sync::Arc::new(parking_lot::Mutex::new(db));
    (runtime_over(dir, std::sync::Arc::clone(&shared)), shared)
}

///
/// ★ Why this exists: two runtimes over one store is what a **restart** is, and there is no other way to test that what a
/// daemon wrote down is what the next daemon reads. A fixture that built its own database every time could only ever test
/// a daemon against an empty one.
fn runtime_over(
    dir: &Path,
    shared_db: std::sync::Arc<parking_lot::Mutex<synra_store::SynraDb>>,
) -> Runtime {
    let identity = Identity::load(&shared_db.lock(), "windows", 1_000).expect("an identity");
    let local_peer = synra_core::LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        synra_core::platform_of_os("windows"),
        "0.1.0-test",
    );
    let host = Host::new(identity.clone(), local_peer);
    // Read before the identity is moved into the host: the desk derives the verification code from it, and the fixture is
    // the only place a test's device identity comes from.
    // ★ One handle, shared: the runtime reads it and so does the host a plugin's calls reach.
    Runtime {
        version: "0.1.0-test".to_owned(),
        data_dir: dir.to_path_buf(),
        plugins_dir: dir.join("plugins"),
        // The same layout the serve path builds, so a command that measures or removes plugin files answers about the
        // directories this fixture actually uses.
        paths: synra_store::Paths::new(dir.to_path_buf(), dir.join("cache")),
        listen_port: 47100,
        discovery_port: 47101,
        started_at_ms: 1_000,
        identity,
        host: std::sync::Arc::new(parking_lot::Mutex::new(host)),
        // No discovery socket in a unit test: binding the well-known port would collide with a kernel that happens to
        // be running on this machine, so the fixture leaves it absent — which is also the state a kernel with no
        // network is in, and one the code has to handle anyway.
        discovery: None,
        scan_until_ms: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0)),
        db: std::sync::Arc::clone(&shared_db),
        // A scripted engine rather than a real one: these tests are about what the daemon *reports*, and a unit test
        // that compiles Wasmtime to assert a JSON field would be a slower version of the same test.
        plugins: std::sync::Arc::new(parking_lot::Mutex::new(
            synra_core::dispatch::PluginSet::new(
                synra_plugin_host::Backend::new(std::sync::Arc::new(
                    synra_plugin_host::ScriptedBackend::new(),
                )),
                // ★ The daemon's own host, not a stub. The fixture exists to answer questions about what the daemon
                // reports, and a stub here would make every question about a plugin's authority answer the same thing.
                std::sync::Arc::new(crate::runtime::plugin_host::KernelHost::new(
                    std::sync::Arc::clone(&shared_db),
                    "0.1.0-test",
                )),
            ),
        )),
        metrics: std::sync::Arc::new(synra_observe::metrics::RingRecorder::new()),
        plugin_loads: std::sync::Arc::new(parking_lot::Mutex::new(
            crate::runtime::LoadedSummary::default(),
        )),
        // No revocations in a fixture: the list is a document shipped beside the data directory, and a test that wanted
        // one would say so explicitly.
        revocations: synra_plugin_api::revocation::RevocationList::empty(),
        board: std::sync::Arc::new(parking_lot::Mutex::new(synra_core::intent::Board::new())),
        // ★ A real verbosity rather than `None`, so a test can assert that `logs --verbose` actually raised it. `None`
        // is the state of a daemon whose log file could not be opened, and a fixture that used it would make every
        // assertion about raising vacuously true.
        verbosity: Some(std::sync::Arc::new(synra_observe::logging::Verbosity::new(
            synra_observe::logging::LogLevel::Info,
        ))),
        // The fixture keeps no writer, so the counts are absent: `synra logs` must still answer, with zeroes.
        log_stats: None,
        // And no flush handle, for the same reason: there is no file to wait for.
        log_flush: None,
    }
}

/// Inserts a plugin row, which is what the database is the source of truth for.
fn install(runtime: &Runtime, id: &str, enabled: i64, trusted: i64) {
    runtime
        .db()
        .insert_plugin(id, enabled != 0, trusted != 0, "healthy", 100, 200)
        .expect("a plugin row");
}

/// Records the user's decision about a plugin's capabilities, which is what makes it loadable.
///
/// # ★ Why this helper had to exist
///
/// Because `trusted = 1` is no longer an authorisation. It used to be treated as one: the loader took the manifest's own
/// declaration as the grant, so a row saying "the user trusts this" was enough, and a plugin received exactly what it
/// asked for. Now the grants come from the decisions recorded here, and the manifest's digest is checked against the
/// document those decisions were made about — so a test that set a flag and expected a plugin to run was asserting the
/// old rule.
///
/// That three tests failed the moment this changed is the point rather than a nuisance: they were installing trusted
/// plugins with nothing recorded, which is precisely the state the consistency check exists to catch.
fn consent(runtime: &Runtime, id: &str, granted: &[&str]) {
    let text = std::fs::read_to_string(plugin_dir(&runtime.plugins_dir, id).join("manifest.json"))
        .expect("the manifest this consent is about");
    let manifest: synra_plugin_api::Manifest = serde_json::from_str(&text).expect("a manifest");
    let decisions: Vec<(String, bool)> = manifest
        .capabilities
        .iter()
        .map(|declared| {
            (
                declared.cap.clone(),
                granted.contains(&declared.cap.as_str()),
            )
        })
        .collect();
    runtime
        .db()
        .record_grants(
            id,
            &decisions,
            200,
            &synra_plugin_api::manifest_digest(&text),
        )
        .expect("the decisions");
}

/// Writes a plugin directory the loader will accept: a manifest and a component.
///
/// The manifest carries every field [`synra_plugin_api::Manifest`] requires, because the loader parses the real type
/// rather than a `Value` — a fixture that left one out would be refused for a missing field and the refusal would read
/// as a loader bug.
fn manifest_json(id: &str, capabilities: &str, runtime: &str) -> String {
    format!(
        r#"{{"id": "{id}", "version": "1.2.3", "title": "Fixture",
            "publisher": {{"id": "@acme"}},
            "sdk": {{"min": "0.1.0"}},
            "wit": "synra:plugin",
            "capabilities": [{capabilities}],
            "runtime": {runtime}}}"#
    )
}

/// Where the installer puts a plugin: the sanitised directory name, not the raw id.
fn plugin_dir(plugins_dir: &Path, id: &str) -> PathBuf {
    plugins_dir.join(synra_store::sanitise_component(id))
}

/// Writes a plugin directory the loader will accept: a manifest and a component.
fn write_plugin(plugins_dir: &Path, id: &str, capability: &str) {
    let directory = plugin_dir(plugins_dir, id);
    std::fs::create_dir_all(&directory).expect("a plugin directory");
    let runtime = r#"{"headless": {"artifact": "plugin.wasm", "stateful": false}}"#;
    std::fs::write(
        directory.join("manifest.json"),
        manifest_json(id, capability, runtime),
    )
    .expect("a manifest");
    // The bytes have the WebAssembly header, because the loader's engine refuses anything else — and a fixture that
    // dodged that check would be testing a path no plugin takes.
    std::fs::write(
        directory.join("plugin.wasm"),
        synra_testkit::component::inert_component().expect("a valid component"),
    )
    .expect("an artifact");
}

/// Writes a `signature.json` over the package's bytes — or over **other** bytes, when `swap` is set.
///
/// # Why this signs instead of writing a document by hand
///
/// Because the case that matters is a document that genuinely verifies over bytes the package does not contain: a
/// hand-written `signature.json` fails at a different check, and a test built on one would pass against an
/// implementation that never compared anything.
pub(super) fn sign_plugin(directory: &Path, swap: bool) {
    use ed25519_dalek::Signer as _;

    let manifest_text =
        std::fs::read_to_string(directory.join("manifest.json")).expect("a manifest");
    let wasm = std::fs::read(directory.join("plugin.wasm")).expect("the artifact");
    let covered = if swap {
        b"bytes that are not here".to_vec()
    } else {
        wasm
    };
    let digest = synra_core::ObjectDigest::of(&covered).as_sri().to_string();

    let mut artifacts = synra_plugin_api::publisher::Digests::new();
    artifacts.insert("plugin.wasm", digest);
    let subject = synra_plugin_api::publisher::SigningSubject {
        manifest: synra_plugin_api::manifest_digest(&manifest_text),
        artifacts,
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let signature = signing.sign(&subject.canonical_bytes());
    let document = serde_json::json!({
        "version": synra_plugin_api::publisher::SIGNATURE_VERSION,
        "publisher": { "id": "@acme" },
        "algorithm": synra_plugin_api::publisher::ALGORITHM,
        "signedAt": "unix-ms:1",
        "pubkey": base64_of(signing.verifying_key().as_bytes()),
        "subject": {
            "manifest": subject.manifest,
            "artifacts": { "plugin.wasm": subject.artifacts.get("plugin.wasm").expect("a digest") },
        },
        "signature": base64_of(&signature.to_bytes()),
    });
    std::fs::write(directory.join("signature.json"), document.to_string()).expect("a signature");
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A loader over a scripted engine, so a test can load without compiling Wasmtime.
fn loader() -> (
    synra_core::dispatch::PluginSet,
    synra_plugin_host::ScriptedBackend,
) {
    let backend = synra_plugin_host::ScriptedBackend::new();
    let set = synra_core::dispatch::PluginSet::new(
        synra_plugin_host::Backend::new(std::sync::Arc::new(backend.clone())),
        // ★ The same host the fixture uses: a plugin loaded by these tests is given a session built from the real
        // one, so a question about authority is answered by the code that answers it in production.
        std::sync::Arc::new(crate::runtime::plugin_host::KernelHost::new(
            std::sync::Arc::new(parking_lot::Mutex::new(
                synra_store::SynraDb::open_in_memory().expect("a database"),
            )),
            "0.1.0-test",
        )),
    );
    (set, backend)
}

mod catalogue;
mod consent;
mod devices;
mod instrumentation;
mod intent_recovery;
mod logs;
mod plugin_discovery;
mod plugin_inventory;
mod plugin_loading;
mod plugin_loading_reports;
mod plugin_management;
mod publisher_revocation;
mod retention;
mod sending;
mod status;
