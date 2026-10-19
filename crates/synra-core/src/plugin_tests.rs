//! The loader's own tests.
//!
//! A plugin row, a manifest, an artifact and a consent decision are enough to reach every refusal in [`super`], so these
//! tests use a real store and a real directory rather than a double: the loader's job is to read exactly those files, and
//! a fixture that replaced them would test a plugin host that does not exist.

use std::path::{Path, PathBuf};

use synra_plugin_host::testing::RefusingHost;
use synra_plugin_host::{Backend, Scripted, ScriptedBackend, Work};
use synra_protocol::ids::PluginId;

use super::{LoadedSummary, load_installed, load_plugin};

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

#[test]
fn a_plugin_that_refuses_to_activate_is_not_left_loaded() {
    // ★ Loading is not activation. A plugin that compiles but refuses `activate` is not fit to answer, and leaving it in
    // the set would let it match a share it cannot execute. The refusal is the plugin's own sentence, not a code.
    let root = scratch("activate-refused");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, backend) = set();
    backend.script_for(
        "@acme/hello",
        &Work::Activate { config_json: "{}".to_owned() },
        Scripted::Failed {
            code: "invalidArgument".to_owned(),
            message: "the settings are nonsense".to_owned(),
        },
    );

    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "a plugin that refused to start was left loaded: {:?}", summary.loaded);
    let reason = summary.refusal_for("@acme/hello").expect("a refusal, not silence");
    assert!(reason.contains("activate"), "{reason}");
    assert!(reason.contains("the settings are nonsense"), "the plugin's own sentence is carried: {reason}");
    assert!(!set.contains(&PluginId::try_from("@acme/hello".to_owned()).expect("an id")));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_plugin_the_user_enabled_and_confirmed_loads_with_the_granted_capabilities() {
    // ★ The difference the whole loader exists for, asserted at the place it is observable: the manifest declares two
    // capabilities and the user granted one, so the plugin must run with one. Before consent was consulted, the two
    // were the same thing by construction and no test could tell them apart.
    let root = scratch("granted-narrow");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info", "device:list"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert_eq!(summary.len(), 1, "refused: {:?}", summary.refused);
    let id = PluginId::try_from("@acme/hello".to_owned()).expect("an id");
    let held: Vec<String> = set.grants(&id).expect("the plugin is loaded").iter().map(ToString::to_string).collect();
    assert_eq!(held, vec!["log:info".to_owned()], "the granted set, not the requested one: {held:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn safe_mode_loads_nothing_and_says_why() {
    // ★ Safe mode has to stop a *good* plugin, because the host cannot know which one is crashing until it starts them.
    // The verdict is reached the way a host reaches it — three reports, then the store's decision — rather than by
    // hand-building the enum, which would only prove that a made-up value returns false.
    let root = scratch("safe-mode");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let crashes = synra_observe::crash::CrashStore::new(&root);
    for offset in 0..synra_observe::crash::SAFE_MODE_THRESHOLD {
        crashes
            .write(&synra_observe::crash::CrashReport::new(
                1_000 + i64::try_from(offset).expect("a small offset"),
                "1.0.0",
                Some("src/plugin.rs:42".to_owned()),
                Some("the plugin panicked".to_owned()),
                None,
                None,
                None,
            ))
            .expect("the report is written");
    }
    let safe = crashes.verdict(1_000);
    assert!(!safe.allows_plugins(), "three crashes in one location did not reach safe mode: {safe:?}");

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &safe,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "safe mode loaded something: {:?}", summary.loaded);
    // ★ Not in `refused`: this plugin did not fail, it was never examined. Reporting it as a refusal would put a plugin
    // author on a bug report for the host's own decision.
    assert!(summary.refused.is_empty(), "a plugin was blamed for the host's decision: {:?}", summary.refused);
    let why = summary.safe_mode.as_deref().expect("safe mode must explain itself");
    assert!(why.contains("crashed 3 times"), "{why}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_plugin_without_a_recorded_decision_is_refused_rather_than_run_with_its_request() {
    let root = scratch("no-consent");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal, not silence");
    assert!(reason.contains("confirmed by the user"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_manifest_that_changed_since_consent_needs_confirming_again() {
    let root = scratch("stale-consent");
    let plugins = root.join("plugins");
    let text = write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    // A decision about a different document: the digest is the contract's own hex digest, not an arbitrary string.
    db.record_grants("@acme/hello", &[("log:info".to_owned(), true)], 200, "a different document")
        .expect("the stale decision");
    let _ = text;

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal, not silence");
    assert!(reason.contains("changed since the user confirmed it"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_revoked_version_is_disabled_in_the_store_and_refused() {
    let root = scratch("revoked");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@bad/plugin", &["log:info"]);
    let db = database();
    install(&db, "@bad/plugin", true, true);
    consent(&db, &plugins, "@bad/plugin", &["log:info"]);
    let revoked = synra_plugin_api::revocation::RevocationList::parse(
        r#"{"revoked": [{"plugin": "@bad/plugin", "versions": ["1.0.0"], "reason": "malicious code"}]}"#,
    )
    .expect("a revocation list");

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &revoked,
    );

    let reason = summary.refusal_for("@bad/plugin").expect("a refusal");
    assert!(reason.contains("malicious code"), "{reason}");
    assert!(reason.contains("disabled"), "{reason}");
    let row = db.plugins().expect("the table").into_iter().find(|row| row.plugin_id == "@bad/plugin");
    assert!(!row.expect("the row").enabled, "a revoked plugin stays enabled and is tried again next start");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_ui_only_plugin_is_refused_because_it_has_no_headless_half() {
    let root = scratch("ui-only");
    let plugins = root.join("plugins");
    let directory = plugin_dir(&plugins, "@acme/hello");
    std::fs::create_dir_all(&directory).expect("a plugin directory");
    // The headless half is what a loader can instantiate; a UI bundle is served by the shell instead.
    let text = format!(
        r#"{{"id": "@acme/hello", "version": "1.0.0", "title": "Hello", "publisher": {{"id": "@acme"}},
            "sdk": {{"min": "0.1.0"}}, "wit": "{}",
            "capabilities": [{{"cap": "log:info"}}],
            "runtime": {{"ui": {{"artifact": "ui.zip", "entry": "index.html"}}}}}}"#,
        synra_plugin_host::host_world()
    );
    std::fs::write(directory.join("manifest.json"), &text).expect("a manifest");
    let db = database();
    install(&db, "@acme/hello", true, true);
    db.record_grants("@acme/hello", &[("log:info".to_owned(), true)], 200, &synra_plugin_api::manifest_digest(&text))
        .expect("the decisions");

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal");
    assert!(reason.contains("headless"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_plugin_that_is_not_enabled_is_neither_loaded_nor_refused() {
    let root = scratch("disabled");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", false, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty());
    assert!(summary.refused.is_empty(), "a decision the user made is not a failure: {:?}", summary.refused);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn loading_one_plugin_records_it_without_claiming_the_rest() {
    let root = scratch("one");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let mut summary = LoadedSummary::default();
    let id = load_plugin(
        &mut set,
        &db,
        &plugins,
        "@acme/hello",
        &synra_plugin_api::revocation::RevocationList::empty(),
    )
    .expect("it loads");
    summary.record_loaded(id);
    assert_eq!(summary.len(), 1);
    assert!(summary.contains(&PluginId::try_from("@acme/hello".to_owned()).expect("an id")));

    // A refusal recorded later replaces the claim for that plugin rather than leaving two answers.
    summary.record_refused("@acme/hello", "the engine refused it".to_owned());
    assert!(summary.is_empty());
    assert_eq!(summary.refusal_for("@acme/hello"), Some("the engine refused it"));

    // Unloading forgets both, because a disabled plugin is neither a success nor a failure.
    let id = PluginId::try_from("@acme/hello".to_owned()).expect("an id");
    summary.record_unloaded(&id);
    assert!(summary.is_empty());
    assert_eq!(summary.refusal_for("@acme/hello"), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_missing_artifact_is_refused_with_the_reason_the_author_needs() {
    let root = scratch("missing-artifact");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    std::fs::remove_file(plugin_dir(&plugins, "@acme/hello").join("plugin.wasm")).expect("the artifact is removed");
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal");
    assert!(reason.contains("artifact"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}
