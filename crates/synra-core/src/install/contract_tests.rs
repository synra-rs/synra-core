use super::*;
use synra_plugin_host::{
    BackendError, BackendKind, CompiledArtifact, Enforcement, PluginInstance, WasmBackend,
};

/// A failed static admission must never reach this engine.
struct NeverCompile;

impl WasmBackend for NeverCompile {
    fn kind(&self) -> BackendKind {
        BackendKind::WasmtimeCranelift
    }
    fn enforcement(&self) -> Enforcement {
        synra_plugin_host::ScriptedBackend::new().enforcement()
    }
    fn engine_version(&self) -> &str {
        "admission-order-test"
    }
    fn compile(&self, _wasm: &[u8], _id: &str) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        panic!("native compilation ran before static admission")
    }
    fn instantiate(
        &self,
        _backend: &Backend,
        _artifact: &dyn CompiledArtifact,
    ) -> Result<Box<dyn PluginInstance>, BackendError> {
        panic!("static admission instantiated a guest")
    }
}

#[rstest::rstest]
#[case(b"not wasm".to_vec(), false, "wit-compatibility")]
#[case(wat::parse_str("(module)").unwrap(), false, "wit-compatibility")]
#[case(wat::parse_str("(component)").unwrap(), false, "wit-compatibility")]
#[case(b"not wasm".to_vec(), true, "signature")]
fn refused_components_leave_no_installation(
    #[case] wasm: Vec<u8>,
    #[case] bad_signature: bool,
    #[case] expected_stage: &str,
) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let manifest = serde_json::json!({
        "id":"@acme/invalid", "version":"1.0.0", "title":"Invalid component",
        "publisher":{"id":"acme"}, "sdk":{"min":"1.0.0"}, "wit":synra_plugin_host::host_world(),
        "capabilities":[], "runtime":{"headless":{"artifact":"plugin.wasm","stateful":false}}
    });
    std::fs::write(source.join("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(source.join("plugin.wasm"), wasm).unwrap();
    if bad_signature {
        std::fs::write(source.join("signature.json"), "{}").unwrap();
    }
    let path = root.path().join("store.sqlite");
    let mut db = synra_store::SynraDb::open(&path).unwrap();
    db.migrate().unwrap();
    let plugins = root.path().join("plugins");
    let backend = Backend::new(std::sync::Arc::new(NeverCompile));
    let error = from_directory(
        &mut db,
        &backend,
        &plugins,
        &source,
        1,
        HostFacts::desktop(),
    )
    .unwrap_err();
    assert_eq!(error.stage, expected_stage, "{}", error.reason);
    assert!(db.plugins().unwrap().is_empty());
    assert!(!plugins.exists());
    drop(db);
    let connection = rusqlite::Connection::open(path).unwrap();
    let versions: i64 = connection
        .query_row("SELECT COUNT(*) FROM plugin_versions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(versions, 0);
    drop(connection);
    root.close().unwrap();
}

#[test]
fn executing_backends_validate_the_world_before_compiling_a_direct_load() {
    let backend = Backend::new(std::sync::Arc::new(NeverCompile));
    let mut set = crate::dispatch::PluginSet::new(
        backend,
        std::sync::Arc::new(synra_plugin_host::testing::RefusingHost),
    );
    let error = set
        .load(crate::dispatch::PluginSpec {
            id: synra_protocol::PluginId::parse("@acme/invalid").unwrap(),
            version: "1.0.0".to_owned(),
            wasm: wat::parse_str("(component)").unwrap(),
            grants: synra_capability::CapabilitySet::new(),
            policy: synra_plugin_host::InstancePolicy::Stateful,
            limit: 1,
            quota: synra_plugin_host::quota::Quota::default(),
        })
        .unwrap_err();
    assert!(matches!(
        error,
        crate::dispatch::PluginSetError::Compile(BackendError::Compile { .. })
    ));
}

#[test]
fn a_ui_only_package_is_refused_before_native_compilation_or_writes() {
    use std::io::Write as _;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let manifest = serde_json::json!({
        "id":"@acme/ui", "version":"1.0.0", "title":"UI only",
        "publisher":{"id":"acme"}, "sdk":{"min":"1.0.0"}, "wit":synra_plugin_host::host_world(),
        "capabilities":[], "runtime":{"ui":{"artifact":"ui.zip","entry":"index.html"}}
    });
    std::fs::write(source.join("manifest.json"), manifest.to_string()).unwrap();
    let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    archive
        .start_file("index.html", zip::write::SimpleFileOptions::default())
        .unwrap();
    archive
        .write_all(b"<!doctype html><title>UI fixture</title>")
        .unwrap();
    std::fs::write(
        source.join("ui.zip"),
        archive.finish().unwrap().into_inner(),
    )
    .unwrap();
    let mut db = synra_store::SynraDb::open(&root.path().join("store.sqlite")).unwrap();
    db.migrate().unwrap();
    let backend = Backend::new(std::sync::Arc::new(NeverCompile));
    let error = from_directory(
        &mut db,
        &backend,
        &root.path().join("plugins"),
        &source,
        1,
        HostFacts::desktop(),
    )
    .unwrap_err();
    assert_eq!(error.stage, "manifest-schema");
    assert!(error.reason.contains("headless"), "{}", error.reason);
    assert!(!root.path().join("plugins").exists());
    assert!(db.plugins().unwrap().is_empty());
    drop(db);
    root.close().unwrap();
}
