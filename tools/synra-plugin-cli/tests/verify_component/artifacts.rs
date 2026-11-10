use super::*;

#[test]
fn missing_escaping_and_oversized_artifacts_cannot_hide_behind_a_valid_default_file() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("plugin.wasm"), fixture::component()).unwrap();
    std::fs::write(root.path().join("Source.JSON"), fixture::component()).unwrap();
    for artifact in [
        "missing.wasm",
        "../plugin.wasm",
        "",
        "Source.JSON",
        "plugin.wasm:stream",
    ] {
        manifest(root.path(), artifact, &[]);
        let (status, report) = verify(root.path());
        assert!(!status.success(), "{report}");
    }
    let oversized = root.path().join("large.wasm");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(synra_plugin_cli::MAX_WASM_BYTES + 1)
        .unwrap();
    manifest(root.path(), "large.wasm", &[]);
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("limit"), "{report}");
}

#[test]
fn oversized_manifests_fail_before_json_or_artifact_inspection() {
    let root = tempfile::tempdir().unwrap();
    std::fs::File::create(root.path().join("manifest.json"))
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    let (status, report) = verify(root.path());
    assert!(!status.success(), "{report}");
    assert!(report.to_string().contains("manifest.json is"), "{report}");
    assert!(report.to_string().contains("limit"), "{report}");
}
