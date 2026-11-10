use super::*;

#[test]
fn an_unread_artifact_fails_rather_than_warns() {
    let report = verify(&Target {
        wasm: Err("component inspection failed".to_owned()),
        ..headless_ok()
    });
    assert!(!report.is_ok());
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn no_imports_is_a_verified_empty_set() {
    let report = verify(&headless_ok());
    let imports = report
        .findings
        .iter()
        .find(|finding| finding.name == "imports")
        .unwrap();
    assert_eq!(imports.verdict, Verdict::Pass);
    assert!(imports.detail.contains("0 actual"));
    assert_eq!(report.warnings(), 0);
}

#[test]
fn actual_host_functions_require_manifest_coverage() {
    let import = "synra:plugin/host#platform-open-url";
    let report = verify(&Target {
        wasm: component(1024, &[import]),
        ..headless_ok()
    });
    assert!(!report.is_ok());
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.detail.contains(import))
    );
    let mut manifest: serde_json::Value = serde_json::from_str(HEADLESS).unwrap();
    manifest["capabilities"] = serde_json::json!([{ "cap": "platform:open-url" }]);
    let report = verify(&Target {
        wasm: component(1024, &[import]),
        ..target(&manifest.to_string())
    });
    assert!(report.is_ok(), "{:?}", report.findings);
}

#[test]
fn ungated_functions_need_no_manifest_capability() {
    let report = verify(&Target {
        wasm: component(1024, &["synra:plugin/host#env-locale"]),
        ..headless_ok()
    });
    assert!(report.is_ok(), "{:?}", report.findings);
}

#[test]
fn unknown_or_lookalike_functions_are_not_granted_by_a_prefix() {
    for import in [
        "synra:plugin/host#env-locale-extra",
        "synra:host/execute",
        "wasi:cli/environment@0.2.0",
    ] {
        let report = verify(&Target {
            wasm: component(1024, &[import]),
            ..headless_ok()
        });
        assert!(!report.is_ok(), "{import}");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.detail.contains(import))
        );
    }
}
