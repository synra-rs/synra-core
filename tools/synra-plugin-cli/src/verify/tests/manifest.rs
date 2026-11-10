use super::*;

#[test]
fn a_missing_manifest_is_the_first_finding() {
    // The answer an author needs when they ran the command from the wrong directory.
    let report = verify(&Target {
        manifest_json: Err("there is no manifest.json here".to_owned()),
        wasm: Err("no component".to_owned()),
        ui_bundle: Err("no UI bundle".to_owned()),
    });
    assert!(!report.is_ok());
    assert_eq!(report.findings[0].name, "manifest");
    assert_eq!(report.findings[0].verdict, Verdict::Fail);
    assert!(report.plugin_id.is_none());
}

#[test]
fn a_manifest_that_does_not_parse_names_the_problem() {
    let report = verify(&target("{ not json"));
    assert!(!report.is_ok());
    assert!(
        report.findings[0].detail.contains("does not parse"),
        "{:?}",
        report.findings[0]
    );
}

#[test]
fn a_valid_manifest_passes_and_names_the_plugin() {
    let report = verify(&headless_ok());
    assert_eq!(report.plugin_id.as_deref(), Some("@synra-plugin/example"));
    assert_eq!(report.version.as_deref(), Some("1.0.0"));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.name == "manifest" && f.verdict == Verdict::Pass)
    );
}
