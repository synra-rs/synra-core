use super::*;

#[test]
fn a_manifest_naming_a_wasm_entry_point_with_no_artifact_fails() {
    // The failure a build script produces when it silently succeeded at nothing.
    let report = verify(&target(HEADLESS));
    assert!(!report.is_ok());
    let wasm = report
        .findings
        .iter()
        .find(|f| f.name == "wasm")
        .expect("a wasm finding");
    assert_eq!(wasm.verdict, Verdict::Fail);
    assert!(
        wasm.suggestion
            .as_deref()
            .is_some_and(|s| s.contains("build"))
    );
}

#[test]
fn an_empty_artifact_fails_rather_than_passing_on_existence() {
    // Zero bytes is not "small", it is "the build produced nothing" — and a check that only asked whether the file
    // exists would pass it.
    let report = verify(&Target {
        wasm: component(0, &[]),
        ..target(HEADLESS)
    });
    assert!(!report.is_ok());
    let wasm = report
        .findings
        .iter()
        .find(|f| f.name == "wasm")
        .expect("a finding");
    assert!(wasm.detail.contains("empty"), "{}", wasm.detail);
}

#[test]
fn an_oversized_artifact_fails_with_both_numbers() {
    // The bound and the measured size, so the author knows how far over they are.
    let report = verify(&Target {
        wasm: component(MAX_WASM_BYTES + 1, &[]),
        ..target(HEADLESS)
    });
    assert!(!report.is_ok());
    let wasm = report
        .findings
        .iter()
        .find(|f| f.name == "wasm")
        .expect("a finding");
    assert!(
        wasm.detail.contains(&(MAX_WASM_BYTES + 1).to_string()),
        "{}",
        wasm.detail
    );
    assert!(
        wasm.detail.contains(&MAX_WASM_BYTES.to_string()),
        "{}",
        wasm.detail
    );
}

#[test]
fn a_large_but_legal_artifact_warns() {
    // Inside the bound and worth saying: a plugin's size is what the user pays on every install.
    let report = verify(&Target {
        wasm: component(MAX_WASM_BYTES / 2 + 1, &[]),
        ..target(HEADLESS)
    });
    assert!(report.is_ok(), "a warning is not a failure");
    // Report an advisory size warning independently of successful binary and import validation.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.name == "wasm-size" && f.verdict == Verdict::Warn),
        "{:?}",
        report.findings
    );
    assert!(report.warnings() >= 1);
}

#[test]
fn a_ui_plugin_with_no_bundle_fails() {
    let report = verify(&target(UI));
    assert!(!report.is_ok());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.name == "ui" && f.verdict == Verdict::Fail)
    );
}

#[test]
fn an_empty_ui_bundle_fails_rather_than_passing_on_the_directory_existing() {
    let report = verify(&Target {
        ui_bundle: Ok((0, 0)),
        ..target(UI)
    });
    assert!(!report.is_ok());
    let ui = report
        .findings
        .iter()
        .find(|f| f.name == "ui")
        .expect("a finding");
    assert!(ui.detail.contains("empty"), "{}", ui.detail);
}

#[test]
fn a_ui_bundle_over_the_file_count_fails() {
    let report = verify(&Target {
        ui_bundle: Ok((MAX_UI_FILES + 1, 10)),
        ..target(UI)
    });
    assert!(!report.is_ok());
    let ui = report
        .findings
        .iter()
        .find(|f| f.name == "ui")
        .expect("a finding");
    assert!(ui.detail.contains("files"), "{}", ui.detail);
}

#[test]
fn a_headless_plugin_is_not_asked_for_an_interface() {
    // The kind decides which checks apply. Running both sets against both would report a finding about a file that
    // cannot exist, and an author would go looking for it.
    let report = verify(&headless_ok());
    assert!(
        !report.findings.iter().any(|f| f.name == "ui"),
        "{:?}",
        report.findings
    );
    assert!(report.is_ok(), "{:?}", report.findings);
}

#[test]
fn a_ui_only_plugin_is_refused_by_manifest_validation() {
    let report = verify(&Target {
        ui_bundle: Ok((3, 100)),
        ..target(UI)
    });
    assert!(!report.is_ok());
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.name == "manifest"
                && finding.verdict == Verdict::Fail
                && finding.detail.contains("headless")),
        "{:?}",
        report.findings
    );
}
