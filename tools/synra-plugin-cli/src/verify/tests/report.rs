use super::*;

#[test]
fn a_warning_does_not_make_the_report_fail() {
    // A plugin that warns still installs. Treating it as unhealthy would make `verify` refuse a plugin that works,
    // and an author would learn to ignore the command.
    let report = verify(&Target {
        wasm: component(MAX_WASM_BYTES / 2 + 1, &[]),
        ..headless_ok()
    });
    assert!(report.warnings() > 0, "the size warning is missing");
    assert!(report.is_ok());
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn a_failure_is_an_exit_code_a_build_script_can_branch_on() {
    assert_eq!(verify(&target(HEADLESS)).exit_code(), 1);
    assert_eq!(verify(&headless_ok()).exit_code(), 0);
}

#[test]
fn the_lines_lead_with_the_plugin_and_end_with_a_tally() {
    let lines = verify(&headless_ok()).lines();
    assert!(lines[0].contains("@synra-plugin/example"), "{:?}", lines[0]);
    assert!(lines[0].contains("1.0.0"), "{:?}", lines[0]);
    let last = lines.last().expect("a line");
    assert!(last.contains(" ok"), "{last}");
    assert!(last.contains("warn"), "{last}");
    assert!(last.contains("fail"), "{last}");
}

#[test]
fn a_suggestion_gets_its_own_line() {
    // The half that tells an author what to do, and a long detail plus a long suggestion on one line is a line
    // nobody reads to the end.
    let report = verify(&target(HEADLESS));
    let lines = report.lines();
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("      ") && line.contains("build")),
        "{lines:?}"
    );
}

#[test]
fn the_report_serialises_for_a_script() {
    let report = verify(&headless_ok());
    let json = serde_json::to_value(&report).expect("serialises");
    assert_eq!(json["pluginId"], "@synra-plugin/example");
    assert!(json["findings"].as_array().is_some_and(|f| !f.is_empty()));
    assert_eq!(json["findings"][0]["verdict"], "pass");
}

#[test]
fn the_verdicts_have_words_a_person_reads() {
    assert_eq!(Verdict::Pass.as_str(), "ok");
    assert_eq!(Verdict::Warn.as_str(), "warn");
    assert_eq!(Verdict::Fail.as_str(), "fail");
    assert!(Verdict::Fail.is_failure());
    assert!(!Verdict::Warn.is_failure());
}

#[test]
fn the_bounds_are_the_ones_the_artifact_layer_uses() {
    // Asserted so a change here and not there is a failure rather than two bounds that disagree about the same
    // plugin, one of which the kernel enforces.
    assert_eq!(MAX_UI_BYTES, synra_plugin_ui::MAX_ARTIFACT_BYTES);
    assert_eq!(MAX_UI_FILES, 2_000);
    // Through a binding, so the comparison is not a constant expression the compiler folds away — and because the
    // relationship is the point: a Wasm bound above the bundle bound would let a plugin the kernel refuses to load
    // pass `verify`.
    let (wasm, ui) = (MAX_WASM_BYTES, MAX_UI_BYTES);
    assert!(wasm > 0 && wasm < ui, "wasm {wasm}, ui {ui}");
}
