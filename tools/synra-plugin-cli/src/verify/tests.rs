//! The verifier's tests.

use super::*;

/// A manifest for a headless plugin.
const HEADLESS: &str = r#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } },
  "capabilities": []
}"#;

/// A manifest for a UI plugin.
const UI: &str = r#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "ui": { "artifact": "ui", "entry": "index.html" } },
  "capabilities": []
}"#;

fn target(manifest: &str) -> Target {
    Target {
        manifest_json: Ok(manifest.to_owned()),
        wasm: Err("the declared component is missing".to_owned()),
        ui_bundle: Err("the declared UI directory is missing".to_owned()),
    }
}

fn headless_ok() -> Target {
    Target {
        wasm: component(1_024, &[]),
        ..target(HEADLESS)
    }
}

// ── The manifest ──────────────────────────────────────────────────────────────────────────────

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

// ── The artifact ──────────────────────────────────────────────────────────────────────────────

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

// ── The imports ───────────────────────────────────────────────────────────────────────────────

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

// ── The report ────────────────────────────────────────────────────────────────────────────────

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
    assert_eq!(MAX_UI_BYTES, 32 * 1024 * 1024);
    assert_eq!(MAX_UI_FILES, 2_000);
    // Through a binding, so the comparison is not a constant expression the compiler folds away — and because the
    // relationship is the point: a Wasm bound above the bundle bound would let a plugin the kernel refuses to load
    // pass `verify`.
    let (wasm, ui) = (MAX_WASM_BYTES, MAX_UI_BYTES);
    assert!(wasm > 0 && wasm < ui, "wasm {wasm}, ui {ui}");
}

fn component(bytes: u64, imports: &[&str]) -> Result<ComponentInfo, String> {
    Ok(ComponentInfo {
        bytes,
        imports: imports.iter().map(|name| (*name).to_owned()).collect(),
    })
}
