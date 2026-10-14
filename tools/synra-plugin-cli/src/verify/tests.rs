//! The verifier's tests.

use super::*;
use crate::verify::check::covers;

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
        manifest_json: Some(manifest.to_owned()),
        wasm_bytes: None,
        wasm_imports: Vec::new(),
        ui_bundle: None,
    }
}

fn headless_ok() -> Target {
    Target { wasm_bytes: Some(1_024), ..target(HEADLESS) }
}

// ── The manifest ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_missing_manifest_is_the_first_finding() {
    // The answer an author needs when they ran the command from the wrong directory.
    let report = verify(&Target {
        manifest_json: None,
        wasm_bytes: None,
        wasm_imports: Vec::new(),
        ui_bundle: None,
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
    assert!(report.findings[0].detail.contains("does not parse"), "{:?}", report.findings[0]);
}

#[test]
fn a_valid_manifest_passes_and_names_the_plugin() {
    let report = verify(&headless_ok());
    assert_eq!(report.plugin_id.as_deref(), Some("@synra-plugin/example"));
    assert_eq!(report.version.as_deref(), Some("1.0.0"));
    assert!(report.findings.iter().any(|f| f.name == "manifest" && f.verdict == Verdict::Pass));
}

// ── The artifact ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_manifest_naming_a_wasm_entry_point_with_no_artifact_fails() {
    // The failure a build script produces when it silently succeeded at nothing.
    let report = verify(&target(HEADLESS));
    assert!(!report.is_ok());
    let wasm = report.findings.iter().find(|f| f.name == "wasm").expect("a wasm finding");
    assert_eq!(wasm.verdict, Verdict::Fail);
    assert!(wasm.suggestion.as_deref().is_some_and(|s| s.contains("build")));
}

#[test]
fn an_empty_artifact_fails_rather_than_passing_on_existence() {
    // Zero bytes is not "small", it is "the build produced nothing" — and a check that only asked whether the file
    // exists would pass it.
    let report = verify(&Target { wasm_bytes: Some(0), ..target(HEADLESS) });
    assert!(!report.is_ok());
    let wasm = report.findings.iter().find(|f| f.name == "wasm").expect("a finding");
    assert!(wasm.detail.contains("empty"), "{}", wasm.detail);
}

#[test]
fn an_oversized_artifact_fails_with_both_numbers() {
    // The bound and the measured size, so the author knows how far over they are.
    let report = verify(&Target { wasm_bytes: Some(MAX_WASM_BYTES + 1), ..target(HEADLESS) });
    assert!(!report.is_ok());
    let wasm = report.findings.iter().find(|f| f.name == "wasm").expect("a finding");
    assert!(wasm.detail.contains(&(MAX_WASM_BYTES + 1).to_string()), "{}", wasm.detail);
    assert!(wasm.detail.contains(&MAX_WASM_BYTES.to_string()), "{}", wasm.detail);
}

#[test]
fn a_large_but_legal_artifact_warns() {
    // Inside the bound and worth saying: a plugin's size is what the user pays on every install.
    let report = verify(&Target { wasm_bytes: Some(MAX_WASM_BYTES / 2 + 1), ..target(HEADLESS) });
    assert!(report.is_ok(), "a warning is not a failure");
    // Two: the size, and the imports this tool could not read. The assertion names which, rather than counting —
    // a count would break the moment a different warning was added for a good reason.
    assert!(
        report.findings.iter().any(|f| f.name == "wasm-size" && f.verdict == Verdict::Warn),
        "{:?}",
        report.findings
    );
    assert!(report.warnings() >= 1);
}

#[test]
fn a_ui_plugin_with_no_bundle_fails() {
    let report = verify(&target(UI));
    assert!(!report.is_ok());
    assert!(report.findings.iter().any(|f| f.name == "ui" && f.verdict == Verdict::Fail));
}

#[test]
fn an_empty_ui_bundle_fails_rather_than_passing_on_the_directory_existing() {
    let report = verify(&Target { ui_bundle: Some((0, 0)), ..target(UI) });
    assert!(!report.is_ok());
    let ui = report.findings.iter().find(|f| f.name == "ui").expect("a finding");
    assert!(ui.detail.contains("empty"), "{}", ui.detail);
}

#[test]
fn a_ui_bundle_over_the_file_count_fails() {
    let report = verify(&Target { ui_bundle: Some((MAX_UI_FILES + 1, 10)), ..target(UI) });
    assert!(!report.is_ok());
    let ui = report.findings.iter().find(|f| f.name == "ui").expect("a finding");
    assert!(ui.detail.contains("files"), "{}", ui.detail);
}

#[test]
fn a_headless_plugin_is_not_asked_for_an_interface() {
    // The kind decides which checks apply. Running both sets against both would report a finding about a file that
    // cannot exist, and an author would go looking for it.
    let report = verify(&headless_ok());
    assert!(!report.findings.iter().any(|f| f.name == "ui"), "{:?}", report.findings);
    assert!(report.is_ok(), "{:?}", report.findings);
}

#[test]
fn a_ui_plugin_is_not_asked_for_wasm() {
    let report = verify(&Target { ui_bundle: Some((3, 100)), ..target(UI) });
    assert!(!report.findings.iter().any(|f| f.name == "wasm"), "{:?}", report.findings);
    assert!(report.is_ok(), "{:?}", report.findings);
}

// ── The imports ───────────────────────────────────────────────────────────────────────────────

#[test]
fn an_unread_artifact_is_a_warning_rather_than_a_pass() {
    // ★ A pass it did not earn is worse than a warning: an author would publish believing the imports were fine.
    let report = verify(&headless_ok());
    let imports = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
    assert_eq!(imports.verdict, Verdict::Warn);
    assert!(report.is_ok(), "a warning is not a failure");
}

#[test]
fn every_provided_import_passes() {
    let report = verify(&Target {
        wasm_imports: PROVIDED_IMPORTS.iter().map(|s| (*s).to_owned()).collect(),
        ..headless_ok()
    });
    let imports = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
    assert_eq!(imports.verdict, Verdict::Pass, "{}", imports.detail);
}

#[test]
fn a_refused_import_fails_and_names_the_import() {
    // ★ The list that exists because no capability makes these safe. A plugin importing `wasi:filesystem` is one
    // that would read anything on the machine.
    for refused in REFUSED_IMPORTS {
        let report = verify(&Target {
            wasm_imports: vec![(*refused).to_owned()],
            ..headless_ok()
        });
        assert!(!report.is_ok(), "{refused} was accepted");
        let finding = report
            .findings
            .iter()
            .find(|f| f.name == "imports" && f.verdict == Verdict::Fail)
            .unwrap_or_else(|| panic!("{refused}: no finding"));
        assert!(finding.detail.contains(refused), "{}", finding.detail);
    }
}

#[test]
fn an_import_this_sdk_does_not_provide_fails() {
    // The failure that otherwise appears as a trap at the first call, naming nothing.
    let report = verify(&Target {
        wasm_imports: vec!["synra:host/teleport".to_owned()],
        ..headless_ok()
    });
    assert!(!report.is_ok());
    let finding = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
    assert!(finding.detail.contains("teleport"), "{}", finding.detail);
    assert!(
        finding.suggestion.as_deref().is_some_and(|s| s.contains("SDK")),
        "{finding:?}"
    );
}

#[test]
fn a_prefix_of_a_provided_import_is_not_treated_as_refusing_it() {
    // ★ The bug a `starts_with` comparison produced. `synra:host/exec` is refused and `synra:host/execute` is
    // provided, and one is a string prefix of the other — so a plugin importing the *provided* function was
    // refused for importing the forbidden one. A user would have read "exec is never provided" about a line they
    // never wrote.
    let report = verify(&Target {
        wasm_imports: vec!["synra:host/execute".to_owned()],
        ..headless_ok()
    });
    let imports = report.findings.iter().find(|f| f.name == "imports").expect("a finding");
    assert_eq!(imports.verdict, Verdict::Pass, "{}", imports.detail);
}

#[test]
fn a_rule_covers_a_namespace_but_not_a_longer_name() {
    // The rule itself, asserted directly: an import is a namespace and an item, so a rule matches the whole import
    // or the namespace it belongs to — and `wasi:filesystemx` is a different namespace.
    assert!(covers("wasi:filesystem", "wasi:filesystem"));
    assert!(covers("wasi:filesystem", "wasi:filesystem/types"));
    assert!(covers("wasi:filesystem", "wasi:filesystem/preopens"));
    assert!(!covers("wasi:filesystem", "wasi:filesystemx"));
    assert!(!covers("synra:host/exec", "synra:host/execute"));
    assert!(covers("synra:host/exec", "synra:host/exec"));
}

#[test]
fn every_refused_import_is_also_absent_from_the_provided_list() {
    // A function on both lists would be one this tool refuses and the kernel provides, which is a rule nobody
    // could satisfy.
    for refused in REFUSED_IMPORTS {
        assert!(
            !PROVIDED_IMPORTS.iter().any(|provided| provided == refused),
            "{refused} is on both lists"
        );
    }
}

// ── The report ────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_warning_does_not_make_the_report_fail() {
    // A plugin that warns still installs. Treating it as unhealthy would make `verify` refuse a plugin that works,
    // and an author would learn to ignore the command.
    let report = verify(&headless_ok());
    assert!(report.warnings() > 0, "the unread-imports warning is missing");
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
        lines.iter().any(|line| line.starts_with("      ") && line.contains("build")),
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
