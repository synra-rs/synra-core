use std::path::PathBuf;
use super::super::{BuildError, BuildPlan, Step};
use super::Cleanup;

#[test]
fn a_plan_reports_what_is_missing() {
    // The check that runs *after* the commands, and the one that catches a build script that silently succeeded at
    // nothing.
    let dir = Cleanup::new("missing");
    dir.headless("plugin.wasm");

    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    assert_eq!(plan.missing(), vec![PathBuf::from("plugin.wasm")]);

    dir.write("dist/plugin.wasm", "");
    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    assert!(plan.missing().is_empty(), "{:?}", plan.missing());
    assert_eq!(plan.outcome_lines(), vec!["built plugin.wasm".to_owned()]);
}

#[test]
fn a_missing_artifact_says_the_manifest_is_what_decides_where() {
    // The message an author needs, because the usual cause is a build that wrote somewhere other than the manifest
    // says.
    let dir = Cleanup::new("missing-line");
    dir.headless("plugin.wasm");

    let lines = BuildPlan::resolve(dir.path())
        .expect("resolves")
        .outcome_lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("plugin.wasm"), "{}", lines[0]);
    assert!(lines[0].contains("manifest"), "{}", lines[0]);
}

// ── The lines ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_lines_name_the_kind_the_commands_and_the_artifacts() {
    let dir = Cleanup::new("lines");
    dir.hybrid("plugin.wasm", "dist");
    dir.package_with_build();

    let lines = BuildPlan::resolve(dir.path()).expect("resolves").lines();
    assert!(lines[0].contains("hybrid"), "{:?}", lines[0]);
    assert!(
        lines.iter().any(|line| line.contains("cargo build")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("npm run build")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("expects plugin.wasm")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("expects dist")),
        "{lines:?}"
    );
}

#[test]
fn a_step_says_why_it_is_there() {
    // A command with no reason beside it is one an author cannot tell from a mistake.
    let dir = Cleanup::new("why");
    dir.headless("plugin.wasm");
    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    assert!(
        plan.steps[0].why.contains("wasm32-unknown-unknown"),
        "{}",
        plan.steps[0].why
    );
    assert!(plan.steps[0].why.len() > 30);
}

#[test]
fn a_command_line_with_a_space_is_quoted() {
    // So a line an author copies and pastes is one that runs.
    let step = Step {
        program: "cargo".to_owned(),
        args: vec![
            "build".to_owned(),
            "--verbose".to_owned(),
            "plugin".to_owned(),
        ],
        in_dir: PathBuf::new(),
        why: "x".to_owned(),
        component: None,
    };
    assert_eq!(step.command_line(), "cargo build --verbose plugin");

    // And a flag with a value *is* quoted: `=` is a substitution in some shells, and the cost of being wrong the
    // other way is a pasted line that does something unexpected rather than one that fails.
    let with_value = Step {
        program: "cargo".to_owned(),
        args: vec!["--config=net.offline=false".to_owned()],
        in_dir: PathBuf::new(),
        why: "x".to_owned(),
        component: None,
    };
    assert!(
        with_value.command_line().contains('"'),
        "{}",
        with_value.command_line()
    );

    let quoted = Step {
        program: "node".to_owned(),
        args: vec!["--eval".to_owned(), "console.log(1)".to_owned()],
        in_dir: PathBuf::new(),
        why: "x".to_owned(),
        component: None,
    };
    assert!(
        quoted.command_line().contains("\"console.log(1)\""),
        "{}",
        quoted.command_line()
    );
}

#[test]
fn build_errors_explain_themselves() {
    let errors = [
        BuildError::NoManifest {
            path: "/p/manifest.json".to_owned(),
        },
        BuildError::BadManifest {
            reason: "missing field `id`".to_owned(),
        },
        BuildError::UiConfiguration {
            reason: "command must be a nonempty argv array".to_owned(),
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 25, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
