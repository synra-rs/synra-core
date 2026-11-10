use crate::args::VerifyArgs;
use super::super::{Outcome, new_plugin, verify_plugin};
use super::scaffold::new_args;

#[test]
fn a_built_scaffold_succeeds() {
    let outcome = new_plugin(&new_args(None, false)).expect("builds");
    assert_eq!(outcome.exit_code(), 0);
    assert!(!outcome.is_failure());
}

// ── verify ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn verifying_an_empty_directory_reports_a_failure() {
    // The answer an author needs when they ran the command from the wrong directory.
    let dir = tempfile::Builder::new().prefix("empty").tempdir().expect("a temporary directory");
    let outcome = verify_plugin(&VerifyArgs {
        dir: dir.path().to_path_buf(),
        json: false,
        brief: false,
    });
    assert_eq!(outcome.exit_code(), 1);
    assert!(outcome.is_failure());
    assert!(outcome.lines()[0].contains("manifest"), "{:?}", outcome.lines());
}

#[test]
fn a_scaffold_verifies_cleanly() {
    // ★ The property that ties the two commands together: what `new` writes is what `verify` accepts. A scaffold
    // that does not verify is the failure an author meets first and cannot diagnose, because they do not yet know
    // what a correct manifest looks like.
    let dir = tempfile::Builder::new().prefix("scaffolded").tempdir().expect("a temporary directory");
    let outcome = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
    let Outcome::Scaffold { files, .. } = outcome else {
        panic!("expected a scaffold");
    };
    for (path, contents) in files {
        let full = dir.path().join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("creates");
        }
        std::fs::write(&full, contents).expect("writes");
    }
    // The Wasm artifact `verify` looks for, because a build has not run.
    std::fs::write(
        dir.path().join("plugin.wasm"),
        crate::test_component::component(),
    )
    .expect("writes");

    let report = verify_plugin(&VerifyArgs {
        dir: dir.path().to_path_buf(),
        json: false,
        brief: false,
    });
    assert_eq!(
        report.exit_code(),
        0,
        "a scaffolded plugin does not verify:\n{}",
        report.lines().join("\n")
    );
}

#[test]
fn json_output_still_carries_the_exit_code() {
    // ★ A failing `verify` asked for JSON still failed. The exit code follows the report and not its shape, which
    // is what a build script reads rather than parsing the body.
    let dir = tempfile::Builder::new().prefix("json-failure").tempdir().expect("a temporary directory");
    let outcome = verify_plugin(&VerifyArgs {
        dir: dir.path().to_path_buf(),
        json: true,
        brief: false,
    });
    assert_eq!(outcome.exit_code(), 1);
    assert!(outcome.is_failure());
    let body = outcome.lines().join("\n");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(value["findings"].as_array().is_some_and(|f| !f.is_empty()));
}

#[test]
fn json_output_for_a_healthy_plugin_succeeds() {
    let dir = tempfile::Builder::new().prefix("json-ok").tempdir().expect("a temporary directory");
    let _ = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
    // Write the scaffold by hand, since `new_plugin` only decides.
    let outcome = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
    let Outcome::Scaffold { files, .. } = outcome else {
        panic!("expected a scaffold");
    };
    for (path, contents) in files {
        let full = dir.path().join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("creates");
        }
        std::fs::write(&full, contents).expect("writes");
    }
    std::fs::write(
        dir.path().join("plugin.wasm"),
        crate::test_component::component(),
    )
    .expect("writes");

    let report = verify_plugin(&VerifyArgs {
        dir: dir.path().to_path_buf(),
        json: true,
        brief: false,
    });
    assert_eq!(report.exit_code(), 0, "{}", report.lines().join("\n"));
    assert!(!report.is_failure());
}

#[test]
fn a_brief_report_drops_the_suggestions() {
    // What a build script's log wants: the finding without the advice.
    let dir = tempfile::Builder::new().prefix("brief").tempdir().expect("a temporary directory");
    let full = verify_plugin(&VerifyArgs {
        dir: dir.path().to_path_buf(),
        json: false,
        brief: false,
    });
    let brief = verify_plugin(&VerifyArgs {
        dir: dir.path().to_path_buf(),
        json: false,
        brief: true,
    });

    assert!(
        full.lines().iter().any(|line| line.starts_with("      ")),
        "the full report has no suggestions to drop: {:?}",
        full.lines()
    );
    assert!(
        !brief.lines().iter().any(|line| line.starts_with("      ")),
        "{:?}",
        brief.lines()
    );
    // And the verdict is unchanged, because the advice is not what decides.
    assert_eq!(full.exit_code(), brief.exit_code());
}
