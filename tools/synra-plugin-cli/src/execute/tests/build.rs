use crate::args::BuildArgs;
use crate::build::BuildPlan;
use crate::run::build_plugin;
use super::super::run_steps;
use super::Cleanup;

#[test]
fn a_build_whose_artifact_is_there_succeeds() {
    // The commands are not run in a test — that would be a test of the toolchain — so the plan is built directly and
    // the check that follows the commands is asserted on its own.
    let dir = Cleanup::new("built");
    dir.plugin();
    dir.write("dist/plugin.wasm", b"the module");

    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    assert!(plan.missing().is_empty());
    assert_eq!(plan.outcome_lines(), vec!["built plugin.wasm".to_owned()]);
}

#[test]
fn a_build_whose_artifact_is_missing_fails_even_though_nothing_reported_an_error() {
    // ★ The failure this check exists for: a build script that silently succeeded at nothing exits zero, and the
    // only thing that catches it is looking for the artifact.
    let dir = Cleanup::new("not-built");
    dir.plugin();

    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    let lines = plan.outcome_lines();
    assert!(!plan.missing().is_empty());
    assert!(lines[0].contains("plugin.wasm"), "{}", lines[0]);
    assert!(lines[0].contains("manifest"), "{}", lines[0]);
}

#[test]
fn a_build_plan_can_be_asked_for_without_a_dry_run() {
    // The wiring, asserted once: `build_plugin` resolves a plan and says what it will do.
    let dir = Cleanup::new("plan");
    dir.plugin();
    let outcome = build_plugin(&BuildArgs {
        dir: dir.path().to_path_buf(),
        dry_run: true,
    })
    .expect("plans");
    let lines = outcome.lines().join("\n");
    assert!(lines.contains("cargo build"), "{lines}");
    assert!(lines.contains("dry run"), "{lines}");
    assert_eq!(outcome.exit_code(), 0);
}

#[test]
fn a_build_of_a_directory_with_no_manifest_says_which_file() {
    let dir = Cleanup::new("no-manifest");
    let error = build_plugin(&BuildArgs {
        dir: dir.path().to_path_buf(),
        dry_run: false,
    })
    .expect_err("refused");
    assert!(error.contains("manifest.json"), "{error}");
}

#[test]
fn a_build_whose_step_exits_non_zero_stops_and_names_the_command() {
    // A real command that fails, on every platform this runs on: asking a program that does not exist is the
    // closest a test can get without a toolchain, and the code path is the same one.
    let dir = Cleanup::new("failing-step");
    dir.plugin();
    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    // A program that cannot be run: the plan is replaced by one whose step names it, so the failure path is
    // exercised without depending on a toolchain.
    let broken = BuildPlan {
        steps: vec![crate::build::Step {
            program: "synra-no-such-program".to_owned(),
            args: Vec::new(),
            in_dir: std::path::PathBuf::new(),
            why: "x".to_owned(),
            component: None,
        }],
        ..plan
    };
    let executed = run_steps(&broken);
    assert_eq!(executed.code, 1);
    assert!(
        executed.lines[0].contains("synra-no-such-program"),
        "{:?}",
        executed.lines
    );
}
