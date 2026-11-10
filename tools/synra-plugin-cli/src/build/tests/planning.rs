use std::path::PathBuf;
use crate::template::TemplateKind;
use super::super::{BuildError, BuildPlan, WASM_TARGET};
use super::Cleanup;

#[test]
fn a_headless_manifest_plans_one_cargo_build() {
    let dir = Cleanup::new("headless");
    dir.headless("plugin.wasm");

    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    assert_eq!(plan.kind, TemplateKind::Headless);
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.steps[0].program, "cargo");
    assert_eq!(plan.steps[0].args[0], "build");
    assert_eq!(plan.expected, vec![PathBuf::from("plugin.wasm")]);
}

#[test]
fn the_cargo_build_names_the_wasm_target() {
    // ★ A `cdylib` built for the host is a shared library the kernel cannot load and `verify` will not accept. A
    // plan that omitted the target would compile successfully and produce the wrong thing, which is the failure
    // that costs the most time.
    let dir = Cleanup::new("target");
    dir.headless("plugin.wasm");

    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    let args = &plan.steps[0].args;
    let position = args
        .iter()
        .position(|arg| arg == "--target")
        .expect("the target flag");
    assert_eq!(args[position + 1], WASM_TARGET);
    assert_eq!(WASM_TARGET, "wasm32-unknown-unknown");
    assert!(
        args.iter().any(|arg| arg == "--release"),
        "not a release build: {args:?}"
    );
}

#[test]
fn a_ui_only_manifest_is_refused_before_a_build_is_planned() {
    let dir = Cleanup::new("ui-only");
    dir.ui("dist");
    dir.package_with_build();
    let error = BuildPlan::resolve(dir.path()).unwrap_err();
    assert!(matches!(error, BuildError::BadManifest { .. }));
    assert!(error.to_string().contains("headless"), "{error}");
}

#[test]
fn a_hybrid_manifest_plans_both_in_order() {
    // Wasm first, because the interface's build may read the module's metadata — and because a plan whose order
    // varied would make a failure depend on which half broke first.
    let dir = Cleanup::new("hybrid");
    dir.hybrid("plugin.wasm", "dist");
    dir.package_with_build();

    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    assert_eq!(plan.kind, TemplateKind::Hybrid);
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(plan.steps[0].program, "cargo");
    assert_eq!(plan.steps[1].program, "npm");
    assert_eq!(
        plan.expected,
        vec![PathBuf::from("plugin.wasm"), PathBuf::from("dist")]
    );
}

#[test]
fn the_artifact_path_comes_from_the_manifest() {
    // The manifest is what the kernel reads, so a build that wrote to a path of this tool's choosing would produce
    // a plugin that installs and cannot load.
    let dir = Cleanup::new("artifact");
    dir.headless("dist/plugin.wasm");

    let plan = BuildPlan::resolve(dir.path()).expect("resolves");
    assert_eq!(plan.expected, vec![PathBuf::from("dist/plugin.wasm")]);
}

// ── Refusals ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_directory_with_no_manifest_is_refused() {
    // The answer an author needs when they ran the command from the wrong directory.
    let dir = Cleanup::new("empty");
    match BuildPlan::resolve(dir.path()) {
        Err(BuildError::NoManifest { path }) => {
            assert!(path.contains("manifest.json"), "{path}")
        }
        other => panic!("expected a missing manifest, got {other:?}"),
    }
}

#[test]
fn a_manifest_that_does_not_parse_is_refused() {
    let dir = Cleanup::new("bad");
    dir.write("manifest.json", "{ not json");
    assert!(matches!(
        BuildPlan::resolve(dir.path()),
        Err(BuildError::BadManifest { .. })
    ));
}

#[test]
fn a_static_hybrid_needs_no_package_manager() {
    let dir = Cleanup::new("static-ui");
    dir.hybrid("plugin.wasm", "ui.zip");
    let plan = BuildPlan::resolve(dir.path()).unwrap();
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.ui_source, Some(PathBuf::from("ui")));
}

#[test]
fn malformed_explicit_ui_commands_are_refused() {
    let dir = Cleanup::new("bad-ui-command");
    dir.hybrid("plugin.wasm", "ui.zip");
    dir.write("Cargo.toml", "[package.metadata.synra.ui]\ncommand = []\n");
    assert!(matches!(
        BuildPlan::resolve(dir.path()),
        Err(BuildError::UiConfiguration { .. })
    ));
}

#[test]
fn a_manifest_declaring_no_runtime_is_refused() {
    // A plugin with neither half has nothing to build and cannot be loaded either — the manifest's own validation
    // refuses it, so this is the second line of defence.
    let dir = Cleanup::new("nothing");
    dir.write(
        "manifest.json",
        r#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": {},
  "capabilities": []
}"#,
    );
    assert!(matches!(
        BuildPlan::resolve(dir.path()),
        Err(BuildError::BadManifest { .. })
    ));
}
