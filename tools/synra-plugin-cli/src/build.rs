//! Build plans choose commands and destinations; component output is staged only after Cargo succeeds.
//!
//! Rust guests compile to a core module without ambient WASI imports. Cargo's JSON metadata locates
//! the actual cdylib, including custom library names and target directories; the component encoder
//! uses the SDK's embedded WIT metadata and writes the manifest's artifact atomically.
//! Ordinary unit tests cover decisions and failures; the opt-in authoring gate builds a real scaffold.

use std::path::{Path, PathBuf};

use crate::template::TemplateKind;

pub mod component;

/// The Rust core-module target; the SDK supplies host imports and the CLI supplies component encoding.
pub const WASM_TARGET: &str = "wasm32-unknown-unknown";

/// The `package.json` script a UI plugin's build runs.
pub const UI_BUILD_SCRIPT: &str = "build";

/// One command to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The program.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The directory to run it in, relative to the plugin's root.
    pub in_dir: PathBuf,
    /// What this step is for, in a sentence an author reads.
    pub why: String,
    /// Component destination relative to the plugin root, when this is a Cargo build.
    pub component: Option<PathBuf>,
}

impl Step {
    /// The whole command, as an author would type it.
    ///
    /// # Why quoting is not "does it contain a space"
    ///
    /// A line is printed so an author can copy it into a shell, and a shell treats more than spaces as
    /// significant — `console.log(1)` has no space and would be a syntax error pasted into `sh`. So an argument is
    /// quoted whenever it contains anything a shell would interpret, which is the property the line is for.
    #[must_use]
    pub fn command_line(&self) -> String {
        let mut line = self.program.clone();
        for arg in &self.args {
            line.push(' ');
            if needs_quoting(arg) {
                line.push_str(&format!("\"{arg}\""));
            } else {
                line.push_str(arg);
            }
        }
        line
    }
}

/// Whether a shell would interpret an argument.
///
/// The set is deliberately conservative — punctuation that is harmless in one shell is a substitution in another — and
/// the cost of being wrong is a quoted word that did not need quoting.
fn needs_quoting(arg: &str) -> bool {
    arg.is_empty()
        || arg.contains(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '"' | '\''
                        | '\\'
                        | '$'
                        | '`'
                        | '&'
                        | '|'
                        | ';'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '!'
                        | '#'
                        | '~'
                        | '='
                        | ','
                        | ':'
                )
        })
}

/// Why a build could not be planned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// There is no plugin here.
    #[error("there is no manifest.json in {path}")]
    NoManifest {
        /// Where it looked.
        path: String,
    },

    /// The manifest does not parse.
    #[error("the manifest does not parse: {reason}")]
    BadManifest {
        /// What the parser said.
        reason: String,
    },

    /// A UI plugin has no `package.json`, so there is no build script to run.
    ///
    /// Refused rather than defaulted to a bundler: the one an author picked is the one their project already works
    /// with, and a tool that chose for them would produce an artifact their project does not reproduce.
    #[error("{path} declares no `{script}` script, so there is nothing to run")]
    NoUiBuildScript {
        /// The file that was missing or incomplete.
        path: String,
        /// The script name.
        script: String,
    },
}

/// What a build will do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlan {
    /// The plugin's root.
    pub root: PathBuf,
    /// The kind, derived from the manifest's runtime block.
    pub kind: TemplateKind,
    /// The commands, in order.
    pub steps: Vec<Step>,
    /// The artifacts the build is expected to produce, relative to the root.
    pub expected: Vec<PathBuf>,
}

impl BuildPlan {
    /// Decides the build for a plugin directory.
    ///
    /// # The kind comes from the manifest
    ///
    /// Not from a flag and not from which files happen to be present. A manifest declaring both halves is a hybrid
    /// plugin whatever else is on disk, and a flag would let a user build half of one — which produces an artifact the
    /// manifest disagrees with, and the disagreement surfaces at install.
    ///
    /// # Errors
    ///
    /// [`BuildError`] when there is no manifest, it does not parse, it declares no runtime, or a UI plugin has no
    /// build script.
    pub fn resolve(root: &Path) -> Result<Self, BuildError> {
        let manifest_path = root.join("manifest.json");
        let text = std::fs::read_to_string(&manifest_path).map_err(|_| BuildError::NoManifest {
            path: manifest_path.display().to_string(),
        })?;
        let manifest = synra_plugin_api::manifest::Manifest::from_json(&text).map_err(|error| {
            BuildError::BadManifest {
                reason: error.to_string(),
            }
        })?;

        manifest
            .validate(&synra_plugin_api::ManifestContext::default())
            .map_err(|error| BuildError::BadManifest {
                reason: error.to_string(),
            })?;
        let headless = manifest.runtime.headless.as_ref();
        let ui = manifest.runtime.ui.as_ref();
        let kind = if ui.is_some() {
            TemplateKind::Hybrid
        } else {
            TemplateKind::Headless
        };

        let mut steps = Vec::new();
        let mut expected = Vec::new();

        if let Some(headless) = headless {
            steps.push(Step {
                program: "cargo".to_owned(),
                args: vec![
                    "build".to_owned(),
                    "--target".to_owned(),
                    WASM_TARGET.to_owned(),
                    "--release".to_owned(),
                    "--message-format=json-render-diagnostics".to_owned(),
                ],
                in_dir: PathBuf::new(),
                component: Some(PathBuf::from(&headless.artifact)),
                why: format!(
                    "compile the Wasm half to {WASM_TARGET}, which is the target the kernel's host functions are \
                     defined against"
                ),
            });
            // The artifact path comes from the manifest rather than from a constant, because the manifest is what the
            // kernel reads: a build that wrote somewhere else would produce a plugin that installs and cannot load.
            expected.push(PathBuf::from(&headless.artifact));
        }

        if let Some(ui) = ui {
            // The script is the author's, read from their `package.json`: this tool does not choose a bundler, because
            // the one they picked is the one their project already works with.
            let package = root.join("package.json");
            let text =
                std::fs::read_to_string(&package).map_err(|_| BuildError::NoUiBuildScript {
                    path: package.display().to_string(),
                    script: UI_BUILD_SCRIPT.to_owned(),
                })?;
            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(|_| BuildError::NoUiBuildScript {
                    path: package.display().to_string(),
                    script: UI_BUILD_SCRIPT.to_owned(),
                })?;
            let has_script = value
                .get("scripts")
                .and_then(|scripts| scripts.get(UI_BUILD_SCRIPT))
                .is_some();
            if !has_script {
                return Err(BuildError::NoUiBuildScript {
                    path: package.display().to_string(),
                    script: UI_BUILD_SCRIPT.to_owned(),
                });
            }

            steps.push(Step {
                program: "npm".to_owned(),
                args: vec!["run".to_owned(), UI_BUILD_SCRIPT.to_owned()],
                in_dir: PathBuf::new(),
                component: None,
                why: "run the interface's own build, which writes the bundle the manifest names"
                    .to_owned(),
            });
            expected.push(PathBuf::from(&ui.artifact));
        }

        Ok(Self {
            root: root.to_path_buf(),
            kind,
            steps,
            expected,
        })
    }

    /// The lines a person reads.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "{} plugin in {}",
            self.kind.as_str(),
            self.root.display()
        )];
        for (index, step) in self.steps.iter().enumerate() {
            lines.push(format!("{}. {}", index + 1, step.command_line()));
            lines.push(format!("   {}", step.why));
        }
        for artifact in &self.expected {
            lines.push(format!("expects {}", artifact.display()));
        }
        lines
    }

    /// Whether every expected artifact exists.
    ///
    /// Separate from [`Self::resolve`], because a plan is decided *before* the commands run and the artifacts are
    /// checked after. A `resolve` that also demanded the artifacts would be one that could not plan a first build.
    #[must_use]
    pub fn produced(&self) -> Vec<(PathBuf, bool)> {
        self.expected
            .iter()
            .map(|artifact| {
                let full = self.root.join(artifact);
                let exists = full.exists();
                (artifact.clone(), exists)
            })
            .collect()
    }

    /// The artifacts that are missing.
    #[must_use]
    pub fn missing(&self) -> Vec<PathBuf> {
        self.produced()
            .into_iter()
            .filter_map(|(path, exists)| if exists { None } else { Some(path) })
            .collect()
    }

    /// The lines for a build that ran, naming what is missing.
    #[must_use]
    pub fn outcome_lines(&self) -> Vec<String> {
        let missing = self.missing();
        if missing.is_empty() {
            return self
                .expected
                .iter()
                .map(|artifact| format!("built {}", artifact.display()))
                .collect();
        }
        missing
            .into_iter()
            .map(|artifact| {
                format!(
                    "{} was not produced — check that the build writes to the path the manifest names",
                    artifact.display()
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary plugin directory.
    struct Cleanup(PathBuf);

    impl Cleanup {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("synra-build-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creates");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Writes a file, making its parents.
        fn write(&self, path: &str, contents: &str) {
            let full = self.0.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("creates");
            }
            std::fs::write(full, contents).expect("writes");
        }

        /// Writes a manifest with the given runtime block and artifact.
        fn manifest(&self, runtime: &str, artifact: &str) {
            self.write(
                "manifest.json",
                &format!(
                    r#"{{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": {{ "id": "synra-official" }},
  "sdk": {{ "min": "0.1.0" }},
  "wit": "synra:plugin@1.0.0",
  "runtime": {runtime},
  "capabilities": []
}}"#
                ),
            );
            let _ = artifact;
        }

        fn headless(&self, artifact: &str) {
            self.manifest(
                &format!(r#"{{ "headless": {{ "artifact": "{artifact}", "stateful": false }} }}"#),
                artifact,
            );
        }

        fn ui(&self, artifact: &str) {
            self.manifest(
                &format!(r#"{{ "ui": {{ "artifact": "{artifact}", "entry": "index.html" }} }}"#),
                artifact,
            );
        }

        fn hybrid(&self, wasm: &str, ui: &str) {
            self.manifest(
                &format!(
                    r#"{{ "headless": {{ "artifact": "{wasm}", "stateful": false }}, "ui": {{ "artifact": "{ui}", "entry": "index.html" }} }}"#
                ),
                wasm,
            );
        }

        /// A `package.json` with a build script.
        fn package_with_build(&self) {
            self.write(
                "package.json",
                r#"{ "scripts": { "build": "vite build" } }"#,
            );
        }

        /// A `package.json` without one.
        fn package_without_build(&self) {
            self.write("package.json", r#"{ "scripts": { "dev": "vite" } }"#);
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── The kind comes from the manifest ──────────────────────────────────────────────────────────

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
    fn a_ui_plugin_with_no_build_script_is_refused_rather_than_defaulted() {
        // ★ Refused rather than defaulted to a bundler. A tool that chose one would produce an artifact the author's
        // own project does not reproduce, and the difference would appear as a plugin that behaves differently when
        // they build it themselves.
        let dir = Cleanup::new("no-script");
        dir.hybrid("plugin.wasm", "dist");
        dir.package_without_build();

        match BuildPlan::resolve(dir.path()) {
            Err(BuildError::NoUiBuildScript { path, script }) => {
                assert!(path.contains("package.json"), "{path}");
                assert_eq!(script, "build");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_ui_plugin_with_no_package_json_is_refused_the_same_way() {
        // The two are the same problem from the author's side: there is nothing to run.
        let dir = Cleanup::new("no-package");
        dir.hybrid("plugin.wasm", "dist");
        assert!(matches!(
            BuildPlan::resolve(dir.path()),
            Err(BuildError::NoUiBuildScript { .. })
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

    // ── What was produced ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plan_reports_what_is_missing() {
        // The check that runs *after* the commands, and the one that catches a build script that silently succeeded at
        // nothing.
        let dir = Cleanup::new("missing");
        dir.headless("plugin.wasm");

        let plan = BuildPlan::resolve(dir.path()).expect("resolves");
        assert_eq!(plan.missing(), vec![PathBuf::from("plugin.wasm")]);

        dir.write("plugin.wasm", "");
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
            BuildError::NoUiBuildScript {
                path: "/p/package.json".to_owned(),
                script: "build".to_owned(),
            },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 25, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}
