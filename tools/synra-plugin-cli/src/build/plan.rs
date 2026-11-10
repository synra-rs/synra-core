use std::path::{Path, PathBuf};

use crate::template::TemplateKind;

use super::{Step, WASM_TARGET, ui};

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

    /// UI build metadata is invalid.
    #[error("invalid UI build configuration: {reason}")]
    UiConfiguration {
        /// The invalid metadata or path.
        reason: String,
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
    /// Artifacts inside the completed `dist/` package.
    pub expected: Vec<PathBuf>,
    /// Manifest snapshot copied to the completed package.
    pub manifest_json: String,
    /// Source assets relative to the project, separate from the package artifact.
    pub ui_source: Option<PathBuf>,
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
    /// build configuration.
    pub fn resolve(root: &Path) -> Result<Self, BuildError> {
        let manifest_path = root.join("manifest.json");
        if !manifest_path
            .try_exists()
            .map_err(|error| BuildError::BadManifest {
                reason: error.to_string(),
            })?
        {
            return Err(BuildError::NoManifest {
                path: manifest_path.display().to_string(),
            });
        }
        let text = crate::verify::read_manifest(root)
            .map_err(|reason| BuildError::BadManifest { reason })?;
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

        let mut ui_source = None;
        if let Some(ui) = ui {
            let (source, command) =
                ui::configuration(root).map_err(|reason| BuildError::UiConfiguration { reason })?;
            ui_source = Some(source);
            if let Some(command) = command {
                steps.push(command);
            }
            expected.push(PathBuf::from(&ui.artifact));
        }
        for artifact in &expected {
            let name = artifact.to_str().ok_or_else(|| BuildError::BadManifest {
                reason: "artifact path must be UTF-8".to_owned(),
            })?;
            synra_plugin_ui::artifact::check_package_artifact_path(name).map_err(|error| {
                BuildError::BadManifest {
                    reason: error.to_string(),
                }
            })?;
        }

        Ok(Self {
            root: root.to_path_buf(),
            kind,
            steps,
            expected,
            manifest_json: text,
            ui_source,
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
                let full = self.root.join("dist").join(artifact);
                let exists = full.is_file();
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
