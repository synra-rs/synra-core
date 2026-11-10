use std::collections::BTreeMap;

use synra_plugin_api::manifest::{Manifest, ManifestContext};

use super::TemplateKind;
use super::files::{HEADLESS_SOURCE, gitignore, hybrid_source, manifest_json, readme, ui_document};

/// Why a scaffold could not be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScaffoldError {
    /// The plugin id is not one the kernel would accept.
    ///
    /// Refused here rather than discovered at install: an id is in every path, every log line and every capability
    /// string, so changing it later is a rename across the whole plugin.
    #[error("the plugin id is not usable: {reason}")]
    BadId {
        /// What the validator said.
        reason: String,
    },

    /// The version is not a version.
    #[error("the version is not usable: {reason}")]
    BadVersion {
        /// What the validator said.
        reason: String,
    },

    /// The name is not one a plugin may have.
    #[error("the name is not usable: {reason}")]
    BadName {
        /// What the validator said.
        reason: String,
    },
}

/// A file a scaffold will write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldFile {
    /// Where it goes, relative to the plugin's directory, with `/` as the separator.
    pub path: String,
    /// What it contains.
    pub contents: String,
    /// Whether the author is expected to edit it, which decides whether it is reported as theirs or as scaffolding.
    pub authored: bool,
}

/// What `new` will write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scaffold {
    /// The plugin's id, as it will appear in the manifest.
    pub plugin_id: String,
    /// The version.
    pub version: String,
    /// The directory name, derived from the id.
    pub directory: String,
    /// Every file, sorted by path so the output is stable.
    pub files: Vec<ScaffoldFile>,
    /// The kind.
    pub kind: TemplateKind,
}

impl Scaffold {
    /// Builds the scaffold for a plugin.
    ///
    /// # Errors
    ///
    /// [`ScaffoldError`] when the id, version or name is one the kernel's own validator would refuse.
    ///
    /// # Why the validation runs here
    ///
    /// The same functions the manifest's own validation uses, so a scaffold cannot produce a manifest that fails
    /// `verify` — which is the one thing an author would reasonably expect and the one thing a template that
    /// duplicated the rules would get wrong.
    pub fn new(
        plugin_id: &str,
        version: &str,
        title: &str,
        kind: TemplateKind,
    ) -> Result<Self, ScaffoldError> {
        synra_plugin_api::manifest::check_plugin_id(plugin_id).map_err(|error| {
            ScaffoldError::BadId {
                reason: error.to_string(),
            }
        })?;
        synra_plugin_api::manifest::check_version(version).map_err(|error| {
            ScaffoldError::BadVersion {
                reason: error.to_string(),
            }
        })?;
        if title.trim().is_empty() {
            return Err(ScaffoldError::BadName {
                reason: "the title is empty".to_owned(),
            });
        }

        // The directory is the wire slug, so a plugin's directory is the name its artifact uses everywhere else — the
        // registry, the cache, the log. A directory named after the raw id would contain a `/` and a scope.
        //
        // Parsed once, here, and the result used for both the directory and the crate name: parsing again where the
        // crate manifest is written would need an `expect` on a value that was already proven valid, and an `expect` in
        // production code is what this workspace forbids.
        let id =
            synra_protocol::PluginId::parse(plugin_id).map_err(|error| ScaffoldError::BadId {
                reason: error.to_string(),
            })?;
        let slug = synra_plugin_api::manifest::to_project_slug(&id).map_err(|error| {
            ScaffoldError::BadId {
                reason: error.to_string(),
            }
        })?;

        let manifest = manifest_json(plugin_id, version, title, kind);
        let mut files = vec![
            ScaffoldFile {
                path: "manifest.json".to_owned(),
                contents: manifest,
                authored: false,
            },
            ScaffoldFile {
                path: "README.md".to_owned(),
                contents: readme(plugin_id, kind),
                authored: true,
            },
            ScaffoldFile {
                path: ".gitignore".to_owned(),
                contents: gitignore(),
                authored: false,
            },
        ];

        // A crate manifest, so `build` has something to compile. Written as text rather than left out, because a
        // scaffold whose `build` needs a file the author has to invent is a scaffold that does not build.
        let crate_manifest = format!(
            r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"

# A plugin is a library, not a binary: the kernel loads it, nothing runs it.
[lib]
crate-type = ["cdylib"]

[dependencies]
# The SDK supplies the component ABI; all effects go through its capability-gated host imports.
synra-plugin-sdk = "0.1"

# Release builds are what get published, and a plugin is loaded once and called many times.
[profile.release]
opt-level = "s"
lto = true
codegen-units = 1
panic = "abort"
strip = true
"#,
            name = slug,
        );

        match kind {
            TemplateKind::Headless => {
                files.push(ScaffoldFile {
                    path: "Cargo.toml".to_owned(),
                    contents: crate_manifest,
                    authored: false,
                });
                files.push(ScaffoldFile {
                    path: "src/lib.rs".to_owned(),
                    contents: HEADLESS_SOURCE.to_owned(),
                    authored: true,
                });
            }
            TemplateKind::Hybrid => {
                files.push(ScaffoldFile {
                    path: "Cargo.toml".to_owned(),
                    contents: crate_manifest,
                    authored: false,
                });
                files.push(ScaffoldFile {
                    path: "src/lib.rs".to_owned(),
                    contents: hybrid_source(),
                    authored: true,
                });
                files.push(ScaffoldFile {
                    path: "ui/index.html".to_owned(),
                    contents: ui_document(title),
                    authored: true,
                });
            }
        }

        files.sort_by(|first, second| first.path.cmp(&second.path));

        Ok(Self {
            plugin_id: plugin_id.to_owned(),
            version: version.to_owned(),
            directory: slug,
            files,
            kind,
        })
    }

    /// The paths it will write.
    ///
    /// Owned for the same reason [`Self::as_map`] is: a caller usually builds the scaffold inline, and a reference
    /// into a temporary is a borrow error at every call site.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        self.files.iter().map(|file| file.path.clone()).collect()
    }

    /// The files, as a map from path to contents.
    ///
    /// Owned rather than borrowed: a caller comparing a template against what it expects usually builds the scaffold
    /// inline, and a returned reference into a temporary is a borrow error at every call site rather than a design
    /// decision made once.
    #[must_use]
    pub fn as_map(&self) -> BTreeMap<String, String> {
        self.files
            .iter()
            .map(|file| (file.path.clone(), file.contents.clone()))
            .collect()
    }

    /// The manifest it will write, parsed and validated.
    ///
    /// # Errors
    ///
    /// The validator's error, when the template produced something it refuses. This exists so a test can assert the
    /// templates against the kernel's own rules rather than against a second copy of them.
    pub fn validate_manifest(&self) -> Result<Manifest, String> {
        let files = self.as_map();
        let text = files
            .get("manifest.json")
            .ok_or_else(|| "the scaffold has no manifest".to_owned())?;
        let manifest = Manifest::from_json(text).map_err(|error| error.to_string())?;

        let context = ManifestContext {
            // The lowest SDK the scaffold could name, so a template is checked against the rule an author meets
            // rather than against a version chosen to make it pass.
            host_sdk: Some(manifest.sdk.min.clone()),
            ..ManifestContext::default()
        };
        manifest
            .validate(&context)
            .map_err(|error| error.to_string())?;
        Ok(manifest)
    }
}
