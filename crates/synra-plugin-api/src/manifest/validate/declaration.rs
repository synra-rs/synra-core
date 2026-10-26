use crate::manifest::error::ManifestError;
use crate::manifest::types::{Manifest, ManifestContext};
use crate::manifest::version::{check_plugin_id, check_version, compare_versions};

impl Manifest {
    /// The complete package id and versions.
    pub(super) fn check_identity(&self) -> Result<(), ManifestError> {
        check_plugin_id(self.id.as_str())?;
        check_version(&self.version)?;
        check_version(&self.sdk.min)?;
        if let Some(preferred) = &self.sdk.preferred {
            check_version(preferred)?;
        }
        Ok(())
    }

    /// The runtime's shape and its artifacts.
    pub(super) fn check_runtime(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        if !self.is_headless() && !self.has_ui() {
            return Err(ManifestError::NoRuntime);
        }

        if let Some(present) = &context.present_artifacts {
            let check = |kind: &'static str, path: &str| {
                if present.iter().any(|artifact| artifact == path) {
                    Ok(())
                }
                else {
                    Err(ManifestError::MissingArtifact { kind, path: path.to_owned() })
                }
            };
            if let Some(headless) = &self.runtime.headless {
                check("headless", &headless.artifact)?;
            }
            if let Some(ui) = &self.runtime.ui {
                check("ui", &ui.artifact)?;
            }
        }

        if let Some(ui) = &self.runtime.ui
            && ui.entry.trim().is_empty()
        {
            return Err(ManifestError::Malformed(
                "the ui runtime declares an empty entry document".to_owned(),
            ));
        }
        Ok(())
    }

    /// Composition cycles.
    ///
    /// A plugin naming itself is the cycle that matters most, because it is the one an author writes by
    /// accident when copying a template. A cycle between two plugins is the loader's business, since it can see
    /// the whole set; this catches the part that is visible from one file.
    pub(super) fn check_composition(&self) -> Result<(), ManifestError> {
        for dependency in &self.compose {
            if dependency.id == self.id {
                return Err(ManifestError::CompositionCycle {
                    through: vec![self.id.to_string()],
                });
            }
            check_version(dependency.version.trim_start_matches(['^', '~', '=', '>', '<', ' ']))?;
        }
        Ok(())
    }

    /// The SDK and WIT compatibility checks.
    pub(super) fn check_versions(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        if let Some(host) = &context.host_sdk
            && compare_versions(&self.sdk.min, host)? == core::cmp::Ordering::Greater
        {
            return Err(ManifestError::SdkTooOld {
                min: self.sdk.min.clone(),
                host: host.clone(),
            });
        }
        if let Some(host_wit) = &context.host_wit
            && self.wit != *host_wit
        {
            return Err(ManifestError::WitMismatch {
                plugin: self.wit.clone(),
                host: host_wit.clone(),
            });
        }
        Ok(())
    }

    /// Whether the declarations and the implementation agree, in both directions.
    pub(super) const fn check_implementation(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        let Some(implementation) = context.implementation else {
            return Ok(());
        };

        if !self.handles.is_empty() && !implementation.on_event {
            return Err(ManifestError::MissingImplementation { declared: "`handles`" });
        }
        if self.handles.is_empty() && implementation.on_event {
            return Err(ManifestError::UndeclaredImplementation { implemented: "on_event" });
        }

        // An interface-only plugin's actions run in the interface, so `execute` is about the headless half.
        if !self.actions.is_empty() && self.is_headless() && !implementation.execute {
            return Err(ManifestError::MissingImplementation { declared: "`actions`" });
        }
        if self.actions.is_empty() && implementation.execute {
            return Err(ManifestError::UndeclaredImplementation { implemented: "execute" });
        }
        Ok(())
    }
}
