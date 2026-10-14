//! The rules a manifest must satisfy, and what each field means.
//!
//! # Why every rule is in one `impl` block
//!
//! Because the rules are a set: a manifest is valid when all of them hold, and read one at a time each can look redundant.
//! Keeping them together is what makes "is this field checked anywhere" answerable by reading one place.

mod capabilities;
mod declaration;
mod events;
mod presentation;
mod reading;

use crate::manifest::error::ManifestError;
use crate::manifest::types::{Manifest, ManifestContext, ValidationLevel};

impl Manifest {
    /// Every check the manifest alone can be held to.
    ///
    /// # Errors
    ///
    /// The first [`ManifestError`] found.
    pub fn validate(&self, level: ValidationLevel, context: &ManifestContext) -> Result<(), ManifestError> {
        self.check_identity()?;
        self.check_runtime(context)?;
        let capabilities = self.check_capabilities()?;
        self.check_names()?;
        self.check_events()?;
        self.check_handles()?;
        self.check_network(&capabilities)?;
        self.check_pages()?;
        self.check_composition()?;
        self.check_size_limits()?;
        self.check_versions(context)?;

        if level >= ValidationLevel::Verify {
            self.check_implementation(context)?;
        }
        Ok(())
    }
}
