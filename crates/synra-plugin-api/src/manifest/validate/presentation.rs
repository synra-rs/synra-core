use std::collections::HashSet;

use crate::manifest::error::ManifestError;
use crate::manifest::types::{Manifest, MAX_DESCRIPTION_LEN, MAX_NAME_LEN, MAX_TITLE_LEN};

impl Manifest {
    /// Names within the manifest.
    pub(super) fn check_names(&self) -> Result<(), ManifestError> {
        let mut actions = HashSet::new();
        for action in &self.actions {
            crate::manifest::validate_action_name(&action.name)?;
            if !actions.insert(action.name.as_str()) {
                return Err(ManifestError::DuplicateName {
                    kind: "action",
                    name: action.name.clone(),
                });
            }
        }
        Ok(())
    }

    /// Page keys.
    pub(super) fn check_pages(&self) -> Result<(), ManifestError> {
        let mut keys = HashSet::new();
        for page in &self.pages {
            if !keys.insert(page.key.as_str()) {
                return Err(ManifestError::DuplicatePageKey { key: page.key.clone() });
            }
        }
        if self.pages.is_empty() {
            return Ok(());
        }
        // A headless plugin has no interface to put a page in.
        if !self.has_ui() {
            return Err(ManifestError::UnusableCapability {
                cap: "ui:page".to_owned(),
                kind: "headless",
            });
        }
        if let Some(default_page) = self.runtime.ui.as_ref().and_then(|ui| ui.default_page.as_deref())
            && !keys.contains(default_page)
        {
            return Err(ManifestError::Malformed(format!(
                "the default page {default_page:?} is not one of the declared pages"
            )));
        }
        Ok(())
    }

    /// The length limits on strings that reach the interface.
    pub(super) fn check_size_limits(&self) -> Result<(), ManifestError> {
        check_len("title", &self.title, MAX_TITLE_LEN)?;
        if let Some(description) = &self.description {
            check_len("description", description, MAX_DESCRIPTION_LEN)?;
        }
        for action in &self.actions {
            check_len("action name", &action.name, MAX_NAME_LEN)?;
        }
        for page in &self.pages {
            check_len("page title", &page.title, MAX_TITLE_LEN)?;
        }
        Ok(())
    }
}

/// Checks a string's length.
fn check_len(field: &'static str, value: &str, max: usize) -> Result<(), ManifestError> {
    let len = value.chars().count();
    if len > max {
        return Err(ManifestError::TooLong { field, len, max });
    }
    Ok(())
}
