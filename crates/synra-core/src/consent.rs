//! What a user's answer about a plugin's capabilities amounts to.
//!
//! # Why this is a function in the kernel and not a few lines in each host
//!
//! Because both hosts ask the same question, and they had answered it **differently**: the shell treated a plugin as
//! trusted only when every declared capability was granted, the daemon when any was. The loader then takes the granted
//! rows as the authority and loads either way — so one user decision produced a plugin that could not run in one host
//! and one that ran with a subset in the other.
//!
//! # The rule, and why partial consent runs
//!
//! **Trusted means the user allowed something.** A decision that denies everything is a refusal and leaves the plugin
//! unable to run; a decision that allows one of three means the plugin runs with that one and is refused at the gate for
//! the other two. That is what the design document's `Consent { granted, denied }` and `is_partial()` describe, and what
//! the loader already does — a plugin whose grants are a subset is exactly what a capability gate is for.
//!
//! The alternative — "trusted only if nothing was declined" — sounds safer and is not: it records the partial decision
//! and then ignores it, so the user sees a plugin they allowed two capabilities for and that never runs, with no
//! setting that explains why.
//!
//! # What it does not do
//!
//! It writes nothing. Recording a decision is two writes to the store (the rows and the trust flag) and that belongs to
//! the host that owns the database; this decides **what** to write, once.

use synra_plugin_api::Manifest;
use synra_plugin_api::manifest_digest;

/// One capability, and whether the user allowed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    capability: String,
    granted: bool,
}

impl Row {
    /// Which capability.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// Whether the user allowed it.
    #[must_use]
    pub const fn granted(&self) -> bool {
        self.granted
    }
}

/// What the user's answer amounts to, ready to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    rows: Vec<Row>,
    digest: String,
}

impl Decision {
    /// One row per declared capability, in the manifest's own order.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The same rows in the shape a store records them.
    ///
    /// A pair of `(capability, granted)` rather than the row type, because the store's writer has no business knowing
    /// this module's types — and the conversion is at the one boundary where the two meet.
    #[must_use]
    pub fn pairs(&self) -> Vec<(String, bool)> {
        self.rows.iter().map(|row| (row.capability.clone(), row.granted)).collect()
    }

    /// The digest of the manifest the decision was made about.
    ///
    /// A later manifest with a capability added hashes differently, which is how the loader notices that the decision
    /// on record is about a document the plugin no longer ships.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Whether the plugin may run at all.
    #[must_use]
    pub fn trusted(&self) -> bool {
        self.rows.iter().any(Row::granted)
    }

    /// The capabilities the user allowed.
    pub fn granted(&self) -> impl Iterator<Item = &str> {
        self.rows.iter().filter(|row| row.granted).map(Row::capability)
    }

    /// The capabilities the user refused.
    pub fn denied(&self) -> impl Iterator<Item = &str> {
        self.rows.iter().filter(|row| !row.granted).map(Row::capability)
    }
}

/// Why a decision could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConsentError {
    /// The user named a capability the plugin never asked for.
    ///
    /// # Why this is a refusal rather than being ignored
    ///
    /// It is usually a typo — the user meant another capability and would believe they had granted it — and when it is
    /// not, it is a client widening a decision the user did not make. Recording it would put a grant in the table that
    /// no gate will ever consult, and a denial in the plugin's card for a capability it does not have.
    #[error("the plugin does not ask for `{capability}`")]
    UnknownCapability {
        /// What was named.
        capability: String,
    },
}

/// Turns a user's answer into the rows to record.
///
/// # Errors
///
/// [`ConsentError::UnknownCapability`] when a granted capability is not one the manifest declares.
pub fn decide(
    manifest: &Manifest,
    manifest_json: &str,
    granted: &[String],
) -> Result<Decision, ConsentError> {
    let declared: Vec<&str> = manifest.capabilities.iter().map(|capability| capability.cap.as_str()).collect();
    if let Some(unknown) = granted.iter().find(|allowed| !declared.contains(&allowed.as_str())) {
        return Err(ConsentError::UnknownCapability { capability: unknown.clone() });
    }
    let rows = manifest
        .capabilities
        .iter()
        .map(|capability| Row {
            capability: capability.cap.clone(),
            granted: granted.contains(&capability.cap),
        })
        .collect();
    Ok(Decision { rows, digest: manifest_digest(manifest_json) })
}

#[cfg(test)]
mod tests;
