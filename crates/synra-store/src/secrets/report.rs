//! What a settings screen shows about a secret.

use serde::{Deserialize, Serialize};

use super::kind::SecretStrength;
use super::backend::SecretBackend;
use super::bytes::SecretError;

/// What a diagnostic report says about secret storage.
///
/// The strength and nothing else. A report that named the account or the value would be a report that leaks
/// what it is reporting on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretStorageReport {
    /// Which backend is in use.
    pub backend: String,
    /// What it protects against.
    pub strength: String,
    /// How many values are stored, when the backend can say.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entry_count: Option<usize>,
}

impl SecretStorageReport {
    /// Builds a report from a backend.
    ///
    /// # Errors
    ///
    /// Any failure other than a missing entry, from the backend's own probe.
    pub fn of(backend: &dyn SecretBackend) -> Result<Self, SecretError> {
        let kind = backend.kind();
        Ok(Self {
            backend: kind.as_str().to_owned(),
            strength: format!("{:?}", kind.strength()),
            entry_count: None,
        })
    }

    /// A sentence for the settings screen.
    #[must_use]
    pub fn explain(&self) -> String {
        let strength = match self.strength.as_str() {
            "OperatingSystem" => SecretStrength::OperatingSystem,
            "AtRestOnly" => SecretStrength::AtRestOnly,
            _ => SecretStrength::None,
        };
        format!("{}: {}", self.backend, strength.explain())
    }
}
