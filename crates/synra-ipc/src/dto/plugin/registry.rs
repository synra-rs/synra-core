//! Stable registry workflow reasons, independent of translated error text.

use serde::{Deserialize, Serialize};
use synra_protocol::{ErrorCode, error::SuggestedAction};

use crate::IpcError;

/// A registry failure the management interface can resolve through configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RegistryProblem {
    /// No source was selected, including an explicitly empty configuration.
    NotConfigured,
    /// The whole setting or one mirror is malformed.
    InvalidConfiguration {
        /// The owning configuration key.
        field: String,
        /// Zero-based mirror position, absent for a whole-setting or scalar failure.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<usize>,
        /// Diagnostic explanation, never used for workflow branching.
        reason: String,
    },
    /// Configured sources can serve known packages but cannot search a catalog.
    SearchUnsupported,
}

impl RegistryProblem {
    /// Convert a workflow reason into an IPC refusal with a typed diagnostic envelope.
    #[must_use]
    pub fn into_error(self) -> IpcError {
        let code = match &self {
            Self::InvalidConfiguration { .. } => ErrorCode::InvalidArgument,
            Self::NotConfigured | Self::SearchUnsupported => ErrorCode::Unsupported,
        };
        IpcError::unknown(code)
            .with_details(serde_json::json!({ "registry": self }))
            .with_action(SuggestedAction::OpenSettings {
                section: "plugins".to_owned(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_problem_does_not_depend_on_the_error_sentence() {
        let error = RegistryProblem::InvalidConfiguration {
            field: "plugins.registry".to_owned(),
            index: Some(1),
            reason: "every mirror must be a URL".to_owned(),
        }
        .into_error();
        let encoded = serde_json::to_value(&error).expect("IPC error");
        assert_eq!(encoded["code"], "invalid_argument");
        assert_eq!(
            encoded["details"]["registry"],
            serde_json::json!({
                "kind": "invalidConfiguration", "field": "plugins.registry", "index": 1,
                "reason": "every mirror must be a URL",
            })
        );
        assert_eq!(
            encoded["actions"],
            serde_json::json!([
                {"kind": "openSettings", "section": "plugins"}
            ])
        );
        let decoded: IpcError = serde_json::from_value(encoded).expect("round trip");
        assert_eq!(decoded, error);
    }
}
