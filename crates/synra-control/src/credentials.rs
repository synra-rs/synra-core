//! Explicit local identity maintenance, separate from remote peer pairing.

use serde::{Deserialize, Serialize};

/// One maintenance action from the authenticated local operating-system user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialAction {
    /// Inspect public enrollment and pending old-secret cleanup.
    Status,
    /// Replace exactly the displayed certificate and revoke all previous peer authorizations.
    Repair {
        /// SHA-256 of the public enrollment the user explicitly confirmed.
        expected_fingerprint: String,
    },
    /// Retry old-secret deletion without replacing keys or granting access.
    Cleanup,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_confirmation_uses_camel_case_and_rejects_unrecognized_fields() {
        let action = CredentialAction::Repair {
            expected_fingerprint: "displayed".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&action).unwrap(),
            serde_json::json!({"action": "repair", "expectedFingerprint": "displayed"})
        );
        assert!(
            serde_json::from_value::<CredentialAction>(serde_json::json!({
                "action": "repair", "expectedFingerprint": "displayed", "force": true,
            }))
            .is_err()
        );
    }
}
