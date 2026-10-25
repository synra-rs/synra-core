//! Public local-identity maintenance facts; private keys never cross a host boundary.

use crate::{DeviceId, ErrorCode};
use serde::{Deserialize, Serialize};

/// Persisted public enrollment, independently of the current process's authentication context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialEnrollment {
    /// SHA-256 of the enrolled public certificate.
    pub fingerprint: String,
    /// Secret backend selected for this enrollment.
    pub backend: String,
    /// Whether key readback was committed, not a current key-backend health probe.
    pub ready: bool,
}

/// Enrollment and runtime identity facts read together without secret-backend IO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSnapshot {
    /// Stable local device id.
    pub device_id: DeviceId,
    /// Current public enrollment, or explicit null when none exists.
    pub enrollment: Option<CredentialEnrollment>,
    /// Number of old secret slots still awaiting cleanup.
    pub retired_keys: u32,
    /// Whether the process captured the same ready certificate as the current enrollment.
    pub runtime_ready: bool,
    /// A ready enrollment is not loaded into this process; rebuilding its context requires restart.
    pub restart_required: bool,
}

/// Cleanup outcome, separate from a successful key replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCleanupReport {
    /// Remaining old slots on successful cleanup; unavailable backends can leave a nonzero count.
    pub remaining: Option<u32>,
    /// Structured cleanup failure without undoing a successful key replacement.
    pub error_code: Option<ErrorCode>,
    /// Diagnostic cleanup detail without key material.
    pub detail: Option<String>,
}

/// A successfully persisted new key; previous grants were revoked in the replacement transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRepairReport {
    /// Stable local device id.
    pub device_id: DeviceId,
    /// New certificate fingerprint.
    pub fingerprint: String,
    /// The host must rebuild its authentication context before pairing again.
    pub restart_required: bool,
    /// Independently observable old-secret cleanup outcome.
    pub cleanup: CredentialCleanupReport,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_enrollment_and_cleanup_values_are_required_nulls() {
        let snapshot = CredentialSnapshot {
            device_id: DeviceId::new(),
            enrollment: None,
            retired_keys: 0,
            runtime_ready: false,
            restart_required: false,
        };
        let mut value = serde_json::to_value(snapshot).unwrap();
        assert!(
            value
                .get("enrollment")
                .is_some_and(serde_json::Value::is_null)
        );
        value
            .as_object_mut()
            .unwrap()
            .insert("privateKey".to_owned(), serde_json::json!("refused"));
        assert!(serde_json::from_value::<CredentialSnapshot>(value).is_err());
        let cleanup = CredentialCleanupReport {
            remaining: None,
            error_code: Some(ErrorCode::Internal),
            detail: None,
        };
        let value = serde_json::to_value(cleanup).unwrap();
        assert!(
            value
                .get("remaining")
                .is_some_and(serde_json::Value::is_null)
        );
        assert!(value.get("detail").is_some_and(serde_json::Value::is_null));
    }
}
