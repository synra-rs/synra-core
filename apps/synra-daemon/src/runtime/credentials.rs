//! Local maintenance commands never promote prior grants or replace keys implicitly.

use synra_control::{CredentialAction, Refusal};
use synra_core::device_credentials::{
    CredentialError, NetworkStartupError, cleanup_native_credentials, repair_fingerprint,
    repair_native_credentials,
};
use synra_protocol::ErrorCode;

use super::Runtime;

impl Runtime {
    pub(super) fn credential_action(
        &self,
        action: &CredentialAction,
    ) -> Result<serde_json::Value, Refusal> {
        match action {
            CredentialAction::Status => {
                let db = self.db.lock();
                let marker = db.device_credential().map_err(|error| internal(&error))?;
                let retired = db
                    .retired_device_credentials()
                    .map_err(|error| internal(&error))?
                    .len();
                drop(db);
                Ok(serde_json::json!({
                    "deviceId": self.identity.device_id,
                    "enrollment": marker.map(|record| serde_json::json!({
                        "fingerprint": repair_fingerprint(record.certificate()),
                        "backend": record.backend(),
                        "ready": record.ready(),
                    })),
                    "retiredKeys": retired,
                }))
            }
            CredentialAction::Repair {
                expected_fingerprint,
            } => {
                let repaired = repair_native_credentials(
                    &self.db,
                    self.identity.device_id,
                    expected_fingerprint,
                    super::now_ms() / 1000,
                )
                .map_err(|error| refusal(&error))?;
                let cleanup = match repaired.cleanup {
                    Ok(remaining) => serde_json::json!({"remaining": remaining}),
                    Err(error) => serde_json::json!({"error": error.to_string()}),
                };
                // Existing contexts capture the old credential and remain denied by the DB gates.
                // Restart is explicit; no live listener is declared ready from a new marker alone.
                Ok(serde_json::json!({
                    "deviceId": self.identity.device_id,
                    "fingerprint": repair_fingerprint(repaired.credentials.public_identity().certificate_der()),
                    "previousPairingsRevoked": true,
                    "restartRequired": true,
                    "cleanup": cleanup,
                }))
            }
            CredentialAction::Cleanup => {
                let remaining =
                    cleanup_native_credentials(&self.db).map_err(|error| refusal(&error))?;
                Ok(serde_json::json!({"remaining": remaining}))
            }
        }
    }
}

fn internal(error: &synra_store::DbError) -> Refusal {
    Refusal::new(ErrorCode::Internal, error.to_string())
}

fn refusal(error: &NetworkStartupError) -> Refusal {
    let code = match &error {
        NetworkStartupError::UnsupportedPlatform => ErrorCode::Unsupported,
        NetworkStartupError::Credential(
            CredentialError::RepairRefused | CredentialError::OperationBusy,
        ) => ErrorCode::InvalidArgument,
        _ => ErrorCode::NotPaired,
    };
    Refusal::new(code, error.to_string())
}
