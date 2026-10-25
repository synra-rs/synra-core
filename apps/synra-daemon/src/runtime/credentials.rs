//! Thin local-control adapter for shared typed credential maintenance.
use super::Runtime;
use synra_control::{CredentialAction, Refusal};
use synra_core::device_credentials::{
    cleanup_native_identity, credential_snapshot, repair_native_identity,
};

impl Runtime {
    pub(super) fn credential_action(
        &self,
        action: &CredentialAction,
    ) -> Result<serde_json::Value, Refusal> {
        let id = self.identity.device_id;
        match action {
            CredentialAction::Status => {
                let runtime = self.host.lock().credential_fingerprint();
                let snapshot = credential_snapshot(&self.db, id, runtime)
                    .map_err(|error| Refusal::new(error.code(), error.to_string()))?;
                encode(&snapshot)
            }
            CredentialAction::Repair {
                expected_fingerprint,
            } => {
                let report = repair_native_identity(
                    &self.db,
                    id,
                    expected_fingerprint,
                    super::now_ms() / 1000,
                )
                .map_err(|error| Refusal::new(error.code(), error.to_string()))?;
                encode(&report)
            }
            CredentialAction::Cleanup => {
                let report = cleanup_native_identity(&self.db)
                    .map_err(|error| Refusal::new(error.code(), error.to_string()))?;
                encode(&report)
            }
        }
    }
}

fn encode(value: &impl serde::Serialize) -> Result<serde_json::Value, Refusal> {
    serde_json::to_value(value)
        .map_err(|error| Refusal::new(synra_protocol::ErrorCode::Internal, error.to_string()))
}
