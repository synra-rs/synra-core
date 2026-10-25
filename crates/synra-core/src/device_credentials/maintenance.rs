//! Complete public maintenance reports shared by local hosts.

use super::{CredentialError, NetworkStartupError};
use parking_lot::Mutex;
use synra_protocol::credentials::{
    CredentialCleanupReport, CredentialEnrollment, CredentialRepairReport, CredentialSnapshot,
};
use synra_protocol::{DeviceId, ErrorCode};
use synra_store::SynraDb;

/// Reads public enrollment and compares it with a captured runtime certificate.
/// # Errors
/// Refuses changed identities and unreadable or oversized state; never probes the private backend.
pub fn credential_snapshot(
    db: &Mutex<SynraDb>,
    device: DeviceId,
    runtime_fingerprint: Option<[u8; 32]>,
) -> Result<CredentialSnapshot, CredentialError> {
    let state = db
        .lock()
        .device_credential_state()
        .map_err(|error| database(&error))?
        .ok_or(CredentialError::IdentityChanged)?;
    if state.device_id != device.to_string()
        || state
            .enrollment
            .as_ref()
            .is_some_and(|record| record.device_id() != device.to_string())
    {
        return Err(CredentialError::IdentityChanged);
    }
    let marker = state.enrollment;
    let runtime = runtime_fingerprint.map(|value| {
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    let enrollment = marker.map(|record| CredentialEnrollment {
        fingerprint: super::repair_fingerprint(record.certificate()),
        backend: record.backend().to_owned(),
        ready: record.ready(),
    });
    let runtime_ready = enrollment
        .as_ref()
        .is_some_and(|record| record.ready && runtime.as_ref() == Some(&record.fingerprint));
    let restart_required = enrollment.as_ref().is_some_and(|record| record.ready) && !runtime_ready;
    Ok(CredentialSnapshot {
        device_id: device,
        enrollment,
        retired_keys: state.retired_keys,
        runtime_ready,
        restart_required,
    })
}

/// Runs explicit native repair and reports enrollment success separately from cleanup.
/// # Errors
/// Refuses stale confirmation, unavailable native backends and unsuccessful replacement.
pub fn repair_native_identity(
    db: &Mutex<SynraDb>,
    device: DeviceId,
    expected_fingerprint: &str,
    now_seconds: u64,
) -> Result<CredentialRepairReport, NetworkStartupError> {
    let repaired = super::repair_native_credentials(db, device, expected_fingerprint, now_seconds)?;
    let cleanup = cleanup_report(repaired.cleanup);
    Ok(CredentialRepairReport {
        device_id: device,
        fingerprint: super::repair_fingerprint(
            repaired.credentials.public_identity().certificate_der(),
        ),
        restart_required: true,
        cleanup,
    })
}

/// Retries native cleanup without changing current enrollment or grants.
/// # Errors
/// Reports native backend or persistence failures.
pub fn cleanup_native_identity(
    db: &Mutex<SynraDb>,
) -> Result<CredentialCleanupReport, NetworkStartupError> {
    let remaining = super::cleanup_native_credentials(db)?;
    Ok(CredentialCleanupReport {
        remaining: Some(count(remaining)?),
        error_code: None,
        detail: None,
    })
}

fn cleanup_report(result: Result<usize, CredentialError>) -> CredentialCleanupReport {
    match result.and_then(count) {
        Ok(remaining) => CredentialCleanupReport {
            remaining: Some(remaining),
            error_code: None,
            detail: None,
        },
        Err(error) => CredentialCleanupReport {
            remaining: None,
            error_code: Some(error.code()),
            detail: Some(error.to_string()),
        },
    }
}

fn count(value: usize) -> Result<u32, CredentialError> {
    u32::try_from(value)
        .map_err(|_| CredentialError::Database("credential cleanup count overflow".to_owned()))
}

fn database(error: &synra_store::DbError) -> CredentialError {
    CredentialError::Database(error.to_string())
}

impl CredentialError {
    /// Shared host-facing error classification for identity maintenance.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Database(_) | Self::Secret(_) => ErrorCode::Internal,
            Self::EphemeralBackend
            | Self::EnrollmentRefused
            | Self::RepairRefused
            | Self::OperationBusy => ErrorCode::InvalidArgument,
            _ => ErrorCode::NotPaired,
        }
    }
}

impl NetworkStartupError {
    /// Shared host-facing error classification for native identity operations.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedPlatform => ErrorCode::Unsupported,
            Self::EphemeralDatabase | Self::Profile(_) => ErrorCode::InvalidArgument,
            Self::Credential(error) => error.code(),
        }
    }
}
