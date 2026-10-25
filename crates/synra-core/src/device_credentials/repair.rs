//! An explicit key replacement revokes old authority before any external secret IO.

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use synra_net::authentication::DeviceCredentials;
use synra_protocol::DeviceId;
use synra_store::SynraDb;
use synra_store::secrets::{SecretBackend, SecretBytes, SecretError, SecretKey};

use super::CredentialError;

/// A committed new identity key and the separate result of old-secret cleanup.
pub struct CredentialRepair {
    /// Validated replacement; no previous peer grant survives this repair.
    pub credentials: DeviceCredentials,
    /// Number of retained slots on success, or a cleanup failure after successful enrollment.
    pub cleanup: Result<usize, CredentialError>,
}

/// Fingerprint displayed for explicit repair, even when an old certificate is corrupt or expired.
#[must_use]
pub fn repair_fingerprint(certificate: &[u8]) -> String {
    let digest = Sha256::digest(certificate);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Replaces only the enrollment whose public fingerprint the caller explicitly confirmed.
///
/// The stable device id is retained, but the certificate, all peer grants and pending pairings
/// are replaced atomically. A write failure leaves the new enrollment unready and the old grants
/// revoked; ordinary load may recover only this same replacement if its secret was written.
/// # Errors
/// Refuses stale confirmation, unsuitable storage, concurrent changes and failed persistence.
pub fn repair(
    db: &Mutex<SynraDb>,
    secrets: &dyn SecretBackend,
    device_id: DeviceId,
    expected_fingerprint: &str,
    now_seconds: u64,
) -> Result<CredentialRepair, CredentialError> {
    super::persistent(secrets)?;
    let operation = super::operation::acquire(db)?;
    let state = db
        .lock()
        .device_credential_state()
        .map_err(|error| database(&error))?
        .ok_or(CredentialError::IdentityChanged)?;
    if state.device_id != device_id.to_string() {
        return Err(CredentialError::IdentityChanged);
    }
    let expected =
        state
            .enrollment
            .or(state.recovery_enrollment)
            .ok_or(if state.lineage_present {
                CredentialError::NotEnrolled
            } else {
                CredentialError::MissingRegistration
            })?;
    if expected.device_id() != device_id.to_string() {
        return Err(CredentialError::IdentityChanged);
    }
    if expected_fingerprint != repair_fingerprint(expected.certificate()) {
        return Err(CredentialError::RepairRefused);
    }
    let candidate = DeviceCredentials::generate(device_id, now_seconds)
        .map_err(|error| CredentialError::InvalidCredential(error.to_string()))?;
    let claimed = db
        .lock()
        .replace_device_credential(
            &expected,
            candidate.public_identity().certificate_der(),
            secrets.kind().as_str(),
        )
        .map_err(|error| database(&error))?;
    if !claimed {
        return Err(CredentialError::RepairRefused);
    }
    let key = SecretKey::device_identity(*candidate.public_identity().fingerprint());
    secrets
        .set(
            &key,
            &SecretBytes::new(candidate.private_key_der().to_vec()),
        )
        .map_err(CredentialError::Secret)?;
    let credentials = super::load(db, secrets, device_id, now_seconds)?;
    if credentials.public_identity() != candidate.public_identity() {
        return Err(CredentialError::IdentityChanged);
    }
    let cleanup = cleanup_locked(db, secrets);
    drop(operation);
    Ok(CredentialRepair {
        credentials,
        cleanup,
    })
}

/// Retries old-slot deletion without changing current enrollment or authorizations.
///
/// Unavailable backend kinds remain queued. No DB guard spans backend IO; interrupted deletion is
/// retried idempotently because the queue acknowledgment is persisted only afterwards.
/// # Errors
/// Returns a cleanup failure without undoing an already committed repair.
pub fn cleanup_retired(
    db: &Mutex<SynraDb>,
    secrets: &dyn SecretBackend,
) -> Result<usize, CredentialError> {
    super::persistent(secrets)?;
    let operation = super::operation::acquire(db)?;
    let result = cleanup_locked(db, secrets);
    drop(operation);
    result
}

fn cleanup_locked(
    db: &Mutex<SynraDb>,
    secrets: &dyn SecretBackend,
) -> Result<usize, CredentialError> {
    let retired = db
        .lock()
        .retired_device_credentials()
        .map_err(|error| database(&error))?;
    for record in retired {
        if record.backend != secrets.kind().as_str() {
            continue;
        }
        let eligible = db
            .lock()
            .device_credential_retired(&record)
            .map_err(|error| database(&error))?;
        if !eligible {
            continue;
        }
        // Hash raw public bytes so expired or corrupt certificates can still have their old slot retired.
        let fingerprint = Sha256::digest(&record.certificate).into();
        match secrets.delete(&SecretKey::device_identity(fingerprint)) {
            Ok(()) | Err(SecretError::NotFound { .. }) => {}
            Err(error) => return Err(CredentialError::Secret(error)),
        }
        match secrets.get(&SecretKey::device_identity(fingerprint)) {
            Ok(None) | Err(SecretError::NotFound { .. }) => {}
            Ok(Some(_)) => {
                return Err(CredentialError::Secret(SecretError::Backend(
                    "retired key deletion was not persisted".to_owned(),
                )));
            }
            Err(error) => return Err(CredentialError::Secret(error)),
        }
        db.lock()
            .finish_retired_device_credential(&record)
            .map_err(|error| database(&error))?;
    }
    Ok(db
        .lock()
        .retired_device_credentials()
        .map_err(|error| database(&error))?
        .len())
}

fn database(error: &synra_store::DbError) -> CredentialError {
    CredentialError::Database(error.to_string())
}
