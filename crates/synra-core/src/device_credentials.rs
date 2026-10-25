//! Shared local credential enrollment and restart recovery.
//!
//! SQLite stores only the public certificate and enrollment state. Private keys belong to a persistent
//! secret backend, under a separate slot for each certificate. A durable claim precedes external writes,
//! so a competing enrollment cannot replace the winning key. Backend IO never holds the database lock.
//! Loading never generates keys: missing or invalid credentials require explicit identity repair.

use parking_lot::Mutex;
use synra_net::authentication::{DeviceCredentials, PeerIdentity};
use synra_protocol::DeviceId;
use synra_store::SynraDb;
use synra_store::secrets::{SecretBackend, SecretBytes, SecretError, SecretKey, SecretStrength};
use synra_store::sqlite::DeviceCredentialRecord;

mod network;
pub use network::{DEVICE_IDENTITY_SERVICE, NetworkStartupError, initialize_native_network};

/// Why a local credential cannot be enrolled or loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// No enrollment exists; loading never creates one implicitly.
    #[error("device credentials are not enrolled")]
    NotEnrolled,
    /// A new key cannot be attached to an absent, changed or already paired local identity.
    #[error("device credential enrollment was refused")]
    EnrollmentRefused,
    /// The local identity or enrollment changed while external IO was in progress.
    #[error("device identity or credential enrollment changed")]
    IdentityChanged,
    /// A persistent backend is required; in-memory storage cannot establish durable identity.
    #[error("a persistent secret backend is required for device credentials")]
    EphemeralBackend,
    /// Loading cannot silently move a key to a different backend.
    #[error("the device credential secret backend changed")]
    BackendChanged,
    /// An enrollment has no private key; automatic key replacement is forbidden.
    #[error("device private key is missing; explicit identity repair is required")]
    MissingKey,
    /// Stored credentials failed certificate, device id or private-key validation.
    #[error("invalid stored device credential: {0}")]
    InvalidCredential(String),
    /// The public enrollment marker could not be read or committed.
    #[error("device credential database failed: {0}")]
    Database(String),
    /// The protected secret store refused an operation.
    #[error("device credential secret store failed: {0}")]
    Secret(SecretError),
}

/// Explicitly enrolls a local identity, or recovers its already recorded enrollment.
///
/// The identity must already exist, with no previous pairing when a new enrollment is claimed.
/// Private-key write failure leaves a durable incomplete marker. A later [`load`] can finish only
/// when the same key was actually written; it never creates a replacement to hide credential loss.
///
/// # Errors
/// Returns an error for unsuitable backends, identity races, failed persistence or invalid credentials.
pub fn enroll(
    db: &Mutex<SynraDb>,
    secrets: &dyn SecretBackend,
    device_id: DeviceId,
    now_seconds: u64,
) -> Result<DeviceCredentials, CredentialError> {
    persistent(secrets)?;
    if marker(db, device_id)?.is_some() {
        return load(db, secrets, device_id, now_seconds);
    }
    let candidate = DeviceCredentials::generate(device_id, now_seconds)
        .map_err(|error| CredentialError::InvalidCredential(error.to_string()))?;
    let peer = candidate.public_identity();
    let claimed = db
        .lock()
        .claim_device_credential(
            &device_id.to_string(),
            peer.certificate_der(),
            secrets.kind().as_str(),
        )
        .map_err(|error| CredentialError::Database(error.to_string()))?;
    if !claimed {
        return if marker(db, device_id)?.is_some() {
            load(db, secrets, device_id, now_seconds)
        } else {
            Err(CredentialError::EnrollmentRefused)
        };
    }
    let key = SecretKey::device_identity(*peer.fingerprint());
    let value = SecretBytes::new(candidate.private_key_der().to_vec());
    secrets.set(&key, &value).map_err(CredentialError::Secret)?;
    // Read back through the actual backend, validate, and commit the same marker. A backend that
    // loses or corrupts the write cannot make the enrollment ready.
    load(db, secrets, device_id, now_seconds)
}

/// Loads enrolled credentials, completing a previously interrupted successful secret write if needed.
///
/// No database mutex is held during secret backend calls or cryptographic validation. The final
/// commit rechecks the local id and public enrollment after that external work.
///
/// # Errors
/// Returns an error for absent, lost, corrupt or changed credentials; never generates a new identity.
pub fn load(
    db: &Mutex<SynraDb>,
    secrets: &dyn SecretBackend,
    device_id: DeviceId,
    now_seconds: u64,
) -> Result<DeviceCredentials, CredentialError> {
    persistent(secrets)?;
    let record = marker(db, device_id)?.ok_or(CredentialError::NotEnrolled)?;
    if record.backend() != secrets.kind().as_str() {
        return Err(CredentialError::BackendChanged);
    }
    let peer = PeerIdentity::from_certificate(device_id, record.certificate(), now_seconds)
        .map_err(|error| CredentialError::InvalidCredential(error.to_string()))?;
    let key = SecretKey::device_identity(*peer.fingerprint());
    let private_key = match secrets.get(&key) {
        Ok(Some(value)) => value,
        Ok(None) | Err(SecretError::NotFound { .. }) => return Err(CredentialError::MissingKey),
        Err(error) => return Err(CredentialError::Secret(error)),
    };
    let credentials = DeviceCredentials::restore(
        device_id,
        record.certificate(),
        private_key.expose(),
        now_seconds,
    )
    .map_err(|error| CredentialError::InvalidCredential(error.to_string()))?;
    let committed = db
        .lock()
        .finish_device_credential(&record)
        .map_err(|error| CredentialError::Database(error.to_string()))?;
    if !committed {
        return Err(CredentialError::IdentityChanged);
    }
    Ok(credentials)
}

fn persistent(secrets: &dyn SecretBackend) -> Result<(), CredentialError> {
    if matches!(
        secrets.kind().strength(),
        SecretStrength::OperatingSystem | SecretStrength::AtRestOnly
    ) {
        Ok(())
    } else {
        Err(CredentialError::EphemeralBackend)
    }
}

fn marker(
    db: &Mutex<SynraDb>,
    device_id: DeviceId,
) -> Result<Option<DeviceCredentialRecord>, CredentialError> {
    let db = db.lock();
    let identity = db
        .identity()
        .map_err(|error| CredentialError::Database(error.to_string()))?;
    if identity
        .as_ref()
        .is_none_or(|identity| identity.device_id != device_id.to_string())
    {
        return Err(CredentialError::IdentityChanged);
    }
    let record = db
        .device_credential()
        .map_err(|error| CredentialError::Database(error.to_string()))?;
    drop(db);
    if record
        .as_ref()
        .is_some_and(|record| record.device_id() != device_id.to_string())
    {
        return Err(CredentialError::IdentityChanged);
    }
    Ok(record)
}

#[cfg(test)]
mod tests;
