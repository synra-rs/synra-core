use crate::peer::LocalPeer;
use crate::peer::authenticated::{AuthenticatedPeer, SecurePeerError};
use parking_lot::Mutex;
use std::sync::Arc;
use synra_net::authentication::DeviceCredentials;
use synra_protocol::DeviceId;
use synra_store::SynraDb;

/// Shared native credential namespace used by both production hosts.
pub const DEVICE_IDENTITY_SERVICE: &str = "synra/device-identity";

/// Why persistent authenticated networking could not be initialized.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetworkStartupError {
    /// No native persistent credential backend has been implemented for this platform.
    #[error("persistent device credentials are unavailable on this platform")]
    UnsupportedPlatform,
    /// A persistent identity cannot be recorded in an in-memory database.
    #[error("device networking requires a persistent database")]
    EphemeralDatabase,
    /// Local enrollment or key recovery failed; startup must not replace the identity.
    #[error(transparent)]
    Credential(#[from] super::CredentialError),
    /// Local metadata does not match the enrolled identity.
    #[error(transparent)]
    Profile(#[from] SecurePeerError),
}

/// Loads the persistent native device identity, enrolling only a previously unpaired new identity.
///
/// Secret backend IO and cryptographic validation run outside database guards. Call from the host's
/// blocking startup boundary. Failure disables networking while local application work can continue.
/// # Errors
/// Refuses ephemeral storage, unsupported platforms, lost keys, incompatible enrollments and invalid profiles.
pub fn initialize_native_network(
    db: Arc<Mutex<SynraDb>>,
    profile: LocalPeer,
    now_seconds: u64,
) -> Result<AuthenticatedPeer, NetworkStartupError> {
    if !db.lock().is_file_backed() {
        return Err(NetworkStartupError::EphemeralDatabase);
    }
    let credentials = native_credentials(&db, profile.device_id, now_seconds)?;
    AuthenticatedPeer::new(db, Arc::new(credentials), profile).map_err(NetworkStartupError::from)
}

#[cfg(windows)]
fn native_credentials(
    db: &Mutex<SynraDb>,
    device: DeviceId,
    now_seconds: u64,
) -> Result<DeviceCredentials, NetworkStartupError> {
    let backend = synra_store::secrets::WindowsCredentialBackend::new(DEVICE_IDENTITY_SERVICE)
        .map_err(super::CredentialError::Secret)?;
    super::enroll(db, &backend, device, now_seconds).map_err(NetworkStartupError::from)
}

#[cfg(not(windows))]
fn native_credentials(
    _db: &Mutex<SynraDb>,
    _device: DeviceId,
    _now_seconds: u64,
) -> Result<DeviceCredentials, NetworkStartupError> {
    Err(NetworkStartupError::UnsupportedPlatform)
}
