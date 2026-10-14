//! The trait a backend implements, the memory backend, and how one is chosen.

use super::bytes::{SecretBytes, SecretError};
use super::kind::{SecretBackendKind, SecretKey};

/// The largest secret that may be stored.
///
/// Keychains have their own limits and they differ; this is well below all of them and far above any token. A
/// larger value is a file, and calling it a secret would put it somewhere with a size limit that fails at an
/// unpredictable moment.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Where secrets are kept.
///
/// Synchronous, unlike the design document's sketch. Every backend here is a local call — a keychain read, a
/// file read — and an `async` trait would make the caller's every use of a secret await something that never
/// actually yields. The application layer can wrap it if a backend ever needs to be asynchronous.
pub trait SecretBackend: Send + Sync {
    /// Reads a value.
    ///
    /// # Errors
    ///
    /// [`SecretError::NotFound`] when nothing is stored under the key, and any backend failure.
    fn get(&self, key: &SecretKey) -> Result<Option<SecretBytes>, SecretError>;

    /// Writes a value, replacing any existing one.
    ///
    /// # Errors
    ///
    /// [`SecretError::TooLarge`] or any backend failure.
    fn set(&self, key: &SecretKey, value: &SecretBytes) -> Result<(), SecretError>;

    /// Removes a value.
    ///
    /// Removing something that is not there is not an error: the caller wanted it gone, and it is gone.
    ///
    /// # Errors
    ///
    /// Any backend failure other than a missing entry.
    fn delete(&self, key: &SecretKey) -> Result<(), SecretError>;

    /// Which backend this is.
    fn kind(&self) -> SecretBackendKind;

    /// Whether a value is stored under the key.
    ///
    /// A provided method, because the backend's own read is what can answer it and a caller should not have to
    /// interpret a `NotFound` to find out.
    ///
    /// # Errors
    ///
    /// Any failure other than a missing entry.
    fn contains(&self, key: &SecretKey) -> Result<bool, SecretError> {
        Ok(self.get(key)?.is_some())
    }
}

/// An in-memory backend.
///
/// For tests, and for a session where the user chose not to save anything. It forgets everything at exit, which
/// [`SecretBackendKind::Memory`] reports as [`SecretStrength::None`] so the interface can say so.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    values: parking_lot::RwLock<std::collections::HashMap<String, SecretBytes>>,
}

impl MemoryBackend {
    /// An empty backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many values are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.read().len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.read().is_empty()
    }
}

impl SecretBackend for MemoryBackend {
    fn get(&self, key: &SecretKey) -> Result<Option<SecretBytes>, SecretError> {
        Ok(self.values.read().get(&key.account()).cloned())
    }

    fn set(&self, key: &SecretKey, value: &SecretBytes) -> Result<(), SecretError> {
        check_size(value)?;
        self.values.write().insert(key.account(), value.clone());
        Ok(())
    }

    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        self.values.write().remove(&key.account());
        Ok(())
    }

    fn kind(&self) -> SecretBackendKind {
        SecretBackendKind::Memory
    }
}

/// Rejects a value the store will not accept.
const fn check_size(value: &SecretBytes) -> Result<(), SecretError> {
    if value.len() > MAX_SECRET_BYTES {
        return Err(SecretError::TooLarge { len: value.len(), max: MAX_SECRET_BYTES });
    }
    Ok(())
}

/// Chooses a backend, preferring the operating system's.
///
/// # Errors
///
/// [`SecretError::NoBackend`] if the caller supplies nothing to choose from. The fallback is the *caller's* to
/// supply, because only the application layer knows where the data directory is and whether a file backend is
/// acceptable for this installation.
pub fn choose_backend(
    candidates: Vec<Box<dyn SecretBackend>>,
) -> Result<Box<dyn SecretBackend>, SecretError> {
    let mut best: Option<Box<dyn SecretBackend>> = None;
    for candidate in candidates {
        let better = best
            .as_ref()
            .is_none_or(|current| candidate.kind().strength() > current.kind().strength());
        if better {
            best = Some(candidate);
        }
    }
    best.ok_or(SecretError::NoBackend)
}
