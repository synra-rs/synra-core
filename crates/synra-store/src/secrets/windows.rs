//! Explicit Windows Credential Manager access, with no process-global keyring builder fallback.

use keyring::windows::WinCredential;

use super::{SecretBackend, SecretBackendKind, SecretBytes, SecretError, SecretKey};

/// Windows' native generic credential blob limit (5 * 512 bytes).
pub const MAX_WINDOWS_SECRET_BYTES: usize = 2560;

// keyring documents that native Windows operations must be serialized for each credential. Share
// this lock across backend objects, not just methods on one object. Credential enrollment additionally
// uses a durable DB claim and a distinct slot per certificate, preventing competing key overwrites.
static NATIVE_ACCESS: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Persistent secrets in the current Windows user's Credential Manager.
///
/// The service namespace must be stable and dedicated to this installation. This type always builds
/// native credentials directly; changing keyring's global builder to a mock cannot weaken it.
pub struct WindowsCredentialBackend {
    service: String,
}

impl WindowsCredentialBackend {
    /// Selects a nonempty service namespace of at most 128 ASCII bytes.
    ///
    /// # Errors
    /// Rejects empty, excessive or control-containing namespaces before accessing the operating system.
    pub fn new(service: &str) -> Result<Self, SecretError> {
        if service.is_empty()
            || service.len() > 128
            || !service.is_ascii()
            || service.chars().any(char::is_control)
        {
            return Err(SecretError::Backend(
                "invalid credential service namespace".to_owned(),
            ));
        }
        Ok(Self {
            service: service.to_owned(),
        })
    }

    fn entry(&self, key: &SecretKey) -> Result<keyring::Entry, SecretError> {
        let credential = WinCredential::new_with_target(None, &self.service, &key.account())
            .map_err(|error| native_error(&error))?;
        Ok(keyring::Entry::new_with_credential(Box::new(credential)))
    }
}

impl SecretBackend for WindowsCredentialBackend {
    fn get(&self, key: &SecretKey) -> Result<Option<SecretBytes>, SecretError> {
        let access = NATIVE_ACCESS.lock();
        let result = self.entry(key)?.get_secret();
        drop(access);
        match result {
            Ok(bytes) => Ok(Some(SecretBytes::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(native_error(&error)),
        }
    }

    fn set(&self, key: &SecretKey, value: &SecretBytes) -> Result<(), SecretError> {
        if value.len() > MAX_WINDOWS_SECRET_BYTES {
            return Err(SecretError::TooLarge {
                len: value.len(),
                max: MAX_WINDOWS_SECRET_BYTES,
            });
        }
        let access = NATIVE_ACCESS.lock();
        let result = self.entry(key)?.set_secret(value.expose());
        drop(access);
        result.map_err(|error| native_error(&error))
    }

    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        let access = NATIVE_ACCESS.lock();
        let result = self.entry(key)?.delete_credential();
        drop(access);
        match result {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(native_error(&error)),
        }
    }

    fn kind(&self) -> SecretBackendKind {
        SecretBackendKind::WindowsCredential
    }
}

fn native_error(error: &keyring::Error) -> SecretError {
    // Library errors can hold secret bytes (BadEncoding) or third-party errors. Never format them.
    match error {
        keyring::Error::NoEntry => SecretError::Backend("native credential is missing".to_owned()),
        keyring::Error::BadEncoding(_) => {
            SecretError::Corrupt("invalid native credential encoding".to_owned())
        }
        keyring::Error::NoStorageAccess(_) => {
            SecretError::Backend("native credential access denied".to_owned())
        }
        keyring::Error::Ambiguous(_) => {
            SecretError::Backend("ambiguous native credential".to_owned())
        }
        _ => SecretError::Backend("native credential operation failed".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_credentials_survive_backend_recreation_and_delete_idempotently() {
        let service = format!("synra-test-{}", synra_protocol::DeviceId::new());
        let key = SecretKey::device_identity([23; 32]);
        let first = WindowsCredentialBackend::new(&service).expect("backend");
        let secret = SecretBytes::new(vec![0, 1, 255, 0, 42]);
        assert_eq!(first.get(&key).expect("read"), None);
        first.set(&key, &secret).expect("native write");
        let second = WindowsCredentialBackend::new(&service).expect("reopen");
        let restored = second.get(&key);
        let cleanup = second.delete(&key);
        cleanup.expect("delete");
        assert_eq!(restored.expect("restore"), Some(secret));
        second.delete(&key).expect("delete missing");
        assert_eq!(second.get(&key).expect("missing"), None);
    }

    #[test]
    fn oversized_secrets_are_rejected_before_native_storage() {
        let backend = WindowsCredentialBackend::new("synra-test-size").expect("backend");
        let error = backend.set(
            &SecretKey::device_identity([0; 32]),
            &SecretBytes::new(vec![0; MAX_WINDOWS_SECRET_BYTES + 1]),
        );
        assert!(matches!(error, Err(SecretError::TooLarge { .. })));
    }

    #[test]
    fn invalid_namespaces_and_error_payloads_do_not_leak_secrets() {
        for service in ["", "bad\nname", &"x".repeat(129)] {
            assert!(WindowsCredentialBackend::new(service).is_err());
        }
        let error = native_error(&keyring::Error::BadEncoding(b"secret marker".to_vec()));
        assert!(!format!("{error:?} {error}").contains("secret marker"));
    }
}
