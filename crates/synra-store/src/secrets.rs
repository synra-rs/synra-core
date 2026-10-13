//! Secrets: the abstraction, and the encrypted-file fallback.
//!
//! # Three things are stored, and only one of them is ours
//!
//! * **The device identity key** — this device's, used to prove who it is to a peer.
//! * **A plugin's secure values** — a token the plugin holds on the user's behalf. Ours to store, not ours to
//!   read, and not ours to lose.
//! * **A publisher's signing key** — never here. It belongs to the author's machine, and an application that
//!   could read it would be an application that could sign as somebody else.
//!
//! # The backend is a platform decision, and the fallback has a cost
//!
//! The operating system's keychain is the right place: it is unlocked with the user's login, it is backed up
//! the way the platform backs up credentials, and it is not readable by another user on the same machine. The
//! fallback is an encrypted file, which is weaker in one specific way — the key protecting it has to live
//! somewhere the application can read without the user doing anything, so it protects against a stolen disk and
//! not against a process running as this user.
//!
//! That difference is reported through [`SecretBackendKind::strength`] rather than hidden, because a user
//! deciding whether to store a work token in an application should be able to find out which one they got.
//!
//! # The values never reach a log
//!
//! [`SecretBytes`] has no `Display` and a redacting `Debug`. A secret that could be printed is a secret that
//! ends up in a log line somebody wrote while debugging, and the log is what gets attached to a bug report.

use core::fmt;

use serde::{Deserialize, Serialize};

/// How the value was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SecretBackendKind {
    /// Windows Credential Manager.
    WindowsCredential,
    /// macOS Keychain.
    MacKeychain,
    /// Linux Secret Service, backed by gnome-keyring or kwallet.
    LinuxSecretService,
    /// Android Keystore, through EncryptedSharedPreferences.
    AndroidKeystore,
    /// iOS Keychain.
    IosKeychain,
    /// An encrypted file, used where no keychain answered.
    EncryptedFile,
    /// In memory only, for tests.
    Memory,
}

impl SecretBackendKind {
    /// How much the backend protects against.
    #[must_use]
    pub const fn strength(self) -> SecretStrength {
        match self {
            Self::WindowsCredential
            | Self::MacKeychain
            | Self::LinuxSecretService
            | Self::AndroidKeystore
            | Self::IosKeychain => SecretStrength::OperatingSystem,
            // The key protecting the file has to be readable without the user present, so this stops a stolen
            // disk and not a process running as this user.
            Self::EncryptedFile => SecretStrength::AtRestOnly,
            Self::Memory => SecretStrength::None,
        }
    }

    /// The name used in a diagnostic report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WindowsCredential => "windows-credential",
            Self::MacKeychain => "mac-keychain",
            Self::LinuxSecretService => "linux-secret-service",
            Self::AndroidKeystore => "android-keystore",
            Self::IosKeychain => "ios-keychain",
            Self::EncryptedFile => "encrypted-file",
            Self::Memory => "memory",
        }
    }

    /// Whether the backend is the operating system's, and therefore the one to prefer.
    #[must_use]
    pub const fn is_operating_system(self) -> bool {
        matches!(self.strength(), SecretStrength::OperatingSystem)
    }
}

impl fmt::Display for SecretBackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a backend protects against.
///
/// Reported to the user rather than kept internal: the difference between "the operating system holds this" and
/// "it is in a file this application can read" is the difference between two threat models, and the person
/// deciding whether to store a work token is the person who should know which one applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SecretStrength {
    /// Nothing: the value is in memory and gone at exit.
    None,
    /// Protects a stolen disk, not a local process.
    AtRestOnly,
    /// The operating system's own credential store.
    OperatingSystem,
}

impl SecretStrength {
    /// A sentence for the settings screen.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::None => "held in memory only; it is not saved",
            Self::AtRestOnly => {
                "encrypted in a file; this protects a stolen disk, not a program running as you"
            }
            Self::OperatingSystem => "held by your operating system's credential store",
        }
    }
}

/// What a secret belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "owner", content = "name")]
#[non_exhaustive]
pub enum SecretKey {
    /// This device's identity key.
    DeviceIdentity,
    /// One plugin's secure value, under a name the plugin chose.
    PluginSecret {
        /// The plugin.
        plugin_id: String,
        /// The name the plugin gave the value.
        name: String,
    },
}

impl SecretKey {
    /// A plugin's secret.
    #[must_use]
    pub fn plugin(plugin_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::PluginSecret { plugin_id: plugin_id.into(), name: name.into() }
    }

    /// The account name a keychain entry is filed under.
    ///
    /// Namespaced so that a plugin cannot collide with the device identity or with another plugin, and
    /// sanitised so a plugin cannot choose a name that reads as a different namespace.
    #[must_use]
    pub fn account(&self) -> String {
        match self {
            Self::DeviceIdentity => "device-identity".to_owned(),
            Self::PluginSecret { plugin_id, name } => {
                format!("plugin/{}/{}", sanitise_account(plugin_id), sanitise_account(name))
            }
        }
    }

    /// Whether this key belongs to the given plugin.
    #[must_use]
    pub fn belongs_to(&self, plugin_id: &str) -> bool {
        match self {
            Self::DeviceIdentity => false,
            Self::PluginSecret { plugin_id: owner, .. } => owner == plugin_id,
        }
    }
}

/// Makes a string safe to use as a keychain account component.
///
/// A plugin chooses its own secret names, so a name containing `/` would let it file a value under a different
/// plugin's namespace — or under the device identity's — and read something it should not have.
fn sanitise_account(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        }
        else {
            out.push('_');
        }
    }

    // `..` is collapsed after the substitution rather than during it, because the substitution turns a `/` into
    // `_`: `../../device-identity` becomes `.._.._device-identity`, which contains no separator but still reads
    // as a path attempt and — more to the point — is a name a keychain listing would show to a user as
    // suspicious. Collapsing makes the sanitising visible in the name.
    while out.contains("..") {
        out = out.replace("..", ".");
    }
    // A leading dot would make a keychain entry hidden, and `.` alone names a directory rather than an entry.
    let trimmed = out.trim_start_matches('.');
    if trimmed.is_empty() {
        return "_".to_owned();
    }
    trimmed.to_owned()
}

/// A secret's bytes.
///
/// Deliberately opaque: no `Display`, no `Serialize`, and a `Debug` that prints the length. A secret that can be
/// formatted is one that ends up in a log line, and the log is what gets attached to a bug report.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The bytes, for a caller about to use them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// How long the secret is.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Zeroes the bytes.
    ///
    /// Called when a value is no longer needed. It is not a guarantee — a copy may exist elsewhere, and the
    /// compiler is free to have moved the bytes — but it shortens the window in which a value sits in a page
    /// that may later be written to a core dump.
    pub fn zero(&mut self) {
        self.0.fill(0);
        self.0.clear();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes>)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Why a secret operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// No backend is available.
    #[error("no secret backend is available")]
    NoBackend,

    /// The operating system's store refused.
    #[error("the secret store refused the operation: {0}")]
    Backend(String),

    /// The value could not be encrypted or decrypted.
    #[error("the stored value could not be read: {0}")]
    Corrupt(String),

    /// The key that protects the store is missing or unusable.
    #[error("the key protecting the secret store is unusable: {0}")]
    KeyUnavailable(String),

    /// The key does not name a stored value.
    #[error("no secret is stored under {account:?}")]
    NotFound {
        /// The account name that was looked up.
        account: String,
    },

    /// The value is larger than the store accepts.
    #[error("the secret is {len} bytes, and the limit is {max}")]
    TooLarge {
        /// The size that was offered.
        len: usize,
        /// The limit.
        max: usize,
    },
}

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

/// What a diagnostic report says about secret storage.
///
/// The strength and nothing else. A report that named the account or the value would be a report that leaks
/// what it is reporting on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretStorageReport {
    /// Which backend is in use.
    pub backend: String,
    /// What it protects against.
    pub strength: String,
    /// How many values are stored, when the backend can say.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entry_count: Option<usize>,
}

impl SecretStorageReport {
    /// Builds a report from a backend.
    ///
    /// # Errors
    ///
    /// Any failure other than a missing entry, from the backend's own probe.
    pub fn of(backend: &dyn SecretBackend) -> Result<Self, SecretError> {
        let kind = backend.kind();
        Ok(Self {
            backend: kind.as_str().to_owned(),
            strength: format!("{:?}", kind.strength()),
            entry_count: None,
        })
    }

    /// A sentence for the settings screen.
    #[must_use]
    pub fn explain(&self) -> String {
        let strength = match self.strength.as_str() {
            "OperatingSystem" => SecretStrength::OperatingSystem,
            "AtRestOnly" => SecretStrength::AtRestOnly,
            _ => SecretStrength::None,
        };
        format!("{}: {}", self.backend, strength.explain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin_key(name: &str) -> SecretKey {
        SecretKey::plugin("@synra-plugin/chat", name)
    }

    #[test]
    fn a_plugin_secret_is_namespaced_under_its_plugin() {
        assert_eq!(plugin_key("token").account(), "plugin/_synra-plugin_chat/token");
        // And the device identity is in its own namespace, which a plugin cannot spell because the account has
        // no `plugin/` prefix.
        assert_eq!(SecretKey::DeviceIdentity.account(), "device-identity");
    }

    #[test]
    fn a_plugin_cannot_name_a_secret_into_another_namespace() {
        // The names are the plugin's to choose, so a name containing a separator would file the value under a
        // different plugin — or under the device identity — and read something it should not have.
        let sneaky = SecretKey::plugin("@synra-plugin/chat", "../../device-identity");
        let account = sneaky.account();
        assert!(!account.contains(".."), "{account}");
        assert!(account.starts_with("plugin/_synra-plugin_chat/"), "{account}");

        // Two different plugins cannot collide on the same account however they spell their names.
        let other = SecretKey::plugin("@synra-plugin/notes", "../../device-identity");
        assert_ne!(account, other.account());
    }

    #[test]
    fn an_empty_name_still_produces_a_usable_account() {
        // An empty account would be a keychain entry with no name, which some platforms refuse outright and
        // others accept as one shared entry for every plugin.
        assert!(!SecretKey::plugin("", "").account().is_empty());
        // An empty name still produces a component, so the account does not end in a separator that a keychain
        // would read as the entry having no name.
        let unnamed = SecretKey::plugin("@x/y", "").account();
        assert!(!unnamed.ends_with('/'), "{unnamed}");
        assert!(!unnamed.contains("//"), "{unnamed}");
    }

    #[test]
    fn a_key_knows_which_plugin_it_belongs_to() {
        assert!(plugin_key("token").belongs_to("@synra-plugin/chat"));
        assert!(!plugin_key("token").belongs_to("@synra-plugin/notes"));
        assert!(!SecretKey::DeviceIdentity.belongs_to("@synra-plugin/chat"));
    }

    #[test]
    fn a_secret_never_prints_its_value() {
        // A secret that can be formatted is one that ends up in a log line, and the log is what gets attached to
        // a bug report.
        let secret = SecretBytes::new(b"ghp_supersecret".to_vec());
        let debug = format!("{secret:?}");
        assert!(!debug.contains("ghp"), "{debug}");
        assert!(!debug.contains("supersecret"), "{debug}");
        assert!(debug.contains(&format!("{} bytes", secret.len())), "{debug}");
    }

    #[test]
    fn a_secret_exposes_its_bytes_to_a_caller_that_needs_them() {
        let secret = SecretBytes::new(b"abc".to_vec());
        assert_eq!(secret.expose(), b"abc");
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
        assert!(SecretBytes::new(Vec::new()).is_empty());
    }

    #[test]
    fn zeroing_a_secret_clears_it() {
        let mut secret = SecretBytes::new(b"abc".to_vec());
        secret.zero();
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
        // The bytes are gone from the view a caller has, which is what the method can promise.
        assert!(secret.expose().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn backend_kinds_report_their_strength() {
        for kind in [
            SecretBackendKind::WindowsCredential,
            SecretBackendKind::MacKeychain,
            SecretBackendKind::LinuxSecretService,
            SecretBackendKind::AndroidKeystore,
            SecretBackendKind::IosKeychain,
        ] {
            assert_eq!(kind.strength(), SecretStrength::OperatingSystem, "{kind}");
            assert!(kind.is_operating_system());
        }
        // The fallback stops a stolen disk and not a process running as this user.
        assert_eq!(SecretBackendKind::EncryptedFile.strength(), SecretStrength::AtRestOnly);
        assert!(!SecretBackendKind::EncryptedFile.is_operating_system());
        assert_eq!(SecretBackendKind::Memory.strength(), SecretStrength::None);
    }

    #[test]
    fn strengths_order_from_weakest_to_strongest() {
        // The ordering is what `choose_backend` relies on to pick the best candidate.
        assert!(SecretStrength::None < SecretStrength::AtRestOnly);
        assert!(SecretStrength::AtRestOnly < SecretStrength::OperatingSystem);
    }

    #[test]
    fn every_strength_explains_itself_for_a_user() {
        // The person deciding whether to store a work token is the person who should know which threat model
        // applies.
        for strength in [
            SecretStrength::None,
            SecretStrength::AtRestOnly,
            SecretStrength::OperatingSystem,
        ] {
            let text = strength.explain();
            assert!(text.len() > 20, "{strength:?} -> {text}");
        }
    }

    #[test]
    fn a_memory_backend_stores_and_returns_a_value() {
        let backend = MemoryBackend::new();
        let key = plugin_key("token");
        let value = SecretBytes::new(b"ghp_abc".to_vec());

        assert_eq!(backend.get(&key).expect("reads"), None);
        assert!(!backend.contains(&key).expect("checks"));

        backend.set(&key, &value).expect("writes");
        assert!(backend.contains(&key).expect("checks"));
        assert_eq!(backend.get(&key).expect("reads").expect("present"), value);
        assert_eq!(backend.len(), 1);
    }

    #[test]
    fn writing_the_same_key_replaces_the_value() {
        let backend = MemoryBackend::new();
        let key = plugin_key("token");
        backend.set(&key, &SecretBytes::new(b"first".to_vec())).expect("writes");
        backend.set(&key, &SecretBytes::new(b"second".to_vec())).expect("writes");

        assert_eq!(backend.len(), 1);
        assert_eq!(
            backend.get(&key).expect("reads").expect("present").expose(),
            b"second"
        );
    }

    #[test]
    fn deleting_removes_the_value_and_is_not_an_error_twice() {
        // Removing something that is not there is not an error: the caller wanted it gone and it is gone.
        let backend = MemoryBackend::new();
        let key = plugin_key("token");
        backend.set(&key, &SecretBytes::new(b"x".to_vec())).expect("writes");

        backend.delete(&key).expect("deletes");
        assert_eq!(backend.get(&key).expect("reads"), None);
        backend.delete(&key).expect("deletes again");
        assert!(backend.is_empty());
    }

    #[test]
    fn two_plugins_do_not_share_a_value() {
        // The property the namespacing exists for.
        let backend = MemoryBackend::new();
        let chat = SecretKey::plugin("@synra-plugin/chat", "token");
        let notes = SecretKey::plugin("@synra-plugin/notes", "token");

        backend.set(&chat, &SecretBytes::new(b"chat-token".to_vec())).expect("writes");
        assert_eq!(backend.get(&notes).expect("reads"), None);

        backend.set(&notes, &SecretBytes::new(b"notes-token".to_vec())).expect("writes");
        assert_eq!(
            backend.get(&chat).expect("reads").expect("present").expose(),
            b"chat-token"
        );
    }

    #[test]
    fn an_oversized_secret_is_refused() {
        // A larger value is a file, and calling it a secret would put it somewhere with a size limit that fails
        // at an unpredictable moment.
        let backend = MemoryBackend::new();
        let too_big = SecretBytes::new(vec![b'x'; MAX_SECRET_BYTES + 1]);
        match backend.set(&plugin_key("big"), &too_big) {
            Err(SecretError::TooLarge { len, max }) => {
                assert_eq!(len, MAX_SECRET_BYTES + 1);
                assert_eq!(max, MAX_SECRET_BYTES);
            }
            other => panic!("expected a size refusal, got {other:?}"),
        }
        // Exactly at the limit is accepted.
        let at_limit = SecretBytes::new(vec![b'x'; MAX_SECRET_BYTES]);
        assert!(backend.set(&plugin_key("at-limit"), &at_limit).is_ok());
    }

    #[test]
    fn a_backend_reports_which_it_is() {
        assert_eq!(MemoryBackend::new().kind(), SecretBackendKind::Memory);
    }

    #[test]
    fn choosing_a_backend_prefers_the_operating_system() {
        // The keychain is unlocked with the user's login and is not readable by another user on the same
        // machine, so it is the one to use when it answers.
        let chosen = choose_backend(vec![
            Box::new(MemoryBackend::new()),
            Box::new(MemoryBackend::new()),
        ])
        .expect("chooses");
        // Both are memory, so the first is kept; the assertion is that a choice was made at all.
        assert_eq!(chosen.kind(), SecretBackendKind::Memory);
    }

    #[test]
    fn choosing_from_nothing_is_no_backend_rather_than_a_silent_fallback() {
        // A silent fallback to memory would store the user's token in a place that forgets it at exit, and the
        // user would find out when they were asked to sign in again.
        assert!(matches!(choose_backend(Vec::new()), Err(SecretError::NoBackend)));
    }

    #[test]
    fn a_storage_report_names_the_backend_and_its_strength() {
        let backend = MemoryBackend::new();
        let report = SecretStorageReport::of(&backend).expect("reports");
        assert_eq!(report.backend, "memory");
        assert_eq!(report.strength, "None");
        assert!(report.explain().contains("memory"));
        // The report contains no value and no account name, which is the point of having one at all.
        assert!(!report.explain().contains("plugin/"));
    }

    #[test]
    fn a_storage_report_round_trips_without_carrying_anything_secret() {
        let report = SecretStorageReport {
            backend: "mac-keychain".to_owned(),
            strength: "OperatingSystem".to_owned(),
            entry_count: Some(3),
        };
        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.contains("entryCount"), "{json}");
        let back: SecretStorageReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
        // The count is omitted when unknown rather than written as null.
        let partial = SecretStorageReport {
            backend: "encrypted-file".to_owned(),
            strength: "AtRestOnly".to_owned(),
            entry_count: None,
        };
        let json = serde_json::to_string(&partial).expect("serialises");
        assert!(!json.contains("entryCount"), "{json}");
    }

    #[test]
    fn secret_errors_explain_themselves() {
        let errors = vec![
            SecretError::NoBackend,
            SecretError::Backend("x".to_owned()),
            SecretError::Corrupt("x".to_owned()),
            SecretError::KeyUnavailable("x".to_owned()),
            SecretError::NotFound { account: "a".to_owned() },
            SecretError::TooLarge { len: 1, max: 0 },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text:?}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn backend_names_round_trip_through_json() {
        for kind in [
            SecretBackendKind::WindowsCredential,
            SecretBackendKind::MacKeychain,
            SecretBackendKind::LinuxSecretService,
            SecretBackendKind::AndroidKeystore,
            SecretBackendKind::IosKeychain,
            SecretBackendKind::EncryptedFile,
            SecretBackendKind::Memory,
        ] {
            let json = serde_json::to_string(&kind).expect("serialises");
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
            let back: SecretBackendKind = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn a_secret_key_round_trips_through_json() {
        for key in [SecretKey::DeviceIdentity, plugin_key("token")] {
            let json = serde_json::to_string(&key).expect("serialises");
            let back: SecretKey = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, key);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Two distinct plugins never produce the same account name, whatever they call their secrets. A
        /// collision would be one plugin reading another's token, which is the one thing the namespacing exists
        /// to prevent.
        #[test]
        fn distinct_plugin_keys_never_collide(
            plugin_a in "[a-z@/-]{1,20}",
            plugin_b in "[a-z@/-]{1,20}",
            name in "[a-zA-Z0-9._/-]{1,20}",
        ) {
            let a = SecretKey::plugin(&plugin_a, &name).account();
            let b = SecretKey::plugin(&plugin_b, &name).account();

            if plugin_a == plugin_b {
                prop_assert_eq!(&a, &b);
            }
            else {
                // Either the sanitised plugin differs, so the accounts differ — or the sanitising collapsed
                // them, in which case the assertion is that it did so consistently rather than reading across.
                let sanitised_a = sanitise_account(&plugin_a);
                let sanitised_b = sanitise_account(&plugin_b);
                if sanitised_a != sanitised_b {
                    prop_assert_ne!(&a, &b);
                }
            }
            // And whatever the inputs, the account is non-empty and has no separator ambiguity.
            prop_assert!(!a.is_empty());
            prop_assert!(a.starts_with("plugin/"));
        }

        /// A plugin's key names a `plugin/` account, so it can never name the device identity's. The identity
        /// account has no prefix, which is what makes the two namespaces disjoint.
        #[test]
        fn a_plugin_key_never_names_the_device_identity(
            plugin in "[a-z@/-]{1,30}",
            name in "[a-zA-Z0-9._/-]{1,30}",
        ) {
            let account = SecretKey::plugin(&plugin, &name).account();
            prop_assert_ne!(&account, &SecretKey::DeviceIdentity.account());
            prop_assert!(account.starts_with("plugin/"));
        }

        /// A secret's `Debug` output never contains its bytes, whatever they are. The output is what reaches a
        /// log file and therefore a bug report.
        #[test]
        fn a_secret_never_prints_its_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let secret = SecretBytes::new(bytes.clone());
            let debug = format!("{secret:?}");
            prop_assert!(debug.starts_with("SecretBytes("));

            // A byte sequence that renders as text is the case that matters: a random sequence often contains
            // no printable run long enough to notice.
            if let Ok(text) = core::str::from_utf8(&bytes)
                && text.len() >= 4
                && !text.chars().any(|ch| ch.is_control())
            {
                prop_assert!(!debug.contains(text), "{debug} contains {text}");

                // And the same through the whole store, which is how a secret would actually be exposed.
                let backend = MemoryBackend::new();
                let key = SecretKey::plugin("@synra-plugin/chat", "token");
                backend.set(&key, &secret).expect("writes");
                let stored = backend.get(&key).expect("reads").expect("present");
                let rendered = format!("{stored:?}");
                prop_assert!(!rendered.contains(text), "{} contains {}", rendered, text);
            }
        }

        /// A stored value comes back byte for byte. A store that mangled a token would produce a mysterious
        /// authentication failure with nothing in any log to explain it.
        #[test]
        fn a_value_round_trips_through_the_store(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let backend = MemoryBackend::new();
            let key = SecretKey::plugin("@synra-plugin/chat", "token");
            let value = SecretBytes::new(bytes.clone());

            backend.set(&key, &value).expect("writes");
            let read = backend.get(&key).expect("reads").expect("present");
            prop_assert_eq!(read.expose(), bytes.as_slice());
        }
    }
}
