//! Which backend holds a secret, how strong it is, and how it is named.

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
    DeviceIdentity {
        /// SHA-256 of the public certificate; each enrollment has a separate secret slot.
        fingerprint: [u8; 32],
    },
    /// One plugin's secure value, under a name the plugin chose.
    PluginSecret {
        /// The plugin.
        plugin_id: String,
        /// The name the plugin gave the value.
        name: String,
    },
}

impl SecretKey {
    /// A device private key under its public certificate fingerprint.
    #[must_use]
    pub const fn device_identity(fingerprint: [u8; 32]) -> Self {
        Self::DeviceIdentity { fingerprint }
    }

    /// A plugin's secret.
    #[must_use]
    pub fn plugin(plugin_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::PluginSecret {
            plugin_id: plugin_id.into(),
            name: name.into(),
        }
    }

    /// The account name a keychain entry is filed under.
    ///
    /// Namespaced so that a plugin cannot collide with the device identity or with another plugin, and
    /// sanitised so a plugin cannot choose a name that reads as a different namespace.
    #[must_use]
    pub fn account(&self) -> String {
        match self {
            Self::DeviceIdentity { fingerprint } => {
                let hex: String = fingerprint
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                format!("device-identity/{hex}")
            }
            Self::PluginSecret { plugin_id, name } => {
                format!(
                    "plugin/{}/{}",
                    sanitise_account(plugin_id),
                    sanitise_account(name)
                )
            }
        }
    }

    /// Whether this key belongs to the given plugin.
    #[must_use]
    pub fn belongs_to(&self, plugin_id: &str) -> bool {
        match self {
            Self::DeviceIdentity { .. } => false,
            Self::PluginSecret {
                plugin_id: owner, ..
            } => owner == plugin_id,
        }
    }
}

/// Makes a string safe to use as a keychain account component.
///
/// A plugin chooses its own secret names, so a name containing `/` would let it file a value under a different
/// plugin's namespace — or under the device identity's — and read something it should not have.
pub(crate) fn sanitise_account(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
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
