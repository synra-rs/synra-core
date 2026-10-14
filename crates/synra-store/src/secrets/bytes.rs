//! The secret bytes, the redacted `Debug`, and the wipe on drop.

use core::fmt;
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
