//! Typed identifiers.
//!
//! # Why newtypes
//!
//! Every id in this protocol is a UUID, so without wrappers they are interchangeable and the
//! compiler will happily let a `TransferId` be passed where a `RequestId` belongs. That mistake
//! does not fail at the call site; it fails later, as a message nobody can correlate, and it costs
//! an afternoon. Wrapping each one costs a line of code and makes the mistake impossible to write.
//!
//! # Why UUIDv7
//!
//! Time-ordered. Sorting log lines needs no extra column, SQLite primary-key inserts stay
//! append-mostly rather than scattering across the B-tree, and a debug dump of ids reads in the
//! order things happened.
//!
//! # Parsing is strict
//!
//! [`DeviceId::from_str`] and friends reject anything that is not a UUID. There is no "generate a
//! fallback if parsing fails" branch anywhere in this crate: a code path that silently invents an
//! identifier turns a malformed message into a plausible-looking one, which is far harder to find
//! than an error.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Length limit for a [`PluginSlug`].
pub const MAX_PLUGIN_SLUG_LEN: usize = 48;

/// Length limit for a [`PluginId`].
pub const MAX_PLUGIN_ID_LEN: usize = 128;

/// Failure to parse or construct an identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The text is not a UUID.
    #[error("not a UUID")]
    NotUuid,

    /// The text is empty.
    #[error("empty")]
    Empty,

    /// The text is longer than the type allows.
    #[error("too long: {len} > {max}")]
    TooLong {
        /// Observed length in bytes.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },

    /// A character outside the permitted set.
    #[error("invalid character {ch:?} at byte {index}")]
    InvalidCharacter {
        /// The offending character.
        ch: char,
        /// Byte offset where it was found.
        index: usize,
    },

    /// A plugin id is missing its scope.
    #[error("plugin id must be scoped, e.g. @synra-plugin/chat")]
    Unscoped,

    /// The nil UUID, which is never valid as an identifier.
    #[error("nil identifier")]
    Nil,
}

macro_rules! uuid_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Wraps an existing UUID.
            ///
            /// Use this when the value came from a trusted source that already validated it. To
            /// validate untrusted text, use [`FromStr`].
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Whether this is the nil UUID.
            ///
            /// Nil is rejected when parsing, so a value that answers `true` here can only have been
            /// built through [`Self::from_uuid`] or deserialised from a peer that sent one.
            #[must_use]
            pub const fn is_nil(self) -> bool {
                self.0.is_nil()
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(s).map_err(|_| IdError::NotUuid)?;
                if uuid.is_nil() {
                    return Err(IdError::Nil);
                }
                Ok(Self(uuid))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

/// A device. Stable across restarts; it is the identity pairing is recorded against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(Uuid);

impl DeviceId {
    /// Generates a fresh device id.
    ///
    /// Called once, when a device first runs, and then persisted. A device that regenerates its id
    /// on every start appears to its peers as a new device each time, and every pairing is lost.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }

    /// Whether this is the nil UUID.
    #[must_use]
    pub const fn is_nil(self) -> bool {
        self.0.is_nil()
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for DeviceId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s).map_err(|_| IdError::NotUuid)?;
        if uuid.is_nil() {
            return Err(IdError::Nil);
        }
        Ok(Self(uuid))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

uuid_newtype!(
    /// One send. Used to correlate an acknowledgement and a request with its reply.
    ///
    /// A retry **reuses** the same `RequestId`; that is what makes redelivery idempotent rather than
    /// duplicating the work.
    RequestId
);

uuid_newtype!(
    /// One large-object transfer session.
    ///
    /// Not interchangeable with [`RequestId`]: a transfer spans many frames, each with its own
    /// request id, all sharing one transfer id.
    TransferId
);

uuid_newtype!(
    /// One intent — an action the user asked for, tracked from decision to result.
    IntentId
);

uuid_newtype!(
    /// One discovery scan, so late replies from a previous scan can be discarded.
    ScanId
);

uuid_newtype!(
    /// One file-sync session, grouping transfers that belong together.
    SessionId
);

impl RequestId {
    /// Generates a fresh request id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferId {
    /// Generates a fresh transfer id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for TransferId {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentId {
    /// Generates a fresh intent id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for IntentId {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanId {
    /// Generates a fresh scan id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ScanId {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionId {
    /// Generates a fresh session id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

mod trace;
mod plugin;

pub use plugin::{PluginId, PluginSlug};
pub use trace::TraceId;

#[cfg(test)]
mod tests;
