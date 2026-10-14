/// Why a configuration operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A key is not a dotted path.
    #[error("`{key}` is not a setting key: {why}")]
    BadKey {
        /// The key.
        key: String,
        /// Which rule it broke.
        why: String,
    },

    /// A patch names a key in both `set` and `unset`.
    #[error("`{key}` is both set and unset in one patch")]
    SetAndUnset {
        /// The key.
        key: String,
    },

    /// A configuration file could not be read as JSON.
    #[error("the configuration file is not readable: {why}")]
    Unreadable {
        /// What the parser said.
        why: String,
    },

    /// A configuration file's top level is not an object.
    #[error("the configuration file holds {found}, not an object of settings")]
    NotAnObject {
        /// What it held instead.
        found: &'static str,
    },

    /// A key is reserved and may not be written by a caller.
    #[error("`{key}` is reserved: {why}")]
    Reserved {
        /// The key.
        key: String,
        /// Why it is reserved.
        why: &'static str,
    },
}
