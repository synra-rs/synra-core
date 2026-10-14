use serde_json::Value;

use super::{ConfigError, SettingKey, SettingKind};

/// One setting the kernel knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// Its dotted path.
    pub key: SettingKey,
    /// What its values look like.
    pub kind: SettingKind,
    /// The value it has when the user has not set it.
    pub default: Value,
    /// What it does, for the settings screen.
    pub description: String,
    /// Whether a caller may write it.
    ///
    /// Reserved for settings the kernel computes — a last-used version, a resolved path — where a write would be a
    /// value the kernel overwrites at the next start, so the user's change appears to work and then silently does not.
    pub reserved: bool,
}

impl Setting {
    /// A writable setting.
    ///
    /// # Errors
    ///
    /// [`ConfigError::BadKey`] when the key is not a dotted path, which is refused here rather than at the first write
    /// because a malformed key in the catalogue is a setting no screen can reach.
    pub fn new(
        key: &str,
        kind: SettingKind,
        default: Value,
        description: &str,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            key: SettingKey::parse(key)?,
            kind,
            default,
            description: description.to_owned(),
            reserved: false,
        })
    }

    /// A setting a caller may not write.
    #[must_use]
    pub const fn reserved(mut self) -> Self {
        self.reserved = true;
        self
    }

    /// Whether a value is acceptable for this setting.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Reserved`] for a reserved setting, and a description of the mismatch otherwise — as a
    /// [`ConfigError::BadKey`] whose `why` says what was expected, because that is the error variant that already
    /// carries "this key, and here is what is wrong with it".
    pub fn check(&self, value: &Value) -> Result<(), ConfigError> {
        if self.reserved {
            return Err(ConfigError::Reserved {
                key: self.key.as_str().to_owned(),
                why: "the kernel computes it, so a write would be overwritten at the next start",
            });
        }
        if !self.kind.matches(value) {
            return Err(ConfigError::BadKey {
                key: self.key.as_str().to_owned(),
                why: format!("expected {}, found {}", self.kind.as_str(), describe(value)),
            });
        }
        Ok(())
    }
}

/// A word for what a JSON value is, for a message.
pub(crate) fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "an integer",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}
