//! Plugin identities and scoped slugs.

use core::fmt;

use serde::{Deserialize, Serialize};

use super::{IdError, MAX_PLUGIN_ID_LEN, MAX_PLUGIN_SLUG_LEN};

/// A plugin's package name, in npm scope form.
///
/// Rule: `@scope/name`. The scope is required — an unscoped plugin id would put every plugin in one
/// flat namespace, and the first collision would be unfixable without renaming a published plugin.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PluginId(String);

impl PluginId {
    /// Parses and validates a plugin id.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Empty`], [`IdError::TooLong`], [`IdError::Unscoped`] or
    /// [`IdError::InvalidCharacter`].
    pub fn parse(s: &str) -> Result<Self, IdError> {
        Self::validate(s)?;
        Ok(Self(s.to_owned()))
    }

    // Event and pattern validation borrow the owner instead of allocating a discarded id.
    pub(crate) fn validate(s: &str) -> Result<(), IdError> {
        if s.is_empty() {
            return Err(IdError::Empty);
        }
        if s.len() > MAX_PLUGIN_ID_LEN {
            return Err(IdError::TooLong { len: s.len(), max: MAX_PLUGIN_ID_LEN });
        }
        let rest = s.strip_prefix('@').ok_or(IdError::Unscoped)?;
        let (scope, name) = rest.split_once('/').ok_or(IdError::Unscoped)?;
        if scope.is_empty() || name.is_empty() {
            return Err(IdError::Unscoped);
        }
        // Slashes beyond the one separator are not part of the grammar.
        if name.contains('/') {
            return Err(IdError::Unscoped);
        }
        // `base` is where each part starts in the whole string: the scope begins right after `@`,
        // and the name right after `/`.
        validate_slug_like(scope, 1)?;
        validate_slug_like(name, 2 + scope.len())?;
        Ok(())
    }

    /// The whole id, including the scope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part after the slash.
    #[must_use]
    pub fn name(&self) -> &str {
        // `parse` guarantees a single slash with non-empty halves, so this cannot fail.
        self.0.split_once('/').map_or(&self.0, |(_, name)| name)
    }

    /// The part between `@` and the slash.
    #[must_use]
    pub fn scope(&self) -> &str {
        self.0
            .strip_prefix('@')
            .and_then(|rest| rest.split_once('/'))
            .map_or("", |(scope, _)| scope)
    }

    /// The complete event namespace owned by this package, including its publisher and trailing dot.
    ///
    /// The full id is preserved: neither publisher names nor conventional package prefixes are aliases.
    #[must_use]
    pub fn event_namespace(&self) -> String {
        format!("{}{self}.", crate::event::PLUGIN_PREFIX)
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for PluginId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PluginId> for String {
    fn from(value: PluginId) -> Self {
        value.0
    }
}

/// Validates the `[a-z0-9][a-z0-9-]*` form.
///
/// `base` is the byte offset at which `part` starts in the string being reported on, so an error
/// message points at a position the reader can find. It is passed in rather than derived from
/// lengths: the length difference gives the right answer only for a part at the *end* of the whole
/// string, which is not where a plugin id's scope lives.
fn validate_slug_like(part: &str, base: usize) -> Result<(), IdError> {
    let mut chars = part.char_indices();

    match chars.next() {
        None => return Err(IdError::Empty),
        Some((offset, ch)) if !(ch.is_ascii_lowercase() || ch.is_ascii_digit()) => {
            return Err(IdError::InvalidCharacter { ch, index: base + offset });
        }
        Some(_) => {}
    }

    for (offset, ch) in chars {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
            return Err(IdError::InvalidCharacter { ch, index: base + offset });
        }
    }
    Ok(())
}

/// The short name a plugin owns on the wire, used in `_plugin.<slug>.…` event names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PluginSlug(compact_str::CompactString);

impl PluginSlug {
    /// Parses and validates a slug.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Empty`], [`IdError::TooLong`] or [`IdError::InvalidCharacter`]. A leading
    /// digit is allowed; a leading or trailing hyphen is not.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.is_empty() {
            return Err(IdError::Empty);
        }
        if s.len() > MAX_PLUGIN_SLUG_LEN {
            return Err(IdError::TooLong { len: s.len(), max: MAX_PLUGIN_SLUG_LEN });
        }
        validate_slug_like(s, 0)?;
        // A trailing hyphen reads as a truncation and is easy to produce by accident when building
        // a slug from a package name.
        if s.ends_with('-') {
            return Err(IdError::InvalidCharacter {
                ch: '-',
                index: s.len() - 1,
            });
        }
        Ok(Self(compact_str::CompactString::from(s)))
    }

    /// The slug text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for PluginSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl TryFrom<String> for PluginSlug {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PluginSlug> for String {
    fn from(value: PluginSlug) -> Self {
        value.0.to_string()
    }
}


