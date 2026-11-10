use serde::{Deserialize, Serialize};

/// A localisable message.
///
/// A newtype rather than a bare `String` so a sentence cannot be passed where a key is wanted. The mistake it
/// prevents is specific and common: writing `MessageKey::new("the plugin was not found")`, which compiles, reads
/// correctly in English, and is untranslatable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageKey(pub(super) String);

impl MessageKey {
    /// Wraps a key.
    ///
    /// # The convention
    ///
    /// `error.<reason>`, with the reason in `snake_case` matching the error code where one exists. A key that
    /// does not start with `error.` is still accepted, because a warning or an informational message uses the
    /// same type — but a key containing a space is refused, because that is a sentence.
    ///
    /// # Errors
    ///
    /// [`MessageKeyError`] when the text is empty, has a space, or is longer than [`MAX_MESSAGE_KEY_LEN`].
    pub fn parse(text: &str) -> Result<Self, MessageKeyError> {
        if text.is_empty() {
            return Err(MessageKeyError::Empty);
        }
        if text.len() > MAX_MESSAGE_KEY_LEN {
            return Err(MessageKeyError::TooLong { len: text.len(), max: MAX_MESSAGE_KEY_LEN });
        }
        // A space is the tell for a sentence. Refusing it here is what makes the convention enforceable rather
        // than a note in a document.
        if text.contains(' ') {
            return Err(MessageKeyError::LooksLikeASentence { text: text.to_owned() });
        }
        if !text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        {
            return Err(MessageKeyError::BadCharacter { text: text.to_owned() });
        }
        Ok(Self(text.to_owned()))
    }

    /// The key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for MessageKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The longest a message key may be.
pub const MAX_MESSAGE_KEY_LEN: usize = 96;

/// Why a message key is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MessageKeyError {
    /// It is empty.
    #[error("a message key cannot be empty")]
    Empty,
    /// It is too long.
    #[error("the message key is {len} characters, and the limit is {max}")]
    TooLong {
        /// How long it is.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// It contains a space, so it is a sentence rather than a key.
    #[error("{text:?} contains a space, so it is a sentence and not a key")]
    LooksLikeASentence {
        /// The text that was offered.
        text: String,
    },
    /// It contains a character a key cannot have.
    #[error("{text:?} contains a character outside `[A-Za-z0-9._-]`")]
    BadCharacter {
        /// The text that was offered.
        text: String,
    },
}
