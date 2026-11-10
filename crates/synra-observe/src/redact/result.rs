use core::fmt;

/// What was done to a value, so a test can assert on the decision rather than on a formatted string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redaction {
    /// The value is safe and appears unchanged.
    Untouched,
    /// The value was replaced entirely.
    Replaced,
    /// The value was cut to [`Redactor::max_value_len`](super::Redactor::max_value_len) characters.
    Truncated {
        /// The original length, in characters.
        original_len: usize,
    },
    /// A URL had its query and fragment removed.
    UrlStripped {
        /// How many characters were removed.
        removed: usize,
    },
}

impl Redaction {
    /// Whether the value reached the log unchanged.
    #[must_use]
    pub const fn is_untouched(&self) -> bool {
        matches!(self, Self::Untouched)
    }

    /// Whether anything was withheld.
    #[must_use]
    pub const fn withheld_something(&self) -> bool {
        !self.is_untouched()
    }
}

/// The result of redacting one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    /// What should be written to the log.
    pub text: String,
    /// What was done.
    pub decision: Redaction,
}

impl Redacted {
    /// A value that needed no change.
    pub(super) fn untouched(text: impl Into<String>) -> Self {
        Self { text: text.into(), decision: Redaction::Untouched }
    }
}

impl fmt::Display for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}
