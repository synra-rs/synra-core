use core::fmt;

use super::{DEFAULT_MAX_VALUE_LEN, REDACTED, Redacted, Redaction, TRUNCATION_MARK};
use super::url::strip_url_query;

/// Field-name fragments that mark a value as secret.
///
/// Matched case-insensitively as substrings against the field name. Ordered longest-first only in the
/// comments: the check is a `contains`, so order does not matter, and listing them together makes it
/// obvious what the policy is.
const SECRET_FRAGMENTS: &[&str] = &[
    // Message and file content.
    "payload",
    "body",
    "content",
    "clipboard",
    "text",
    "file_data",
    "filedata",
    "bytes",
    // Credentials.
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "apikey",
    "api_key",
    "auth",
    "cookie",
    "session_key",
    "private_key",
    "privatekey",
    "signature",
    // Plugin-private storage.
    "secure",
    "keyring",
];

/// A field name that must not be logged at all.
///
/// Also matched as a substring. Kept separate from [`SECRET_FRAGMENTS`] because these are names where
/// the value is *structure* rather than content — a JWT has no useful log representation at all, and
/// logging its first few bytes is still a partial credential.
const WHOLE_VALUE_FRAGMENTS: &[&str] = &["jwt", "bearer", "authorization"];

/// Applies the redaction policy.
///
/// Deliberately holds no subscriber and no I/O: redaction is a pure function of a field name and a
/// value, so it can be tested exhaustively and used from anywhere — a log layer, a diagnostic bundle, an
/// audit record, an error message shown to a user.
#[derive(Debug, Clone)]
pub struct Redactor {
    max_value_len: usize,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// A redactor with the default cap.
    #[must_use]
    pub const fn new() -> Self {
        Self { max_value_len: DEFAULT_MAX_VALUE_LEN }
    }

    /// A redactor with a different cap, for tests and for a verbose mode.
    #[must_use]
    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }

    /// The current cap.
    #[must_use]
    pub const fn max_value_len(&self) -> usize {
        self.max_value_len
    }

    /// Whether a field name marks its value as secret.
    ///
    /// Case-insensitive substring match, so `authToken`, `AUTH_TOKEN` and `request_body` are all caught.
    #[must_use]
    pub fn is_secret_field(name: &str) -> bool {
        let lowered = name.to_ascii_lowercase();
        SECRET_FRAGMENTS
            .iter()
            .chain(WHOLE_VALUE_FRAGMENTS)
            .any(|fragment| lowered.contains(fragment))
    }

    /// Redacts a string value according to its field name.
    ///
    /// A secret field is replaced outright, whatever it contains. Everything else is stripped of a URL's
    /// query and fragment, then truncated.
    #[must_use]
    pub fn value(&self, field: &str, value: &str) -> Redacted {
        if Self::is_secret_field(field) {
            return Redacted { text: REDACTED.to_owned(), decision: Redaction::Replaced };
        }

        // A URL keeps its scheme, host and path: those are usually the diagnosis. The query and
        // fragment are where tokens live.
        let (stripped, removed) = strip_url_query(value);
        let after_url = if removed > 0 {
            stripped
        }
        else {
            value.to_owned()
        };

        let url_decision = if removed > 0 {
            Some(Redaction::UrlStripped { removed })
        }
        else {
            None
        };

        if after_url.chars().count() > self.max_value_len {
            let original_len = after_url.chars().count();
            let mut text: String = after_url.chars().take(self.max_value_len).collect();
            text.push_str(TRUNCATION_MARK);
            let _ = fmt::Write::write_fmt(&mut text, format_args!("(len={original_len})"));
            return Redacted {
                text,
                decision: url_decision.unwrap_or(Redaction::Truncated { original_len }),
            };
        }

        match url_decision {
            Some(decision) => Redacted { text: after_url, decision },
            None => Redacted::untouched(after_url),
        }
    }

    /// Redacts a value that is not a string, by its `Debug` form.
    ///
    /// A non-string field can still hold content: `payload = ?json` where `json` is a
    /// `serde_json::Value` is the most common way to leak a message body, and it renders as a string.
    #[must_use]
    pub fn debug_value<T: fmt::Debug + ?Sized>(&self, field: &str, value: &T) -> Redacted {
        self.value(field, &format!("{value:?}"))
    }

    /// Redacts a value by its `Display` form.
    #[must_use]
    pub fn display_value<T: fmt::Display + ?Sized>(&self, field: &str, value: &T) -> Redacted {
        self.value(field, &format!("{value}"))
    }
}
