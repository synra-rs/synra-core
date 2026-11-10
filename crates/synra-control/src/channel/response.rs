//! Responses the kernel returns to a CLI client.

use serde::{Deserialize, Serialize};

/// What the kernel answers.
///
/// # Why the payload is `serde_json::Value` rather than a typed result per request
///
/// Because the client is a command-line tool that prints what it gets, and a typed variant per request would make
/// adding a field to a status report a change to this enum, to the client and to the kernel at once. The command's
/// *shape* is the contract — `devices` returns a list of device views — and the type belongs where it is produced.
///
/// A `Value` rather than a string, so a client can re-shape it without parsing twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum Response {
    /// The answer to [`Request::Hello`].
    Hello {
        /// The protocol version the kernel speaks.
        version: u16,
        /// The kernel's own version, for a bug report.
        kernel: String,
    },

    /// A successful answer, with the command's result.
    Ok {
        /// The result, shaped by the command that produced it.
        value: serde_json::Value,
    },

    /// A refusal.
    ///
    /// # Why this carries a code rather than only a sentence
    ///
    /// A script branches on the code, and a person reads the sentence. The same split as the device protocol and the
    /// interface: one field is for a program and one is for a human, and a channel that carried only the sentence would
    /// make every script match on prose.
    Failed {
        /// The kernel's stable error code.
        code: String,
        /// Why, for a person.
        message: String,
        /// Whether repeating the request as it was could succeed.
        retryable: bool,
    },
}

impl Response {
    /// A successful answer.
    #[must_use]
    pub const fn ok(value: serde_json::Value) -> Self {
        Self::Ok { value }
    }

    /// A refusal.
    #[must_use]
    pub fn failed(code: &str, message: impl Into<String>, retryable: bool) -> Self {
        Self::Failed {
            code: code.to_owned(),
            message: message.into(),
            retryable,
        }
    }

    /// Whether this is a success.
    ///
    /// # Why `Hello` counts
    ///
    /// It is an answer the kernel was happy to give, and it carries a value the client needs. A predicate that
    /// recognised only `Ok` would call a successful handshake a failure — and the first version of this did, which is
    /// the kind of mistake that makes a client report "the kernel refused my handshake" for a working connection.
    ///
    /// `Failed` is the only shape that is not a success, so it is the one that is matched.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        !matches!(self, Self::Failed { .. })
    }

    /// The error code, when this is a refusal.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::Failed { code, .. } => Some(code),
            _ => None,
        }
    }
}


