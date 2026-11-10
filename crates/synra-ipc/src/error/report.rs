use serde::{Deserialize, Serialize};

use synra_protocol::error::SuggestedAction;
use synra_protocol::ErrorCode;

use super::{MessageKey, MessageKeyError};

/// Why a command failed, in the form the interface can act on.
///
/// Every field is there because the interface does something with it:
///
/// * `code` — branch on it.
/// * `message` + `params` — translate it.
/// * `retryable` — decide whether to offer "try again".
/// * `actions` — render the buttons that could resolve it.
/// * `details` — show more on demand, for a user who wants to know why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    /// The stable reason code.
    pub code: ErrorCode,
    /// The message key the interface translates.
    pub message: MessageKey,
    /// The values the sentence needs.
    ///
    /// A JSON value rather than a typed struct because each key needs different parameters, and a union of
    /// per-key structs would be an enum the interface has to match on anyway — at which point the parameters are
    /// the same bag of values with extra steps.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub params: serde_json::Value,
    /// More, for a user who asks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Whether trying again could succeed.
    pub retryable: bool,
    /// What the user could do about it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<SuggestedAction>,
}

impl IpcError {
    /// Builds an error with no parameters and no actions.
    ///
    /// # Errors
    ///
    /// [`MessageKeyError`] if the key is not one.
    pub fn new(code: ErrorCode, key: &str) -> Result<Self, MessageKeyError> {
        Ok(Self {
            code,
            message: MessageKey::parse(key)?,
            params: serde_json::Value::Null,
            details: None,
            retryable: code.retryable(),
            actions: Vec::new(),
        })
    }

    /// Builds an error from a key that is already validated.
    #[must_use]
    pub const fn from_key(code: ErrorCode, message: MessageKey) -> Self {
        Self {
            code,
            message,
            params: serde_json::Value::Null,
            details: None,
            // The kernel already decided whether this code is worth retrying; re-deriving it in the interface
            // would be a second opinion that can disagree.
            retryable: code.retryable(),
            actions: Vec::new(),
        }
    }

    /// Adds parameters.
    #[must_use]
    pub fn with_params(mut self, params: serde_json::Value) -> Self {
        self.params = params;
        self
    }

    /// Adds details.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Adds an action.
    #[must_use]
    pub fn with_action(mut self, action: SuggestedAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Whether the interface should offer a retry.
    ///
    /// The same as `retryable`, but named for the caller's question: an error that is retryable *and* has no
    /// action the user can take is one where the interface should retry on its own or offer a button; an error
    /// with a concrete action is one where the user has something to do first.
    #[must_use]
    pub const fn has_something_to_offer(&self) -> bool {
        self.retryable || !self.actions.is_empty()
    }

    /// Turns a kernel error into one the interface can act on.
    ///
    /// # Keying the message
    ///
    /// The key is derived from the code rather than from the error's own `message`, which is a sentence. That is
    /// the whole point of the boundary: the kernel's sentence is for a log, and the interface's key is for the
    /// user.
    ///
    /// The kernel's `traceId` and its actions are carried across, because they are what a bug report needs and
    /// what the interface renders.
    #[must_use]
    pub fn from_synra_error(error: &synra_protocol::SynraError) -> Self {
        let key = MessageKey(format!("error.{}", code_key(error.code)));
        Self {
            code: error.code,
            message: key,
            params: serde_json::Value::Null,
            details: Some(serde_json::json!({
                "kernelMessage": error.message,
                "context": error.details,
                "traceId": error.trace_id,
            })),
            retryable: error.retryable,
            actions: error.actions.clone(),
        }
    }

    /// A key for a code that a caller has no sentence for.
    ///
    /// The fallback matters: an interface that receives a code it does not recognise from a newer kernel should
    /// show *something* rather than nothing, and `error.unknown` is a key it can translate.
    ///
    /// # Errors
    ///
    /// Never in practice — the key is built from an ASCII code — but the signature says a key is fallible
    /// because building one by hand is how the sentence gets in.
    #[must_use]
    pub fn unknown(code: ErrorCode) -> Self {
        // Built from the code's own `snake_case` name, which is ASCII by construction, so the parse cannot fail;
        // the fallback is here rather than an `expect` because the workspace forbids one and a panic on this path
        // would be a panic crossing the interface.
        let key = MessageKey::parse(&format!("error.{}", code_key(code)))
            .unwrap_or_else(|_| MessageKey("error.unknown".to_owned()));
        Self::from_key(code, key)
    }
}

/// The `snake_case` name of an error code, which is what its message key ends with.
///
/// Derived from serde's own serialisation so the key and the wire code cannot disagree: a hand-written table
/// would be one more place to update when a code is added.
fn code_key(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}
