//! The error that crosses the interface.
//!
//! # A message *key*, not a message
//!
//! The design document is explicit: `message` is a [`MessageKey`] plus `params`, not a sentence. A sentence
//! baked into a Rust error arrives in the user's language as English, and the only way to fix it later is to
//! change every error site — which by then is every file.
//!
//! So an error carrying text is a key like `error.capability_denied` and a bag of parameters. The interface owns
//! the translation, and the parameters are the values the sentence needs — a plugin's name, a capability's
//! string. That split also means the key and the parameters can be logged without the sentence, which is what
//! makes an error readable in a diagnostic bundle whose reader speaks a different language.
//!
//! # The code is what a caller branches on
//!
//! `code` is the kernel's own [`ErrorCode`], not a separate interface-only enum. Two enums would drift, and the
//! drift would appear as a code the interface has no message for. Sharing it also means a refusal the kernel
//! already decided how to explain — whether it is worth showing the user, whether it is retryable — carries that
//! judgement across the boundary instead of being re-derived.

use serde::{Deserialize, Serialize};

use synra_protocol::error::SuggestedAction;
use synra_protocol::ErrorCode;

/// A localisable message.
///
/// A newtype rather than a bare `String` so a sentence cannot be passed where a key is wanted. The mistake it
/// prevents is specific and common: writing `MessageKey::new("the plugin was not found")`, which compiles, reads
/// correctly in English, and is untranslatable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageKey(String);

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
            details: Some(serde_json::json!({ "kernelMessage": error.message })),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every error code, so a test can assert a property over all of them.
    const ALL_CODES: &[ErrorCode] = &[
        ErrorCode::CapabilityDenied,
        ErrorCode::PluginNotInstalled,
        ErrorCode::DeviceOffline,
        ErrorCode::NotPaired,
        ErrorCode::TransportNotOpen,
        ErrorCode::TransferFailed,
        ErrorCode::IntegrityMismatch,
        ErrorCode::PayloadTooLarge,
        ErrorCode::Timeout,
        ErrorCode::RateLimited,
        ErrorCode::Unsupported,
        ErrorCode::InvalidArgument,
        ErrorCode::SchemeNotAllowed,
        ErrorCode::HostNotAllowed,
        ErrorCode::IpNotAllowed,
        ErrorCode::RedirectBlocked,
        ErrorCode::ResponseTooLarge,
        ErrorCode::ProtocolViolation,
        ErrorCode::ProtocolVersionUnsupported,
        ErrorCode::PluginTrapped,
        ErrorCode::PluginTimeout,
        ErrorCode::Internal,
    ];

    // ── Message keys ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_key_is_accepted() {
        for text in ["error.capability_denied", "error.not_paired", "warn.slow", "info.a-b.c_1"] {
            assert_eq!(MessageKey::parse(text).expect("parses").as_str(), text, "{text}");
        }
    }

    #[test]
    fn a_sentence_is_refused() {
        // The mistake this prevents: writing the sentence where the key goes. It compiles, it reads correctly in
        // English, and it is untranslatable.
        match MessageKey::parse("the plugin was not found") {
            Err(MessageKeyError::LooksLikeASentence { text }) => assert_eq!(text, "the plugin was not found"),
            other => panic!("expected a sentence refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_key_is_refused() {
        assert_eq!(MessageKey::parse(""), Err(MessageKeyError::Empty));
    }

    #[test]
    fn an_over_long_key_is_refused() {
        let long = "a".repeat(MAX_MESSAGE_KEY_LEN + 1);
        assert!(MessageKey::parse(&long).is_err());
        assert!(MessageKey::parse(&long).is_err());
        // Exactly at the limit is fine.
        let exact = "a".repeat(MAX_MESSAGE_KEY_LEN);
        assert!(MessageKey::parse(&exact).is_ok());
    }

    #[test]
    fn a_key_with_an_unexpected_character_is_refused() {
        for text in ["error.capability/denied", "error.a:b", "错误", "error.a b"] {
            assert!(MessageKey::parse(text).is_err(), "{text:?} should be refused");
        }
    }

    #[test]
    fn a_key_is_transparent_on_the_wire() {
        // `#[serde(transparent)]`: the key is a string on the wire, not `{ "0": "…" }`. A wrapper that changed
        // the shape would make every message key a parsing failure in the interface.
        let key = MessageKey::parse("error.timeout").expect("parses");
        let json = serde_json::to_string(&key).expect("serialises");
        assert_eq!(json, "\"error.timeout\"");
        let back: MessageKey = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, key);
    }

    #[test]
    fn a_key_displays_itself() {
        assert_eq!(MessageKey::parse("error.timeout").expect("parses").to_string(), "error.timeout");
    }

    // ── Errors ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_error_carries_what_the_interface_acts_on() {
        let error = IpcError::new(ErrorCode::CapabilityDenied, "error.capability_denied")
            .expect("builds")
            .with_params(serde_json::json!({ "capability": "platform:open-url" }))
            .with_action(SuggestedAction::RequestCapability {
                capability: "platform:open-url".to_owned(),
            });

        assert_eq!(error.code, ErrorCode::CapabilityDenied);
        assert_eq!(error.message.as_str(), "error.capability_denied");
        assert_eq!(error.params["capability"], "platform:open-url");
        assert!(!error.retryable, "a missing grant is not fixed by retrying");
        assert_eq!(error.actions.len(), 1);
        assert!(error.has_something_to_offer(), "there is a button to render");
    }

    #[test]
    fn retryability_comes_from_the_code_and_is_not_re_derived() {
        // The kernel already decided whether a code is worth retrying; a second opinion in the interface is one
        // that can disagree with the kernel the user is actually talking to.
        for code in ALL_CODES {
            let error = IpcError::unknown(*code);
            assert_eq!(error.retryable, code.retryable(), "{code:?}");
        }
    }

    #[test]
    fn an_error_with_neither_a_retry_nor_an_action_offers_nothing() {
        let error = IpcError::new(ErrorCode::CapabilityDenied, "error.capability_denied").expect("builds");
        assert!(!error.has_something_to_offer());
    }

    #[test]
    fn every_code_produces_a_usable_key() {
        // The interface has to translate the key, so a code whose key is not one is a code the interface shows
        // nothing for.
        for code in ALL_CODES {
            let error = IpcError::unknown(*code);
            let key = error.message.as_str();
            assert!(key.starts_with("error."), "{code:?} -> {key}");
            assert!(!key.contains(' '), "{code:?} -> {key}");
            assert!(MessageKey::parse(key).is_ok(), "{code:?} -> {key}");
        }
    }

    #[test]
    fn the_key_matches_the_wire_code() {
        // Derived from serde's own serialisation, so the key and the code cannot disagree — a hand-written table
        // would be one more place to update when a code is added.
        for code in ALL_CODES {
            let wire = serde_json::to_value(code)
                .expect("serialises")
                .as_str()
                .expect("a string")
                .to_owned();
            let error = IpcError::unknown(*code);
            assert_eq!(error.message.as_str(), format!("error.{wire}"), "{code:?}");
        }
    }

    #[test]
    fn a_kernel_error_is_carried_across_with_its_judgement_intact() {
        let kernel = synra_protocol::SynraError::new(ErrorCode::Timeout, "the peer did not answer")
            .with_action(SuggestedAction::Retry);
        let ipc = IpcError::from_synra_error(&kernel);

        assert_eq!(ipc.code, ErrorCode::Timeout);
        assert_eq!(ipc.message.as_str(), "error.timeout");
        assert!(ipc.retryable);
        assert_eq!(ipc.actions.len(), 1);
        // The kernel's sentence is kept as a detail rather than as the message: a log reader and a user need
        // different things from the same failure.
        assert_eq!(ipc.details.as_ref().expect("details")["kernelMessage"], "the peer did not answer");
    }

    #[test]
    fn a_kernel_error_with_no_actions_crosses_with_none() {
        let kernel = synra_protocol::SynraError::new(ErrorCode::Internal, "x");
        let ipc = IpcError::from_synra_error(&kernel);
        assert!(ipc.actions.is_empty());
        // The kernel's own judgement is carried across rather than re-derived, and the kernel treats `internal` as
        // retryable — an internal fault is often a race or a transient, and the retry budget is what bounds it.
        // Disagreeing here would be a second opinion that can contradict the kernel the user is talking to.
        assert_eq!(ipc.retryable, ErrorCode::Internal.retryable());
    }

    #[test]
    fn a_code_the_kernel_calls_permanent_is_not_retried() {
        // The other side of the judgement: a missing grant is not fixed by asking again, and the interface uses
        // this to decide whether to offer a retry button.
        for code in [ErrorCode::CapabilityDenied, ErrorCode::NotPaired, ErrorCode::Unsupported] {
            assert!(!IpcError::unknown(code).retryable, "{code:?}");
        }
        for code in [ErrorCode::Timeout, ErrorCode::DeviceOffline, ErrorCode::TransportNotOpen] {
            assert!(IpcError::unknown(code).retryable, "{code:?}");
        }
    }

    #[test]
    fn an_error_round_trips_through_json() {
        // The shape is what the interface parses, so a field that changes name is a field the interface cannot
        // read. `camelCase` throughout.
        let error = IpcError::new(ErrorCode::RateLimited, "error.rate_limited")
            .expect("builds")
            .with_params(serde_json::json!({ "retryAfterMs": 250 }))
            .with_details(serde_json::json!({ "scope": "events" }))
            .with_action(SuggestedAction::Retry);

        let json = serde_json::to_string(&error).expect("serialises");
        assert!(json.contains("\"message\":\"error.rate_limited\""), "{json}");
        assert!(json.contains("retryAfterMs"), "{json}");
        assert!(json.contains("\"retryable\":true"), "{json}");

        let back: IpcError = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, error);
    }

    #[test]
    fn absent_optional_fields_are_omitted_rather_than_null() {
        // An explicit `null` and an absent field are different statements, and `deny_unknown_fields` consumers
        // elsewhere in the protocol treat the distinction as meaningful.
        let error = IpcError::new(ErrorCode::NotPaired, "error.not_paired").expect("builds");
        let json = serde_json::to_string(&error).expect("serialises");
        assert!(!json.contains("params"), "{json}");
        assert!(!json.contains("details"), "{json}");
        assert!(!json.contains("actions"), "{json}");
    }

    #[test]
    fn an_interface_can_branch_on_the_code_without_parsing_a_sentence() {
        // The design document's requirement, as an executable statement: the code is a closed set, so a branch on
        // it is exhaustive and a typo is a compile error rather than a case that never runs.
        let error = IpcError::new(ErrorCode::CapabilityDenied, "error.capability_denied").expect("builds");
        let outcome = match error.code {
            ErrorCode::CapabilityDenied => "need_permission",
            ErrorCode::NotPaired => "need_pairing",
            ErrorCode::DeviceOffline => "offline",
            ErrorCode::Timeout | ErrorCode::RateLimited => "retry_later",
            _ => "other",
        };
        assert_eq!(outcome, "need_permission");
    }

    #[test]
    fn message_key_errors_explain_themselves() {
        let errors = [
            MessageKeyError::Empty,
            MessageKeyError::TooLong { len: 200, max: 96 },
            MessageKeyError::LooksLikeASentence { text: "a b".to_owned() },
            MessageKeyError::BadCharacter { text: "a:b".to_owned() },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A key that parses is one the interface can look up: non-empty, no space, and inside the character set.
        /// The property is what makes the "not a sentence" rule enforceable rather than a note in a document.
        #[test]
        fn a_parsed_key_is_lookup_shaped(text in ".{0,120}") {
            if let Ok(key) = MessageKey::parse(&text) {
                prop_assert!(!key.as_str().is_empty());
                prop_assert!(!key.as_str().contains(' '));
                prop_assert!(key.as_str().len() <= MAX_MESSAGE_KEY_LEN);
                prop_assert!(key
                    .as_str()
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')));
            }
        }

        /// Parsing a key is total, whatever the text. Keys are built from code names in one place and from a
        /// caller's input in another, and the second is not trusted.
        #[test]
        fn parsing_a_key_is_total(text in ".{0,200}") {
            let _ = MessageKey::parse(&text);
        }

        /// Any code produces an error whose `retryable` agrees with the code, for every code. A disagreement would
        /// make the interface offer a retry the kernel has already decided cannot work.
        #[test]
        fn the_retry_judgement_always_agrees(index in 0usize..22) {
            let codes = [
                ErrorCode::CapabilityDenied,
                ErrorCode::PluginNotInstalled,
                ErrorCode::DeviceOffline,
                ErrorCode::NotPaired,
                ErrorCode::TransportNotOpen,
                ErrorCode::TransferFailed,
                ErrorCode::IntegrityMismatch,
                ErrorCode::PayloadTooLarge,
                ErrorCode::Timeout,
                ErrorCode::RateLimited,
                ErrorCode::Unsupported,
                ErrorCode::InvalidArgument,
                ErrorCode::SchemeNotAllowed,
                ErrorCode::HostNotAllowed,
                ErrorCode::IpNotAllowed,
                ErrorCode::RedirectBlocked,
                ErrorCode::ResponseTooLarge,
                ErrorCode::ProtocolViolation,
                ErrorCode::ProtocolVersionUnsupported,
                ErrorCode::PluginTrapped,
                ErrorCode::PluginTimeout,
                ErrorCode::Internal,
            ];
            let code = codes[index];
            let error = IpcError::unknown(code);
            prop_assert_eq!(error.retryable, code.retryable());
            prop_assert_eq!(error.code, code);
        }

        /// An error survives a JSON round trip with its fields intact, for any parameters. The interface parses
        /// this on every failure, so a shape that does not round-trip is a failure the user never sees the reason
        /// for.
        #[test]
        fn an_error_round_trips(key_suffix in "[a-z_]{1,20}", retry_value in any::<u64>()) {
            let key = format!("error.{key_suffix}");
            let Ok(error) = IpcError::new(ErrorCode::Internal, &key) else {
                return Ok(());
            };
            let error = error.with_params(serde_json::json!({ "value": retry_value }));
            let json = serde_json::to_string(&error).expect("serialises");
            let back: IpcError = serde_json::from_str(&json).expect("deserialises");
            prop_assert_eq!(back, error);
        }
    }
}
