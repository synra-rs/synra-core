use proptest::prelude::*;
use synra_protocol::ErrorCode;

use super::tests::ALL_CODES;
use super::{IpcError, MAX_MESSAGE_KEY_LEN, MessageKey};

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
    fn the_retry_judgement_always_agrees(index in 0usize..ALL_CODES.len()) {
        let code = ALL_CODES[index];
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
