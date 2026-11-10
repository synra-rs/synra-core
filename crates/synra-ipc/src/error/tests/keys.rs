use super::super::{MAX_MESSAGE_KEY_LEN, MessageKey, MessageKeyError};

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
