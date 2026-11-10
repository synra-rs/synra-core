use super::super::{Fingerprint, PluginTrust, PublisherTrustStore, SignatureError, Untrusted};
use super::key;

#[test]
fn an_unknown_publisher_is_a_question_rather_than_an_answer() {
    let store = PublisherTrustStore::new();
    let trust = store.classify("acme", &Fingerprint::of(&key(7).verifying_key()));

    assert_eq!(trust, PluginTrust::UnknownPublisher);
    assert!(!trust.is_trusted(), "a caller that treated this as trusted would be asking for consent it never obtained");
    assert!(!trust.is_refusal(), "and it is not a refusal: it is what a prompt is drawn for");
    assert!(store.is_empty());
}

#[test]
fn a_publisher_with_the_key_it_was_trusted_with_is_trusted() {
    let mut store = PublisherTrustStore::new();
    let fingerprint = Fingerprint::of(&key(7).verifying_key());
    store.trust("acme", fingerprint.clone());

    assert_eq!(store.classify("acme", &fingerprint), PluginTrust::TrustedPublisher);
    assert!(store.classify("acme", &fingerprint).is_trusted());
    assert_eq!(store.len(), 1);
    assert_eq!(store.trusted_key("acme"), Some(&fingerprint));
}

#[test]
fn a_publisher_whose_key_changed_is_refused() {
    // ★ The rule the store exists for. An id is free; a key is not.
    let mut store = PublisherTrustStore::new();
    let known = Fingerprint::of(&key(7).verifying_key());
    store.trust("acme", known.clone());

    let presented = Fingerprint::of(&key(9).verifying_key());
    match store.classify("acme", &presented) {
        PluginTrust::Untrusted { why: Untrusted::KeyChanged { known: held, presented: seen } } => {
            assert_eq!(held, known);
            assert_eq!(seen, presented);
        }
        other => panic!("expected a key-change refusal, got {other:?}"),
    }
    assert!(store.classify("acme", &presented).is_refusal());
}

#[test]
fn a_revoked_key_is_refused_even_by_a_device_that_trusts_it() {
    // ★ The check comes first, because a revocation is a decision made *after* a trust decision — and letting trust
    // win would make revocation impossible to apply.
    let mut store = PublisherTrustStore::new();
    let fingerprint = Fingerprint::of(&key(7).verifying_key());
    store.trust("acme", fingerprint.clone());
    store.revoke(fingerprint.clone(), "malicious code");

    assert!(store.is_revoked(&fingerprint));
    match store.classify("acme", &fingerprint) {
        PluginTrust::Untrusted { why: Untrusted::Revoked { reason } } => assert_eq!(reason, "malicious code"),
        other => panic!("expected a revocation, got {other:?}"),
    }
}

#[test]
fn untrusting_a_publisher_returns_it_to_a_question() {
    let mut store = PublisherTrustStore::new();
    let fingerprint = Fingerprint::of(&key(7).verifying_key());
    store.trust("acme", fingerprint.clone());
    assert!(store.forget("acme"));
    assert!(!store.forget("acme"), "forgetting twice forgets once");

    assert_eq!(store.classify("acme", &fingerprint), PluginTrust::UnknownPublisher);
}

#[test]
fn a_user_who_is_told_about_a_rotation_can_trust_the_new_key() {
    // The store records decisions. Refusing to record one would leave a user unable to recover from a legitimate
    // rotation they were told about out of band.
    let mut store = PublisherTrustStore::new();
    store.trust("acme", Fingerprint::of(&key(7).verifying_key()));
    let rotated = Fingerprint::of(&key(11).verifying_key());
    store.trust("acme", rotated.clone());

    assert_eq!(store.classify("acme", &rotated), PluginTrust::TrustedPublisher);
    assert!(store.classify("acme", &Fingerprint::of(&key(7).verifying_key())).is_refusal());
}

#[test]
fn a_fingerprint_is_what_a_person_compares() {
    let fingerprint = Fingerprint::of(&key(7).verifying_key());
    let text = fingerprint.as_str();
    // Four groups of four, so a person reads it in chunks rather than as one string of sixteen.
    assert_eq!(text.split(' ').count(), 4, "{text}");
    assert!(text.chars().all(|character| character.is_ascii_hexdigit() || character == ' '));
    assert!(text.chars().filter(|character| *character != ' ').all(|character| !character.is_lowercase()));
}

#[test]
fn a_fingerprint_a_user_typed_is_read_leniently() {
    // It came from a screen that grouped it, so case and separators are not the point.
    let canonical = Fingerprint::of(&key(7).verifying_key());
    let typed = canonical.as_str().to_lowercase().replace(' ', "");
    assert_eq!(Fingerprint::parse(&typed).expect("parsed"), canonical);
    assert_eq!(Fingerprint::parse(canonical.as_str()).expect("parsed"), canonical);

    for wrong in ["", "abc", "zzzz zzzz zzzz zzzz", "1234 5678 9abc"] {
        assert!(matches!(Fingerprint::parse(wrong), Err(SignatureError::PublicKey { .. })), "{wrong}");
    }
}

#[test]
fn a_fingerprint_prints_as_it_is_shown() {
    let fingerprint = Fingerprint::of(&key(7).verifying_key());
    assert_eq!(fingerprint.to_string(), fingerprint.as_str());
    assert!(!fingerprint.to_string().is_empty());
}

#[test]
fn every_trust_answer_has_a_name_and_a_defined_meaning() {
    let answers = [
        PluginTrust::TrustedPublisher,
        PluginTrust::UnknownPublisher,
        PluginTrust::Unsigned,
        PluginTrust::Untrusted {
            why: Untrusted::Revoked { reason: "x".to_owned() },
        },
    ];
    let mut seen: Vec<&str> = Vec::new();
    for answer in &answers {
        let name = answer.as_str();
        assert!(!name.is_empty());
        assert!(!seen.contains(&name), "{name} names two answers");
        seen.push(name);
    }
    // Exactly one answer means "no decision needed", and exactly one means "refuse".
    assert_eq!(answers.iter().filter(|answer| answer.is_trusted()).count(), 1);
    assert_eq!(answers.iter().filter(|answer| answer.is_refusal()).count(), 1);
    assert!(!PublisherTrustStore::classify_unsigned().is_trusted());
    assert!(!PublisherTrustStore::classify_unsigned().is_refusal());
}

#[test]
fn every_refusal_explains_itself() {
    for refusal in [
        Untrusted::Revoked { reason: "malicious code".to_owned() },
        Untrusted::KeyChanged {
            known: Fingerprint::parse("AAAA BBBB CCCC DDDD").expect("a fingerprint"),
            presented: Fingerprint::parse("1111 2222 3333 4444").expect("a fingerprint"),
        },
    ] {
        let sentence = refusal.to_string();
        assert!(sentence.len() > 20, "{refusal:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
    }
}
