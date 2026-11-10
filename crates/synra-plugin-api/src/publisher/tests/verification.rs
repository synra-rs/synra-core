use super::super::{ALGORITHM, BASE64, Engine, Fingerprint, SIGNATURE_VERSION, SignatureError, SignatureFile, VerifyOutcome};
use super::{key, signed, subject};

#[test]
fn a_good_signature_verifies_and_names_the_key() {
    let text = signed(&subject(), "acme", 7);
    let document = SignatureFile::parse(&text).expect("a document");
    assert_eq!(document.publisher.id, "acme");
    assert_eq!(document.algorithm, ALGORITHM);

    let outcome = document.verify().expect("a verdict");
    let VerifyOutcome::Good { fingerprint } = outcome else {
        panic!("expected a good signature, got {outcome:?}");
    };
    // The fingerprint is what a user compares, so it is stable for a key and different for another.
    assert_eq!(fingerprint, Fingerprint::of(&key(7).verifying_key()));
    assert_ne!(fingerprint, Fingerprint::of(&key(8).verifying_key()));
    assert_eq!(fingerprint.as_str().len(), 19, "16 hex digits in four groups of four");
}

#[test]
fn a_tampered_subject_does_not_verify() {
    // ★ The one outcome that is never a warning: either the package was altered after signing or it was signed over
    // something else, and there is no third explanation.
    let text = signed(&subject(), "acme", 7);
    let mut document = SignatureFile::parse(&text).expect("a document");
    document.subject.artifacts.insert("plugin.wasm", "sha256-tampered");

    assert_eq!(document.verify().expect("a verdict"), VerifyOutcome::BadSignature);
}

#[test]
fn a_signature_from_another_key_does_not_verify() {
    // The impostor case: a valid-looking document whose signature was made by somebody else.
    let mut document = SignatureFile::parse(&signed(&subject(), "acme", 7)).expect("a document");
    let stranger = key(9);
    document.pubkey = BASE64.encode(stranger.verifying_key().as_bytes());

    assert_eq!(document.verify().expect("a verdict"), VerifyOutcome::BadSignature);
}

#[test]
fn an_unknown_version_is_refused_by_name_rather_than_read() {
    // A verifier that read a document from the future would be guessing at its shape.
    let mut document: serde_json::Value =
        serde_json::from_str(&signed(&subject(), "acme", 7)).expect("valid JSON");
    document["version"] = serde_json::json!(SIGNATURE_VERSION + 1);
    match SignatureFile::parse(&document.to_string()) {
        Err(SignatureError::Version { found, known }) => {
            assert_eq!(found, SIGNATURE_VERSION + 1);
            assert_eq!(known, SIGNATURE_VERSION);
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
}

#[test]
fn an_unknown_algorithm_is_refused_rather_than_skipped() {
    // ★ A verifier that ignored an algorithm it did not know would report "no signature to check" for a package that
    // has one — which is the answer that lets a package through.
    let mut document: serde_json::Value =
        serde_json::from_str(&signed(&subject(), "acme", 7)).expect("valid JSON");
    document["algorithm"] = serde_json::json!("rsa-4096");
    match SignatureFile::parse(&document.to_string()) {
        Err(SignatureError::Algorithm { found }) => assert_eq!(found, "rsa-4096"),
        other => panic!("expected an algorithm refusal, got {other:?}"),
    }
}

#[test]
fn a_key_that_is_not_a_key_is_refused() {
    let mut document = SignatureFile::parse(&signed(&subject(), "acme", 7)).expect("a document");
    document.pubkey = BASE64.encode([0_u8; 7]);
    assert!(matches!(document.verifying_key(), Err(SignatureError::PublicKey { .. })));

    // And thirty-two bytes whose high bit would make them a non-canonical encoding of a point. `ed25519-dalek`
    // rejects exactly that, and it is the one shape of "thirty-two bytes that are not a key" the curve refuses — a
    // random string decompresses to *some* point, which is why a key is not validated by looking plausible.
    let mut non_canonical = [0_u8; 32];
    non_canonical[31] = 0xff;
    document.pubkey = BASE64.encode(non_canonical);
    assert!(matches!(document.verifying_key(), Err(SignatureError::PublicKey { .. })));
}

#[test]
fn a_signature_that_is_not_a_signature_is_refused() {
    let mut document = SignatureFile::parse(&signed(&subject(), "acme", 7)).expect("a document");
    document.signature = BASE64.encode([0_u8; 3]);
    assert!(matches!(document.verify(), Err(SignatureError::Signature { .. })));
}

#[test]
fn a_document_that_is_not_json_is_refused_with_the_parsers_reason() {
    for text in ["", "not json", "{}", r#"{"version":1}"#] {
        assert!(matches!(SignatureFile::parse(text), Err(SignatureError::Unreadable { .. })), "{text}");
    }
}
