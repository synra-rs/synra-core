//! The signature and the trust decision, driven from both sides.
//!
//! A signature test that only ever checks a *good* signature proves nothing about the check: it would pass against a
//! verifier that returned `Good` unconditionally. So every property here has a case that must fail — a tampered
//! subject, an artifact that was swapped, a key that changed — and the cases are asserted as outcomes rather than as
//! "it did not panic".

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::manifest::Manifest;

/// A publisher's key, derived from a byte so a test can name it.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A signature document over a subject, signed by a key.
fn signed(subject: &SigningSubject, publisher_id: &str, seed: u8) -> String {
    let signing = key(seed);
    let public = signing.verifying_key();
    let signature = signing.sign(&subject.canonical_bytes());
    let document = serde_json::json!({
        "version": SIGNATURE_VERSION,
        "publisher": { "id": publisher_id, "name": "A Publisher" },
        "algorithm": ALGORITHM,
        "signedAt": "2026-07-22T10:00:00Z",
        "pubkey": BASE64.encode(public.as_bytes()),
        "subject": {
            "manifest": subject.manifest.clone(),
            "artifacts": subject.artifacts.iter().map(|(name, digest)| (name.to_owned(), digest.to_owned())).collect::<std::collections::BTreeMap<String, String>>(),
        },
        "signature": BASE64.encode(signature.to_bytes()),
    });
    serde_json::to_string(&document).expect("a document")
}

fn subject() -> SigningSubject {
    let mut artifacts = Digests::new();
    artifacts.insert("plugin.wasm", "sha256-aaa");
    SigningSubject { manifest: "sha256-bbb".to_owned(), artifacts }
}

/// A manifest that names the artifact the subject covers.
fn manifest() -> Manifest {
    let text = r#"{
        "id": "@acme/hello",
        "version": "1.2.3",
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": "1.0.0",
        "capabilities": [],
        "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
    }"#;
    serde_json::from_str(text).expect("a manifest")
}

fn digests() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let _ = map.insert("plugin.wasm".to_owned(), "sha256-aaa".to_owned());
    map
}

// ── The canonical form ────────────────────────────────────────────────────────────────────────────

#[test]
fn the_canonical_bytes_have_no_whitespace_and_a_fixed_key_order() {
    // ★ The property the whole signing scheme rests on. `serde_json::to_string` on a struct is a promise about field
    // order that a later refactor can break silently, and a signature that stopped verifying after an unrelated
    // change is indistinguishable from a tampered package.
    let canonical = String::from_utf8(subject().canonical_bytes()).expect("utf-8");
    assert_eq!(canonical, r#"{"manifest":"sha256-bbb","artifacts":{"plugin.wasm":"sha256-aaa"}}"#);
    assert!(!canonical.contains(' '), "whitespace would make the payload depend on a formatting option");
    assert!(!canonical.contains('\n'));
}

#[test]
fn the_artifact_order_is_the_maps_and_not_the_insertion_order() {
    // A list would make two packages with the same files in a different order have different signed bytes, so a
    // repackaging that changed nothing would invalidate a signature.
    let mut first = Digests::new();
    first.insert("z.wasm".to_owned(), "sha256-z".to_owned());
    first.insert("a.wasm", "sha256-a");

    let mut second = Digests::new();
    second.insert("a.wasm".to_owned(), "sha256-a".to_owned());
    second.insert("z.wasm".to_owned(), "sha256-z".to_owned());

    let one = SigningSubject { manifest: "m".to_owned(), artifacts: first };
    let two = SigningSubject { manifest: "m".to_owned(), artifacts: second };
    assert_eq!(one.canonical_bytes(), two.canonical_bytes());
}

#[test]
fn a_name_with_a_quote_in_it_is_escaped_by_the_json_rules() {
    // Otherwise two implementations read the same bytes as different payloads, and one of them verifies a signature
    // over something other than what it checked.
    let mut artifacts = Digests::new();
    artifacts.insert("a\"b\\c\n.wasm", "sha256-1");
    let canonical = String::from_utf8(SigningSubject { manifest: "m".to_owned(), artifacts }.canonical_bytes())
        .expect("utf-8");
    assert!(canonical.contains(r#"a\"b\\c\n.wasm"#), "{canonical}");
    // And it round-trips as JSON, which is what makes it the same bytes a conforming implementation produces.
    let parsed: serde_json::Value = serde_json::from_str(&canonical).expect("valid JSON");
    assert!(parsed.get("artifacts").is_some());
}

#[test]
fn an_empty_artifact_map_is_still_valid_json() {
    let canonical = String::from_utf8(
        SigningSubject { manifest: "m".to_owned(), artifacts: Digests::new() }.canonical_bytes(),
    )
    .expect("utf-8");
    assert_eq!(canonical, r#"{"manifest":"m","artifacts":{}}"#);
    let _: serde_json::Value = serde_json::from_str(&canonical).expect("valid JSON");
}

// ── Verifying ─────────────────────────────────────────────────────────────────────────────────────

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

// ── Checking a package ────────────────────────────────────────────────────────────────────────────

#[test]
fn a_signed_package_checks_out() {
    let text = signed(&subject(), "acme", 7);
    let outcome = check(Some(&text), &manifest(), &digests()).expect("a check");
    match outcome {
        SignatureCheck::Good { publisher_id, fingerprint, subject: signed_subject } => {
            assert_eq!(publisher_id, "acme");
            assert_eq!(fingerprint, Fingerprint::of(&key(7).verifying_key()));
            assert_eq!(signed_subject.manifest, "sha256-bbb");
        }
        other => panic!("expected a good check, got {other:?}"),
    }
}

#[test]
fn a_package_with_no_signature_says_so_rather_than_failing() {
    // An unsigned plugin is allowed — a user's own build has no publisher — but it is a distinct answer, because a
    // caller that showed it the same way as a signed one would be showing a check that did not happen.
    assert_eq!(check(None, &manifest(), &digests()).expect("a check"), SignatureCheck::None);
}

#[test]
fn an_artifact_the_signature_does_not_cover_is_a_bad_package() {
    // ★ A signature over a *subset* is a signature over a different package: a plugin whose manifest names two files
    // and whose signature covers one is one where the other can be replaced, and the signature still verifies.
    let mut partial = subject();
    partial.artifacts.clear();
    let text = signed(&partial, "acme", 7);

    assert_eq!(check(Some(&text), &manifest(), &digests()).expect("a check"), SignatureCheck::Bad);
}

#[test]
fn an_artifact_whose_digest_disagrees_with_the_signature_is_a_bad_package() {
    // The package was assembled from parts: the manifest is signed, the bytes are not the ones that were.
    let text = signed(&subject(), "acme", 7);
    let mut swapped = digests();
    let _ = swapped.insert("plugin.wasm".to_owned(), "sha256-something-else".to_owned());

    assert_eq!(check(Some(&text), &manifest(), &swapped).expect("a check"), SignatureCheck::Bad);
}

#[test]
fn an_extra_artifact_that_was_not_signed_is_a_bad_package() {
    // Adding a file to a signed package is the smallest possible tamper, and it has to be caught by the same check.
    let text = signed(&subject(), "acme", 7);
    let mut added = digests();
    let _ = added.insert("extra.wasm".to_owned(), "sha256-extra".to_owned());

    assert_eq!(check(Some(&text), &manifest(), &added).expect("a check"), SignatureCheck::Bad);
}

// ── The trust decision ────────────────────────────────────────────────────────────────────────────

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

// ── Fingerprints ──────────────────────────────────────────────────────────────────────────────────

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

#[test]
fn the_subject_says_which_manifest_artifacts_it_covers() {
    // The question a caller asks before concluding anything about a publisher.
    let subject = subject();
    assert!(subject.covers(&manifest()).is_empty(), "the fixture's artifact is covered");

    let mut bare = subject;
    bare.artifacts.clear();
    assert_eq!(bare.covers(&manifest()), vec!["plugin.wasm".to_owned()]);
}
