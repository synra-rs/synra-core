use synra_plugin_api::publisher::{self, PublisherTrustStore};
use super::super::{SignError, SignedContent, verify};
use super::{Package, key};

#[test]
fn a_signed_package_verifies_against_its_own_bytes() {
    // The round trip, from both sides: what `sign` writes is what `verify` reads, and the digests in between are
    // of the bytes on disk.
    let package = Package::new("hello", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    assert_eq!(content.plugin_id, "@acme/hello");
    assert_eq!(content.publisher_id, "acme");
    assert_eq!(content.subject.artifacts.len(), 1);
    assert!(content.subject.artifacts.contains("plugin.wasm"));
    assert!(content.subject.manifest.starts_with("sha256-"), "an SRI digest");

    let signing = key(7);
    let document = signing.sign(&content, "unix-ms:1");
    let verified = verify(&document, &package.path, &PublisherTrustStore::new()).expect("verified");
    assert_eq!(verified.plugin_id, "@acme/hello");
    assert_eq!(verified.publisher_id, "acme");
    assert_eq!(verified.fingerprint, signing.fingerprint());
}

#[test]
fn an_artifact_changed_after_signing_does_not_verify() {
    // ★ The one outcome that is never a warning: either the package was altered after signing or it was signed
    // over something else.
    let package = Package::new("changed", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let document = key(7).sign(&content, "unix-ms:1");

    package.write("plugin.wasm", b"\0asm\x01\0\0\0\xff");
    assert_eq!(
        verify(&document, &package.path, &PublisherTrustStore::new()),
        Err(SignError::Mismatch)
    );
}

#[test]
fn a_manifest_changed_after_signing_does_not_verify() {
    // The manifest is what decides what the plugin *is*, so a signature that did not cover it would let a plugin
    // asking for `storage` be substituted for one that does not.
    let package = Package::new("manifest", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let document = key(7).sign(&content, "unix-ms:1");

    let text = package.read("manifest.json").replace("Hello", "Something else");
    package.write("manifest.json", text.as_bytes());
    assert_eq!(
        verify(&document, &package.path, &PublisherTrustStore::new()),
        Err(SignError::Mismatch)
    );
}

#[test]
fn a_document_signed_by_another_key_does_not_verify() {
    let package = Package::new("stranger", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let document = key(7).sign(&content, "unix-ms:1");
    // The document is intact; the key inside it is not the one that signed it, because it was edited.
    let swapped = document.replace(&key(7).public_base64(), &key(9).public_base64());

    assert_eq!(
        verify(&swapped, &package.path, &PublisherTrustStore::new()),
        Err(SignError::Mismatch)
    );
}

#[test]
fn a_revoked_publisher_is_refused_rather_than_reported_as_a_mismatch() {
    // The two answers have different next steps: "the bytes changed" is a corrupt download, "this key is revoked"
    // is a decision, and a caller that folded them together would offer a retry for something no retry fixes.
    let package = Package::new("revoked", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let signing = key(7);
    let document = signing.sign(&content, "unix-ms:1");

    let mut store = PublisherTrustStore::new();
    store.revoke(signing.fingerprint(), "malicious code");
    match verify(&document, &package.path, &store) {
        Err(SignError::Untrusted { why }) => assert!(why.to_string().contains("malicious code")),
        other => panic!("expected a revocation, got {other:?}"),
    }
}

#[test]
fn a_publisher_whose_key_changed_is_refused() {
    let package = Package::new("rotated", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let document = key(7).sign(&content, "unix-ms:1");

    let mut store = PublisherTrustStore::new();
    store.trust("acme", key(9).fingerprint());
    match verify(&document, &package.path, &store) {
        Err(SignError::Untrusted { why }) => assert!(why.to_string().contains("known with key")),
        other => panic!("expected a key-change refusal, got {other:?}"),
    }
}

#[test]
fn a_publisher_the_device_already_trusts_is_reported_as_trusted() {
    let package = Package::new("trusted", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let signing = key(7);
    let document = signing.sign(&content, "unix-ms:1");

    let mut store = PublisherTrustStore::new();
    store.trust("acme", signing.fingerprint());
    let verified = verify(&document, &package.path, &store).expect("verified");
    assert!(verified.trust.is_trusted());
    assert!(!verified.trust.is_refusal());
}

#[test]
fn a_first_install_is_a_question_rather_than_a_refusal() {
    let package = Package::new("first", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let document = key(7).sign(&content, "unix-ms:1");

    let verified = verify(&document, &package.path, &PublisherTrustStore::new()).expect("verified");
    assert_eq!(verified.trust, publisher::PluginTrust::UnknownPublisher);
    assert!(!verified.trust.is_trusted());
    assert!(!verified.trust.is_refusal());
}

#[test]
fn a_document_that_is_not_a_document_is_refused_rather_than_read() {
    let package = Package::new("garbage", "plugin.wasm");
    for wrong in ["", "not json", "{}"] {
        assert!(matches!(
            verify(wrong, &package.path, &PublisherTrustStore::new()),
            Err(SignError::DocumentUnreadable { .. })
        ));
    }
}
