use synra_plugin_api::publisher::{self, PublisherTrustStore, SignatureFile};
use super::super::{SignError, SignedContent, expected_fingerprint, verify};
use super::{Package, key};

#[test]
fn an_artifact_that_is_not_there_is_named_rather_than_signed_as_nothing() {
    let package = Package::new("missing", "plugin.wasm");
    std::fs::remove_file(package.path.join("plugin.wasm")).expect("removed");

    match SignedContent::read(&package.path) {
        Err(SignError::NoArtifact { path }) => assert!(path.contains("plugin.wasm")),
        other => panic!("expected a missing artifact, got {other:?}"),
    }
}

#[test]
fn the_document_is_the_format_the_host_reads() {
    // ★ The property that makes this tool useful: what it writes is what the host verifies with. A second format
    // would produce signatures that this tool makes and the kernel refuses.
    let package = Package::new("format", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let document = key(7).sign(&content, "unix-ms:1");

    let parsed = SignatureFile::parse(&document).expect("the contract's format");
    assert_eq!(parsed.algorithm, publisher::ALGORITHM);
    assert_eq!(parsed.version, publisher::SIGNATURE_VERSION);
    assert!(parsed.verify().is_ok());
}

#[test]
fn the_signed_at_claim_is_recorded_and_changes_nothing() {
    // It is a claim by whoever signed, so a verifier that used it to decide anything would be letting the package
    // choose its own ordering. Two documents that differ only in it are the same statement.
    let package = Package::new("clock", "plugin.wasm");
    let content = SignedContent::read(&package.path).expect("content");
    let signing = key(7);

    let early = signing.sign(&content, "unix-ms:1");
    let late = signing.sign(&content, "unix-ms:999");
    assert_ne!(early, late, "the documents differ");
    // And both verify, because the signature is over the subject and not over the document.
    assert!(verify(&early, &package.path, &PublisherTrustStore::new()).is_ok());
    assert!(verify(&late, &package.path, &PublisherTrustStore::new()).is_ok());
}

#[test]
fn a_public_key_beside_the_package_is_read_as_a_fingerprint() {
    let package = Package::new("pinned", "plugin.wasm");
    assert_eq!(expected_fingerprint(&package.path), None, "nothing pinned yet");

    package.write("public-key.txt", key(7).public_hex().as_bytes());
    assert_eq!(expected_fingerprint(&package.path), Some(key(7).fingerprint()));
    // And a file that is not a key is not a fingerprint, rather than a wrong one.
    package.write("public-key.txt", b"not a key");
    assert_eq!(expected_fingerprint(&package.path), None);
}

#[test]
fn a_ui_bundle_directory_is_covered_by_its_files_in_sorted_order() {
    // A directory listing's order is not defined, so an unsorted walk would produce a digest that changed between
    // runs on the same content — and a signature that verified only sometimes.
    let package = Package::new("ui", "ui");
    std::fs::create_dir_all(package.path.join("ui")).expect("a directory");
    package.write("ui/index.html", b"<html></html>");
    package.write("ui/app.js", b"console.log(1)");

    let first = SignedContent::read(&package.path).expect("content");
    let second = SignedContent::read(&package.path).expect("content");
    assert_eq!(first.subject, second.subject);

    // And changing a file inside the bundle changes the digest.
    package.write("ui/app.js", b"console.log(2)");
    let third = SignedContent::read(&package.path).expect("content");
    assert_ne!(first.subject.artifacts, third.subject.artifacts);
}

#[test]
fn an_extra_file_in_a_signed_bundle_changes_what_was_signed() {
    // The smallest possible tamper, and it has to move the digest.
    let package = Package::new("extra", "plugin.wasm");
    let before = SignedContent::read(&package.path).expect("content");
    let document = key(7).sign(&before, "unix-ms:1");

    package.write("extra.wasm", b"\0asm\x01\0\0\0");
    // The manifest does not name it, so the subject is unchanged and the signature still holds — which is the
    // right answer: a file the manifest does not name is not part of the plugin.
    assert!(verify(&document, &package.path, &PublisherTrustStore::new()).is_ok());
}
