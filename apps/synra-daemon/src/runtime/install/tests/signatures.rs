use super::*;

#[test]
fn the_signature_file_travels_with_the_package() {
    let dir = TempDir::new("install-signed");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    // Not a valid document: this asserts that the file is *carried*, and a package that ships one is refused by the
    // pipeline rather than by this copy step — which is the next test's subject.
    std::fs::write(source.join("signature.json"), "{}").expect("a signature file");
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "signature");
    assert!(!plugins(dir.path()).join("@acme/hello").exists(), "a refused install writes nothing");
    assert!(db.plugins().expect("the table").is_empty(), "a refused install records nothing");
}

#[test]
fn a_signed_package_with_a_genuine_signature_installs() {
    // The control for the refusal below, and the one that caught a defect: the install pipeline computed the manifest's
    // digest as an SRI string while the CLI signs it in hex, so every genuinely signed package looked like one whose
    // signature covered a different document. Without this test the first signed install in the field would have been
    // the first time anyone found out.
    let dir = TempDir::new("install-signed-good");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    crate::runtime::tests::sign_plugin(&source, false);
    let mut db = database();

    let installed = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect("installs");

    assert!(installed.path.join("signature.json").is_file(), "the signature travels with it");
    assert!(installed.warnings.is_empty(), "{:?}", installed.warnings);
    // ★ The publisher is recorded as "seen", not "trusted": the key signed this package, and only a user can decide
    // whether it is a key they trust.
    let publishers = db.publishers().expect("the publisher table");
    assert_eq!(publishers.len(), 1);
    assert_eq!(publishers[0].publisher_id, "@acme");
    assert_eq!(publishers[0].trust, synra_store::TRUST_SEEN);
    // ★ The fingerprint travels with the result, because the interface's next question is "do you trust this key?" and a
    // caller that had to re-read the signature would be reading a copy the install already checked.
    let signed = installed.signed_by.expect("a signed package names its signer");
    assert_eq!(signed.publisher_id, "@acme");
    assert!(!signed.fingerprint.is_empty(), "the fingerprint is what a person compares");
}

#[test]
fn a_signed_package_whose_signature_covers_other_bytes_is_refused_at_the_signature() {
    let dir = TempDir::new("install-signed-swapped");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    crate::runtime::tests::sign_plugin(&source, true);
    let mut db = database();

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 1_000).expect_err("refused");

    assert_eq!(refusal.stage, "signature", "{}", refusal.reason);
    assert!(refusal.reason.contains("different bytes"), "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
    assert!(db.plugins().expect("the table").is_empty());
}

#[test]
fn a_revoked_publisher_is_refused_even_with_a_valid_signature() {
    // ★ A revocation is not a cryptographic fact — the signature is genuine — so it is checked at the publisher-trust
    // step, from the table. Without loading that table every revoked key would install again.
    let dir = TempDir::new("install-revoked");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    crate::runtime::tests::sign_plugin(&source, false);
    let mut db = database();

    let text = std::fs::read_to_string(source.join("signature.json")).expect("a signature");
    let document = synra_plugin_api::publisher::SignatureFile::parse(&text).expect("a document");
    let synra_plugin_api::publisher::VerifyOutcome::Good { fingerprint } =
        document.verify().expect("a genuine signature")
    else {
        panic!("the fixture must sign correctly");
    };
    db.record_publisher("@acme", fingerprint.as_str(), &document.pubkey, 1_000)
        .expect("the publisher is known");
    db.set_publisher_trust("@acme", fingerprint.as_str(), synra_store::TRUST_REVOKED, 2_000)
        .expect("the key is revoked");

    let refusal = from_directory(&mut db, &backend(), &plugins(dir.path()), &source, 3_000)
        .expect_err("a revoked key must not install");

    assert_eq!(refusal.stage, "publisher-trust", "{}", refusal.reason);
    assert!(!plugins(dir.path()).join("@acme/hello").exists());
}
