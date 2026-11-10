use synra_plugin_api::publisher::{Digests, Fingerprint, PublisherTrustStore};
use super::super::{Candidate, PluginTrust, Stage, VerifyError, verify};
use super::{Fixture, key, signed, subject};

#[test]
fn an_unsigned_package_is_refused_when_the_host_requires_one() {
    let fixture = Fixture::new();
    match verify(&fixture.candidate(None, true), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::Unsigned)) => assert_eq!(stage, Stage::Signature),
        other => panic!("expected an unsigned refusal, got {other:?}"),
    }
}

#[test]
fn a_tampered_subject_stops_at_the_signature() {
    // The document is valid JSON and the key is a key; what does not hold is the signature over the bytes.
    let fixture = Fixture::new();
    let mut document: serde_json::Value = serde_json::from_str(&signed(&subject(), "acme", 7)).expect("valid JSON");
    document["subject"]["artifacts"]["plugin.wasm"] = serde_json::json!("sha256-tampered");
    let text = document.to_string();

    match verify(&fixture.candidate(Some(&text), true), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::BadSignature { .. })) => assert_eq!(stage, Stage::Signature),
        other => panic!("expected a signature refusal, got {other:?}"),
    }
}

#[test]
fn a_genuine_signature_over_other_bytes_stops_at_the_signature() {
    // ★ The direction the previous test cannot reach: the document is untouched, the key is the publisher's, and the
    // signature genuinely verifies — over a package that is not this one. Before the subject was compared, this was
    // the whole attack: take a signed package, replace `plugin.wasm`, keep `signature.json`, and every check passed.
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let mut swapped = Digests::new();
    swapped.insert("plugin.wasm", "sha256-something-else");
    let candidate = Candidate { artifacts: &swapped, ..fixture.candidate(Some(&text), true) };

    match verify(&candidate, &PublisherTrustStore::new()) {
        Err((stage, VerifyError::SignatureCoversOtherBytes { detail })) => {
            assert_eq!(stage, Stage::Signature);
            assert!(detail.contains("plugin.wasm"), "{detail}");
            assert!(detail.contains("sha256-something-else"), "{detail}");
        }
        other => panic!("expected a coverage refusal, got {other:?}"),
    }
}

#[test]
fn a_manifest_edited_after_signing_stops_at_the_signature() {
    // The artifact still matches; the manifest the plugin declares is not the one that was signed — which is how a
    // capability gets added to a package whose signature nobody will look at again.
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let candidate = Candidate { manifest_digest: "sha256-edited", ..fixture.candidate(Some(&text), true) };

    match verify(&candidate, &PublisherTrustStore::new()) {
        Err((stage, VerifyError::SignatureCoversOtherBytes { detail })) => {
            assert_eq!(stage, Stage::Signature);
            assert!(detail.contains("manifest"), "{detail}");
        }
        other => panic!("expected a coverage refusal, got {other:?}"),
    }
}

#[test]
fn an_extra_artifact_the_signature_does_not_cover_is_refused() {
    // A signature over a subset is a signature over a different package: the file added afterwards is the half nobody
    // signed, and it is the half that would be swapped.
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let mut widened = fixture.artifacts.clone();
    widened.insert("ui.zip", "sha256-unsigned");
    let candidate = Candidate { artifacts: &widened, ..fixture.candidate(Some(&text), true) };

    match verify(&candidate, &PublisherTrustStore::new()) {
        Err((stage, VerifyError::SignatureCoversOtherBytes { detail })) => {
            assert_eq!(stage, Stage::Signature);
            assert!(detail.contains("ui.zip"), "{detail}");
        }
        other => panic!("expected a coverage refusal, got {other:?}"),
    }
}


#[test]
fn a_revoked_publisher_stops_at_the_trust_step_with_the_reason() {
    // ★ A refusal and not a warning: a revocation is a decision already made, and a user cannot consent past it.
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let mut store = PublisherTrustStore::new();
    store.revoke(Fingerprint::of(&key(7).verifying_key()), "malicious code");

    match verify(&fixture.candidate(Some(&text), true), &store) {
        Err((stage, VerifyError::UntrustedPublisher { why })) => {
            assert_eq!(stage, Stage::PublisherTrust);
            assert!(why.to_string().contains("malicious code"), "{why}");
        }
        other => panic!("expected a trust refusal, got {other:?}"),
    }
}

#[test]
fn an_unknown_publisher_passes_and_is_reported_so_the_interface_can_ask() {
    // ★ The pipeline does not decide who the user trusts: it reports what it found. A pipeline that failed here would
    // make the first install from anybody impossible.
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let report = verify(&fixture.candidate(Some(&text), true), &PublisherTrustStore::new()).expect("a report");

    assert!(report.is_acceptable());
    assert_eq!(report.trust, Some(PluginTrust::UnknownPublisher));
    assert_eq!(report.fingerprint, Some(Fingerprint::of(&key(7).verifying_key())));
    let trust_step = report
        .steps
        .iter()
        .find(|step| step.stage == Stage::PublisherTrust)
        .expect("a trust step");
    assert!(trust_step.detail.contains("asked"), "{}", trust_step.detail);
}

#[test]
fn a_publisher_this_device_trusts_is_reported_as_trusted() {
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let mut store = PublisherTrustStore::new();
    store.trust("acme", Fingerprint::of(&key(7).verifying_key()));

    let report = verify(&fixture.candidate(Some(&text), true), &store).expect("a report");
    assert_eq!(report.trust, Some(PluginTrust::TrustedPublisher));
    assert!(report.trust.expect("a level").is_trusted());
}

#[test]
fn a_signature_document_that_is_not_one_stops_at_the_signature() {
    let fixture = Fixture::new();
    for text in ["", "not json", "{}"] {
        match verify(&fixture.candidate(Some(text), true), &PublisherTrustStore::new()) {
            Err((stage, VerifyError::BadSignature { .. })) => assert_eq!(stage, Stage::Signature),
            other => panic!("{text} -> {other:?}"),
        }
    }
}
