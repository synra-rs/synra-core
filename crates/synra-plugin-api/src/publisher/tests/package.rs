use super::super::{Fingerprint, SignatureCheck, check};
use super::{digests, key, manifest, signed, subject};

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

#[test]
fn the_subject_says_which_manifest_artifacts_it_covers() {
    // The question a caller asks before concluding anything about a publisher.
    let subject = subject();
    assert!(subject.covers(&manifest()).is_empty(), "the fixture's artifact is covered");

    let mut bare = subject;
    bare.artifacts.clear();
    assert_eq!(bare.covers(&manifest()), vec!["plugin.wasm".to_owned()]);
}
