use super::*;

#[test]
fn a_tarball_that_hashes_to_what_was_declared_is_accepted() {
    use base64::Engine as _;
    use sha2::Digest as _;

    let bytes = b"the tarball's bytes";
    let digest = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha512::digest(bytes));
    let declared = format!("sha512-{digest}");

    let checked = check_integrity("https://r", &declared, bytes).expect("it matches");
    assert_eq!(checked.algorithm, "sha512");
    assert!(checked.matches(bytes));
    assert_eq!(checked.as_str(), declared);
}

#[test]
fn a_tarball_that_does_not_hash_to_what_was_declared_is_refused() {
    use base64::Engine as _;
    use sha2::Digest as _;

    let declared = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha512::digest(b"the published bytes"))
    );
    match check_integrity("https://r", &declared, b"the substituted bytes") {
        Err(FetchFailure::IntegrityMismatch { registry, declared: reported }) => {
            assert_eq!(registry, "https://r");
            assert_eq!(reported, declared);
        }
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

#[test]
fn an_integrity_failure_is_the_one_failure_that_never_falls_through() {
    // ★ The rule this module exists for. Trying the next mirror after an integrity failure is not resilience: it is
    // asking a different server to tell you what the first one would not, which is what an attacker who can answer
    // for one mirror wants.
    let mismatch = FetchFailure::IntegrityMismatch {
        registry: "https://r".to_owned(),
        declared: "sha512-x".to_owned(),
    };
    assert!(!mismatch.allows_fallback());
    assert!(!mismatch.is_retryable_here(), "the same bytes hash the same way");
    assert_eq!(mismatch.registry(), "https://r");

    // And the failures that do fall through, each for its own reason.
    let network = FetchFailure::Network { registry: "https://r".to_owned(), reason: "timed out".to_owned() };
    assert!(network.allows_fallback());
    assert!(network.is_retryable_here());
    assert!(FetchFailure::NotFound { registry: "r".to_owned(), package: "p".to_owned() }.allows_fallback());
    assert!(
        FetchFailure::RateLimited { registry: "r".to_owned(), retry_after_secs: Some(30) }.allows_fallback()
    );
    assert!(FetchFailure::Malformed { registry: "r".to_owned(), reason: "x".to_owned() }.allows_fallback());
    let missing = FetchFailure::NoSuchVersion {
        package: "p".to_owned(),
        wanted: "2".to_owned(),
        available: "1".to_owned(),
    };
    assert!(!missing.allows_fallback(), "every mirror has the same versions");
    assert_eq!(missing.registry(), "", "a missing version is not a mirror's fault");
    assert!(!missing.is_retryable_here());
}

#[test]
fn every_algorithm_npm_publishes_is_one_this_build_computes() {
    // A verifier that had to be told which algorithm to use could be told the wrong one, so the algorithm is part of
    // the digest and all three of npm's are implemented.
    use base64::Engine as _;
    use sha2::Digest as _;

    let bytes = b"x";
    for (algorithm, digest) in [
        ("sha256", base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(bytes))),
        ("sha384", base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha384::digest(bytes))),
        ("sha512", base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha512::digest(bytes))),
    ] {
        let declared = format!("{algorithm}-{digest}");
        assert!(check_integrity("https://r", &declared, bytes).is_ok(), "{algorithm}");
    }
}

#[test]
fn an_integrity_string_nobody_can_check_is_refused_rather_than_ignored() {
    // ★ An integrity string that a verifier skips reads as "no integrity", and that is the answer that lets a
    // substituted tarball through.
    for text in [
        "",
        "sha512",
        "md5-abc",
        "SHA-1-abc",
        "sha512-",
        "sha512-not base64!",
        // A base64 string of the wrong length for the algorithm it claims.
        "sha512-YWJj",
        "sha256-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo",
    ] {
        match Integrity::parse("https://r", text) {
            Err(FetchFailure::Malformed { .. }) => {}
            other => panic!("{text:?} was accepted: {other:?}"),
        }
    }
}

#[test]
fn a_digest_with_padding_is_the_same_digest() {
    // SRI drops the padding and some servers put it back, and a verifier that compared the text would refuse a
    // perfectly good tarball.
    use base64::Engine as _;
    use sha2::Digest as _;

    let bytes = b"the bytes";
    let unpadded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha512::digest(bytes));
    let padded = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
    assert!(padded.ends_with('='), "the fixture must have padding to be about padding");

    let declared = format!("sha512-{padded}");
    let parsed = Integrity::parse("https://r", &declared).expect("it parses");
    assert_eq!(parsed.digest, unpadded, "the padding is dropped");
    assert!(parsed.matches(bytes));
}

#[test]
fn the_algorithm_is_read_from_the_digest_and_not_guessed() {
    // An SRI that names sha256 is checked with sha256, whatever the same bytes would hash to under another algorithm.
    use base64::Engine as _;
    use sha2::Digest as _;

    let bytes = b"the bytes";
    let as_sha256 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(bytes));
    let parsed = Integrity::parse("https://r", &format!("sha256-{as_sha256}")).expect("it parses");
    assert_eq!(parsed.algorithm, "sha256");
    assert!(parsed.matches(bytes));

    // The same digest under the wrong name does not match, because the check uses the named algorithm.
    let wrong = Integrity { algorithm: "sha512".to_owned(), digest: as_sha256 };
    assert!(!wrong.matches(bytes));
}

#[test]
fn every_failure_explains_itself() {
    let failures = [
        FetchFailure::Network { registry: "https://r".to_owned(), reason: "timed out".to_owned() },
        FetchFailure::NotFound { registry: "https://r".to_owned(), package: "@a/b".to_owned() },
        FetchFailure::RateLimited { registry: "https://r".to_owned(), retry_after_secs: Some(30) },
        FetchFailure::IntegrityMismatch { registry: "https://r".to_owned(), declared: "sha512-x".to_owned() },
        FetchFailure::Malformed { registry: "https://r".to_owned(), reason: "not json".to_owned() },
        FetchFailure::NoSuchVersion {
            package: "@a/b".to_owned(),
            wanted: "2.0.0".to_owned(),
            available: "1.0.0".to_owned(),
        },
    ];
    for failure in &failures {
        let sentence = failure.to_string();
        assert!(sentence.len() > 15, "{failure:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
        assert!(!sentence.contains('}'), "{sentence}");
    }
    // The two that name the package name it, which is what a user needs.
    assert!(failures[1].to_string().contains("@a/b"));
    assert!(failures[5].to_string().contains("1.0.0"));
}
