//! The registry rules, driven from the side that gets them wrong.
//!
//! The two assertions that matter most are negative: an integrity failure must **not** fall through to another mirror,
//! and an exact override must **not** fall back to the public registry. Both are tested by building the configuration
//! that would do it and asserting the refusal.

use sha2::{Sha256, Sha384, Sha512};
use super::*;

fn config() -> RegistryConfig {
    RegistryConfig::new()
}

// ── Mirror resolution ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_configuration_with_nothing_but_a_default_has_one_place_to_look() {
    let order = config().resolve("@acme/chat");
    assert_eq!(order, vec![DEFAULT_REGISTRY.to_owned()]);
}

#[test]
fn mirrors_are_tried_by_priority_and_the_default_is_last() {
    let config = config()
        .with_mirror(RegistryMirror::new("https://slow.example", 90))
        .with_mirror(RegistryMirror::new("https://fast.example", 10))
        .with_mirror(RegistryMirror::new("https://middle.example", 50));

    assert_eq!(
        config.resolve("@acme/chat"),
        vec![
            "https://fast.example".to_owned(),
            "https://middle.example".to_owned(),
            "https://slow.example".to_owned(),
            DEFAULT_REGISTRY.to_owned(),
        ]
    );
}

#[test]
fn two_mirrors_at_one_priority_keep_the_order_they_were_configured_in() {
    // "Last one configured wins" is an ordering nobody reading a configuration file can predict, so the sort is
    // stable and the declaration order decides.
    let config = config()
        .with_mirror(RegistryMirror::new("https://first.example", 10))
        .with_mirror(RegistryMirror::new("https://second.example", 10));

    let order = config.resolve("@acme/chat");
    assert_eq!(order.first().map(String::as_str), Some("https://first.example"));
    assert_eq!(order.get(1).map(String::as_str), Some("https://second.example"));
}

#[test]
fn a_disabled_mirror_is_not_tried() {
    let config = config()
        .with_mirror(RegistryMirror::new("https://off.example", 1).disabled())
        .with_mirror(RegistryMirror::new("https://on.example", 2));

    assert_eq!(config.resolve("@acme/chat"), vec!["https://on.example".to_owned(), DEFAULT_REGISTRY.to_owned()]);
}

#[test]
fn an_exact_override_is_the_only_place_a_package_is_looked_for() {
    // ★ A decision, not a preference. Falling back from a mirror the user configured for a package to a public
    // registry is how a private package's name gets asked for in public.
    let config = config().with_override(PackagePattern::new("@acme/secret"), "https://private.example");
    assert_eq!(config.resolve("@acme/secret"), vec!["https://private.example".to_owned()]);
    // And a package it does not name still gets the ordinary order.
    assert_eq!(config.resolve("@acme/other"), vec![DEFAULT_REGISTRY.to_owned()]);
}

#[test]
fn an_exact_override_wins_over_a_wildcard_one() {
    let config = config()
        .with_override(PackagePattern::new("@acme/*"), "https://scope.example")
        .with_override(PackagePattern::new("@acme/one"), "https://exact.example");

    assert_eq!(config.resolve("@acme/one"), vec!["https://exact.example".to_owned()]);
    assert_eq!(config.resolve("@acme/two"), vec!["https://scope.example".to_owned()]);
    // And the exact one is found even when it is declared second, which is what "exact > wildcard" means.
    let reversed = RegistryConfig::new()
        .with_override(PackagePattern::new("@acme/one"), "https://exact.example")
        .with_override(PackagePattern::new("@acme/*"), "https://scope.example");
    assert_eq!(reversed.resolve("@acme/one"), vec!["https://exact.example".to_owned()]);
}

#[test]
fn a_pattern_matches_what_it_says_and_nothing_else() {
    let exact = PackagePattern::new("@acme/chat");
    assert!(exact.matches("@acme/chat"));
    assert!(!exact.matches("@acme/chatty"), "an exact pattern is not a prefix");
    assert!(exact.is_exact());

    let wildcard = PackagePattern::new("@acme/*");
    assert!(wildcard.matches("@acme/chat"));
    assert!(wildcard.matches("@acme/"));
    assert!(!wildcard.matches("@other/chat"));
    assert!(!wildcard.is_exact());
    assert_eq!(wildcard.as_str(), "@acme/*");

    // Case matters, because a package name is a string a registry compares byte for byte.
    assert!(!PackagePattern::new("@acme/*").matches("@Acme/chat"));
}

#[test]
fn the_default_is_not_listed_twice_when_a_mirror_points_at_it() {
    let config = config().with_mirror(RegistryMirror::new(DEFAULT_REGISTRY, 1));
    assert_eq!(config.resolve("@acme/chat"), vec![DEFAULT_REGISTRY.to_owned()]);
}

// ── The packument ─────────────────────────────────────────────────────────────────────────────────

fn packument_json() -> Vec<u8> {
    serde_json::json!({
        "name": "@acme/chat",
        "dist-tags": { "latest": "1.10.0" },
        "versions": {
            "1.9.0": { "version": "1.9.0", "dist": { "tarball": "https://r/chat-1.9.0.tgz", "integrity": "sha512-abc" } },
            "1.10.0": {
                "version": "1.10.0",
                "dist": {
                    "tarball": "https://r/chat-1.10.0.tgz",
                    "integrity": "sha512-def",
                    "synra": {
                        "manifestDigest": "sha256-m",
                        "artifacts": { "plugin.wasm": "sha256-a" },
                        "capabilities": ["device:send:*", "storage:local:read"],
                        "size": { "wasm": 1234, "ui": 56 }
                    }
                }
            }
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn a_packument_parses_and_answers_what_it_holds() {
    let packument = Packument::parse("@acme", &packument_json()).expect("a packument");
    assert_eq!(packument.name, "@acme/chat");
    assert_eq!(packument.versions.len(), 2);

    let latest = packument.tagged("latest").expect("the latest tag");
    assert_eq!(latest.version, "1.10.0");
    assert_eq!(latest.dist.tarball, "https://r/chat-1.10.0.tgz");
    assert_eq!(latest.dist.integrity.as_deref(), Some("sha512-def"));

    let synra = latest.dist.synra.as_ref().expect("the synra block");
    assert_eq!(synra.capabilities, vec!["device:send:*", "storage:local:read"]);
    assert_eq!(synra.size, Some(SizeBlock { wasm: 1_234, ui: 56 }));
    assert_eq!(synra.manifest_digest.as_deref(), Some("sha256-m"));
    assert!(synra.signature.is_none(), "this registry sent no inline signature");
}

#[test]
fn a_version_is_found_by_its_number_and_by_its_tag() {
    let packument = Packument::parse("@acme", &packument_json()).expect("a packument");
    assert_eq!(packument.version("@acme/chat", "1.9.0").expect("a version").version, "1.9.0");
    // A tag resolves to the version it points at, which is how a caller asks for `latest`.
    assert_eq!(packument.version("@acme/chat", "latest").expect("a version").version, "1.10.0");
}

#[test]
fn a_version_that_does_not_exist_says_what_there_is() {
    // A caller's next step is to pick one of them, so "no such version" without the list leaves them guessing.
    let packument = Packument::parse("@acme", &packument_json()).expect("a packument");
    match packument.version("@acme/chat", "2.0.0") {
        Err(FetchFailure::NoSuchVersion { package, wanted, available }) => {
            assert_eq!(package, "@acme/chat");
            assert_eq!(wanted, "2.0.0");
            assert!(available.contains("1.9.0") && available.contains("1.10.0"), "{available}");
        }
        other => panic!("expected a missing version, got {other:?}"),
    }
    assert!(!packument.version("@acme/chat", "2.0.0").expect_err("absent").allows_fallback());
}

#[test]
fn the_newest_version_compares_numbers_and_not_text() {
    // ★ `1.10.0` sorts before `1.9.0` as text, and picking the wrong one ships an old version to everybody. This is
    // the fallback for a mirror that sent no `latest` tag.
    let packument = Packument::parse("@acme", &packument_json()).expect("a packument");
    assert_eq!(packument.newest().expect("a version").version, "1.10.0");

    assert_eq!(compare_versions("1.10.0", "1.9.0"), core::cmp::Ordering::Greater);
    assert_eq!(compare_versions("2.0.0", "10.0.0"), core::cmp::Ordering::Less);
    assert_eq!(compare_versions("1.0.0", "1.0.0"), core::cmp::Ordering::Equal);
    // A release is newer than its own pre-releases, which is the one semantic rule that matters here.
    assert_eq!(compare_versions("1.0.0", "1.0.0-rc.1"), core::cmp::Ordering::Greater);
    assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0"), core::cmp::Ordering::Less);
    // And two pre-releases of one version are not ordered, which is the honest answer for a comparison that is not a
    // semver implementation.
    assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0-rc.2"), core::cmp::Ordering::Equal);
}

#[test]
fn a_packument_that_is_not_json_is_refused_with_the_parsers_reason() {
    for bytes in [&b"not json"[..], &b""[..], &b"{}"[..]] {
        match Packument::parse("@acme", bytes) {
            Err(FetchFailure::Malformed { registry, reason }) => {
                assert_eq!(registry, "@acme");
                assert!(!reason.is_empty());
            }
            other => panic!("{bytes:?} -> {other:?}"),
        }
    }
}

#[test]
fn a_packument_larger_than_the_bound_is_refused_before_it_is_parsed() {
    // The response is read into memory before anything parses it, so a server that answers with a stream of bytes is
    // a server that decides how much memory the kernel uses.
    let huge = vec![b' '; MAX_PACKUMENT_BYTES + 1];
    match Packument::parse("@acme", &huge) {
        Err(FetchFailure::Malformed { reason, .. }) => assert!(reason.contains("limit"), "{reason}"),
        other => panic!("expected a size refusal, got {other:?}"),
    }
}

#[test]
fn a_packument_listing_too_many_versions_is_refused() {
    let mut versions = serde_json::Map::new();
    for index in 0..(MAX_VERSIONS + 1) {
        let _ = versions.insert(
            format!("1.{index}.0"),
            serde_json::json!({ "version": format!("1.{index}.0"), "dist": { "tarball": "https://r/x.tgz" } }),
        );
    }
    let bytes = serde_json::json!({ "name": "@acme/chat", "versions": versions }).to_string().into_bytes();
    match Packument::parse("@acme", &bytes) {
        Err(FetchFailure::Malformed { reason, .. }) => assert!(reason.contains("versions"), "{reason}"),
        other => panic!("expected a count refusal, got {other:?}"),
    }
}

// ── Integrity ─────────────────────────────────────────────────────────────────────────────────────

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
