use super::*;

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
