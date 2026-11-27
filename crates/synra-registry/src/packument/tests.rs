use super::{Packument, PackumentError};

const DOCUMENT: &str = r#"{
        "name": "@synra-plugin/chat",
        "dist-tags": { "latest": "1.2.0", "beta": "1.3.0-beta.1" },
        "versions": {
            "1.2.0": {
                "name": "@synra-plugin/chat",
                "version": "1.2.0",
                "dist": {
                    "tarball": "https://registry.example.com/@synra-plugin/chat/-/chat-1.2.0.tgz",
                    "integrity": "sha512-abc"
                }
            },
            "1.3.0-beta.1": {
                "name": "@synra-plugin/chat",
                "version": "1.3.0-beta.1",
                "dist": { "tarball": "https://registry.example.com/@synra-plugin/chat/-/chat-1.3.0-beta.1.tgz" }
            }
        }
    }"#;

#[test]
fn the_latest_tag_chooses_the_version() {
    // ★ Not the highest key: the publisher sets `latest`, and a client that sorted versions itself would install one
    // the publisher deliberately did not tag.
    let packument = Packument::parse(DOCUMENT).expect("a document");
    let latest = packument.latest().expect("a latest");
    assert_eq!(latest.version, "1.2.0");
    assert_eq!(
        latest.dist.tarball,
        "https://registry.example.com/@synra-plugin/chat/-/chat-1.2.0.tgz"
    );
    assert_eq!(latest.dist.integrity.as_deref(), Some("sha512-abc"));
}

#[test]
fn a_named_version_is_read_even_when_it_is_not_latest() {
    let packument = Packument::parse(DOCUMENT).expect("a document");
    let beta = packument.at("1.3.0-beta.1").expect("the beta");
    assert_eq!(beta.version, "1.3.0-beta.1");
    let names: Vec<&str> = packument.version_names().collect();
    assert_eq!(names, ["1.2.0", "1.3.0-beta.1"], "ordered by the document");
}

#[test]
fn a_tag_naming_a_version_the_document_lacks_is_not_a_latest() {
    // A registry that lost a version — or a document still being written — must not make a client fall back to
    // whichever key sorts last.
    let document = r#"{
            "name": "x",
            "dist-tags": { "latest": "9.9.9" },
            "versions": { "1.0.0": { "name": "x", "version": "1.0.0", "dist": { "tarball": "https://e/x.tgz" } } }
        }"#;
    let packument = Packument::parse(document).expect("a document");
    assert!(packument.latest().is_none());
    assert!(packument.at("1.0.0").is_some());
}

#[test]
fn something_that_is_not_a_packument_is_a_named_refusal() {
    assert!(matches!(
        Packument::parse("not json"),
        Err(PackumentError::Unreadable(_))
    ));
    assert!(matches!(
        Packument::parse(r#"{"name": "x"}"#),
        Ok(packument) if packument.latest().is_none()
    ));
}

#[test]
fn only_a_genuinely_newer_version_is_an_update() {
    let packument = Packument::parse(DOCUMENT).expect("a document");
    for older in ["1.1.0", "1.2.0-rc.1"] {
        assert_eq!(
            packument.latest_upgrade(older).unwrap().unwrap().version,
            "1.2.0"
        );
    }
    for current in ["1.2.0", "1.2.0+build.9", "1.10.0"] {
        assert!(packument.latest_upgrade(current).unwrap().is_none());
    }
    assert!(matches!(
        packument.latest_upgrade("2026-10-19"),
        Err(super::SelectError::InvalidVersion(_))
    ));

    let corrupt = Packument::parse(&DOCUMENT.replace("1.2.0", "1.0.0-01")).unwrap();
    assert!(matches!(
        corrupt.latest_upgrade("1.0.0"),
        Err(super::SelectError::InvalidVersion(_))
    ));
    assert!(matches!(
        corrupt.select(None),
        Err(super::SelectError::InvalidVersion(_))
    ));
}

#[test]
fn a_range_picks_the_newest_matching_version() {
    // ★ `1.10.0` sorts before `1.9.0` as a string and after it as a version; the whole reason this uses semver.
    let document = serde_json::json!({
        "name": "x",
        "dist-tags": { "latest": "1.9.0" },
        "versions": {
            "1.9.0": { "name": "x", "version": "1.9.0", "dist": { "tarball": "https://e/x-1.9.0.tgz" } },
            "1.10.0": { "name": "x", "version": "1.10.0", "dist": { "tarball": "https://e/x-1.10.0.tgz" } },
            "2.0.0": { "name": "x", "version": "2.0.0", "dist": { "tarball": "https://e/x-2.0.0.tgz" } }
        }
    })
    .to_string();
    let packument = Packument::parse(&document).expect("a document");

    assert_eq!(
        packument.select(Some("^1.9")).expect("a match").version,
        "1.10.0"
    );
    assert_eq!(
        packument.select(Some("~1.9.0")).expect("a match").version,
        "1.9.0"
    );
    assert_eq!(
        packument.select(Some("1.10.0")).expect("exact").version,
        "1.10.0"
    );
    assert_eq!(packument.select(None).expect("latest").version, "1.9.0");
    assert_eq!(
        packument.select(Some("latest")).expect("latest").version,
        "1.9.0"
    );
    assert!(matches!(
        packument.select(Some("1.8.0")),
        Err(super::SelectError::NoSuchVersion(_, _))
    ));
    assert!(matches!(
        packument.select(Some("^2")),
        Ok(version) if version.version == "2.0.0"
    ));
    assert!(matches!(
        packument.select(Some("^3")),
        Err(super::SelectError::NoSuchVersion(_, _))
    ));
}

#[test]
fn a_request_that_is_neither_a_version_nor_a_range_is_named() {
    let packument = Packument::parse(DOCUMENT).expect("a document");
    assert!(matches!(
        packument.select(Some("not-a-version")),
        Err(super::SelectError::NoSuchVersion(_, _))
    ));
}

#[test]
fn a_document_without_a_latest_cannot_be_asked_for_nothing() {
    let packument = Packument::parse(r#"{"name": "x"}"#).expect("a document");
    assert!(matches!(
        packument.select(None),
        Err(super::SelectError::NoLatest(_))
    ));
}
