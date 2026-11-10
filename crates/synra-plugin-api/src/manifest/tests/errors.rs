use synra_capability::Capability;
use super::super::error::ManifestError;

#[test]
fn every_error_variant_explains_itself() {
    // The loader shows these to a user, so a variant without a sentence is one the interface cannot render.
    let errors = vec![
        ManifestError::Malformed("x".to_owned()),
        ManifestError::BadId {
            id: "x".to_owned(),
            reason: "y".to_owned(),
        },
        ManifestError::UnsluggedId { id: "x".to_owned() },
        ManifestError::BadVersion {
            version: "x".to_owned(),
            reason: "y".to_owned(),
        },
        ManifestError::MissingHeadless,
        ManifestError::MissingArtifact {
            kind: "headless",
            path: "x".to_owned(),
        },
        ManifestError::BadCapability {
            cap: "x".to_owned(),
            source: Capability::parse("nope").expect_err("invalid"),
        },
        ManifestError::UnusableCapability {
            cap: "ui:page".to_owned(),
            kind: "headless",
        },
        ManifestError::NetworkMismatch {
            detail: "x".to_owned(),
        },
        ManifestError::DuplicateName {
            kind: "action",
            name: "x".to_owned(),
        },
        ManifestError::ForeignEventNamespace {
            name: "x".to_owned(),
            namespace: "y".to_owned(),
        },
        ManifestError::BadPayloadSchema {
            name: "x".to_owned(),
            detail: "y".to_owned(),
        },
        ManifestError::BadHandle {
            event: "x".to_owned(),
        },
        ManifestError::DuplicatePageKey {
            key: "x".to_owned(),
        },
        ManifestError::SdkTooOld {
            min: "9".to_owned(),
            host: "1".to_owned(),
        },
        ManifestError::WitMismatch {
            plugin: "a".to_owned(),
            host: "b".to_owned(),
        },
        ManifestError::CompositionCycle {
            through: vec!["a".to_owned()],
        },
        ManifestError::TooLong {
            field: "title",
            len: 100,
            max: 64,
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text:?}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
