use super::*;
use serde_json::json;

#[test]
fn absence_is_distinct_from_a_malformed_mirror() {
    for value in [None, Some(json!("")), Some(json!("  ")), Some(json!([]))] {
        assert!(
            RegistryConfig::parse(value.as_ref())
                .unwrap()
                .sources()
                .is_empty()
        );
    }
    for value in [json!(123), json!({}), json!(null)] {
        assert_eq!(
            RegistryConfig::parse(Some(&value)).unwrap_err(),
            ConfigError {
                index: None,
                reason: ConfigReason::ValueType,
            }
        );
    }
    for bad in [json!(123), json!(null), json!(" "), json!({})] {
        let value = json!(["https://registry.example", bad, "https://mirror.example"]);
        assert_eq!(
            RegistryConfig::parse(Some(&value)).unwrap_err(),
            ConfigError {
                index: Some(1),
                reason: ConfigReason::MirrorType,
            }
        );
    }
}

#[test]
fn normalized_sources_preserve_protocol_path_and_mirror_order() {
    let config = RegistryConfig::parse(Some(&json!([
        " HTTPS://Registry.Example:443/ ",
        "static:https://bucket.example/plugins/",
        "http://[::1]:4123/"
    ])))
    .unwrap();
    let sources = config.sources();
    assert_eq!(
        sources.iter().map(RegistrySource::url).collect::<Vec<_>>(),
        [
            "https://registry.example",
            "https://bucket.example/plugins",
            "http://[::1]:4123",
        ]
    );
    assert_eq!(sources[1].kind(), RegistryKind::Static);
    assert_eq!(sources[2].host(), "::1");
    assert!(sources[2].loopback());
    assert!(!sources[2].secure());
}

#[test]
fn remote_http_credentials_and_ambiguous_bases_are_refused() {
    for (text, reason) in [
        ("http://registry.example", ConfigReason::InsecureRemote),
        (
            "https://user:password@registry.example",
            ConfigReason::Credentials,
        ),
        (
            "https://registry.example?token=secret",
            ConfigReason::QueryOrFragment,
        ),
        (
            "https://registry.example#fragment",
            ConfigReason::QueryOrFragment,
        ),
        ("https://registry.example/prefix", ConfigReason::NpmPath),
        ("https:///example", ConfigReason::InvalidUrl),
        ("https://host:99999", ConfigReason::InvalidUrl),
        ("https://host:bad", ConfigReason::InvalidUrl),
        ("https://[::1", ConfigReason::InvalidUrl),
        ("https://host\\path", ConfigReason::InvalidUrl),
        ("https://host/\npath", ConfigReason::InvalidUrl),
        ("ftp://registry.example", ConfigReason::Scheme),
    ] {
        assert_eq!(RegistrySource::parse(text), Err(reason), "{text}");
    }
}

#[test]
fn an_invalid_url_reports_its_mirror_index_without_echoing_the_secret() {
    let value = json!([
        "https://registry.example",
        "https://user:secret@other.example"
    ]);
    let error = RegistryConfig::parse(Some(&value)).unwrap_err();
    assert_eq!(error.index, Some(1));
    assert_eq!(error.reason, ConfigReason::Credentials);
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn npm_metadata_uses_url_origins_instead_of_text_prefixes() {
    let source = RegistrySource::parse("https://registry.example:443").unwrap();
    assert_eq!(
        source.npm_artifact_path("https://REGISTRY.example/pkg.tgz?signature=fixture"),
        Ok("/pkg.tgz?signature=fixture".to_owned())
    );
    for url in [
        "https://registry.example.evil/pkg.tgz",
        "https://registry.example:444/pkg.tgz",
        "http://registry.example/pkg.tgz",
    ] {
        assert_eq!(
            source.npm_artifact_path(url),
            Err(ArtifactError::OriginMismatch)
        );
    }
    assert_eq!(
        source.npm_artifact_path("https://user:secret@registry.example/pkg.tgz"),
        Err(ArtifactError::Credentials)
    );
    let source = RegistrySource::parse("http://[::1]:4123").unwrap();
    assert_eq!(
        source.npm_artifact_path("http://[0:0:0:0:0:0:0:1]:4123/pkg.tgz"),
        Ok("/pkg.tgz".to_owned())
    );
}
