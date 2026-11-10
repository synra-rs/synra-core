use super::super::error::ManifestError;
use super::super::types::{Manifest, ManifestContext};
use super::{MINIMAL, parse};

/// The minimal manifest with network declarations.
fn with_network(hosts: &str, capabilities: &str) -> Manifest {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        &format!(
            "\"capabilities\": [{capabilities}], \
                 \"network\": {{ \"outbound\": [{hosts}] }}"
        ),
    );
    parse(&text)
}

#[test]
fn a_declared_host_without_a_capability_is_refused() {
    // Two lists that disagree produce a consent screen showing one thing and a plugin holding another.
    let manifest = with_network(
        "{ \"host\": \"api.github.com\" }",
        "{ \"cap\": \"network:fetch:api.github.com\" }",
    );
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));

    let mismatched = with_network(
        "{ \"host\": \"api.github.com\" }",
        "{ \"cap\": \"network:fetch:api.x.com\" }",
    );
    assert!(matches!(
        mismatched.validate(&ManifestContext::default()),
        Err(ManifestError::NetworkMismatch { .. })
    ));
}

#[test]
fn a_capability_without_a_declared_host_is_refused() {
    let manifest = with_network(
        "{ \"host\": \"api.x.com\" }",
        "{ \"cap\": \"network:fetch:api.x.com\" }, { \"cap\": \"network:fetch:api.y.com\" }",
    );
    match manifest.validate(&ManifestContext::default()) {
        Err(ManifestError::NetworkMismatch { detail }) => {
            assert!(detail.contains("api.y.com"), "{detail}");
        }
        other => panic!("expected a network mismatch, got {other:?}"),
    }
}

#[test]
fn a_wildcard_capability_needs_no_declared_host() {
    // A wildcard has no finite description, which is exactly why the interface spells it out as "any
    // website" rather than pretending a list covers it.
    let manifest = with_network(
        "{ \"host\": \"api.x.com\" }",
        "{ \"cap\": \"network:fetch:*\" }",
    );
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
}

#[test]
fn a_wildcard_declared_host_needs_its_capability() {
    let manifest = with_network(
        "{ \"host\": \"*.example.com\", \"methods\": [\"GET\"] }",
        "{ \"cap\": \"network:fetch:*.example.com:GET\" }",
    );
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
}

#[test]
fn finite_network_method_declarations_match_their_authority_in_both_directions() {
    let cases = [
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"}"#,
            true,
        ),
        (
            r#""methods":["GET","POST"]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"},{"cap":"network:fetch:api.x.com:POST"}"#,
            true,
        ),
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com:POST"}"#,
            false,
        ),
        (
            r#""methods":[]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"}"#,
            false,
        ),
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com"}"#,
            false,
        ),
        (
            r#""methods":["GET","POST"]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"}"#,
            false,
        ),
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com:*"}"#,
            false,
        ),
    ];
    for (methods, caps, allowed) in cases {
        let declaration = format!(r#"{{"host":"api.x.com",{methods}}}"#);
        let result = with_network(&declaration, caps).validate(&ManifestContext::default());
        assert_eq!(result.is_ok(), allowed, "{methods} / {caps}: {result:?}");
    }
}

#[test]
fn a_non_fetch_network_capability_needs_no_declared_host() {
    // `network:websocket` is not a host-scoped grant, so the two lists say nothing about each other.
    let manifest = with_network(
        "{ \"host\": \"api.x.com\" }",
        "{ \"cap\": \"network:websocket\" }, { \"cap\": \"network:fetch:api.x.com\" }",
    );
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
}

#[test]
fn a_network_capability_with_no_qualifier_needs_no_declared_host() {
    let manifest = with_network(
        "{ \"host\": \"api.x.com\" }",
        "{ \"cap\": \"network:fetch:api.x.com\" }, { \"cap\": \"network:fetch\" }",
    );
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
}
