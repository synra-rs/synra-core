use synra_observe::audit::AuditOutcome;
use super::super::CallError;
use crate::host_surface;
use crate::test_host::Stub;
use super::{budget, granted, session};

#[test]
fn scoped_network_import_is_loadable_with_a_specific_host() {
    let grants = granted(&["network:fetch:api.github.com"]);
    assert!(host_surface::permits(
        "synra:plugin/host#network-fetch",
        &grants
    ));
}

#[test]
fn scoped_network_calls_allow_only_the_actual_requested_host() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:api.github.com"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        assert!(
            calls
                .call(
                    "synra:plugin/host#network-fetch",
                    r#"{"url":"https://api.github.com/repos"}"#
                )
                .is_ok()
        );
        let denied = calls
            .call(
                "synra:plugin/host#network-fetch",
                r#"{"url":"https://evil.example/"}"#,
            )
            .unwrap_err();
        assert_eq!(denied.code, CallError::CAPABILITY_DENIED);
    }
    assert_eq!(host.called(), ["network-fetch"]);
    assert_eq!(audit.len(), 2);
    assert_eq!(audit.last().unwrap().outcome, AuditOutcome::Denied);
}

#[test]
fn scoped_network_url_authority_and_method_are_concrete_and_rechecked() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:api.github.com:POST"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        assert!(
            calls
                .call(
                    "synra:plugin/host#network-fetch",
                    r#"{"url":"https://API.GITHUB.COM.:8443/","method":"POST"}"#
                )
                .is_ok()
        );
        for request in [
            r#"{"url":"https://api.github.com/"}"#,
            r#"{"url":"https://api.github.com.evil/","method":"POST"}"#,
            r#"{"url":"https://api.github.com@evil.example/","method":"POST"}"#,
        ] {
            assert_eq!(
                calls
                    .call("synra:plugin/host#network-fetch", request)
                    .unwrap_err()
                    .code,
                CallError::CAPABILITY_DENIED
            );
        }
    }
    assert_eq!(host.called(), ["network-fetch"]);
}

#[test]
fn scoped_network_json_escaping_does_not_change_the_destination() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:api.github.com"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    assert!(
        calls
            .call(
                "synra:plugin/host#network-fetch",
                r#"{"url":"https:\/\/api.github.com\/repos"}"#
            )
            .is_ok()
    );
}

#[test]
fn scoped_network_malformed_targets_fail_before_host_effects() {
    let host = Stub::default();
    let grants = granted(&["network:fetch:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for request in [
            r#"{"url":"file://api.github.com/path"}"#,
            r#"{"url":"https://*.github.com/"}"#,
            r#"{"url":"https://api.github.com/","method":"bad method"}"#,
            r#"{"url":"https://api.github.com\\@evil.example/"}"#,
            "not json",
        ] {
            assert_eq!(
                calls
                    .call("synra:plugin/host#network-fetch", request)
                    .unwrap_err()
                    .code,
                CallError::BAD_ARGUMENT
            );
        }
    }
    assert!(host.called().is_empty());
    assert!(
        audit
            .iter()
            .all(|entry| entry.outcome == AuditOutcome::Failed)
    );
}
