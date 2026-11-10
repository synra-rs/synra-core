use synra_observe::audit::AuditOutcome;
use super::super::CallError;
use crate::host_surface;
use crate::test_host::Stub;
use super::{budget, granted, session};

#[test]
fn scoped_log_import_requires_at_least_one_supported_level() {
    for (caps, available) in [
        (&["log:info"][..], true),
        (&["log:*"][..], true),
        (&["log:unknown"][..], false),
        (&["log:info:**"][..], true),
        (&["log:**:info"][..], true),
        (&["log:**:unknown"][..], false),
        (&["network:fetch:*"][..], false),
        (&[][..], false),
    ] {
        assert_eq!(
            host_surface::permits("synra:plugin/host#log", &granted(caps)),
            available,
            "{caps:?}"
        );
    }
}

#[test]
fn scoped_log_calls_enforce_the_actual_level_and_revocation() {
    let host = Stub::default();
    let budget = budget();
    let mut audit = Vec::new();
    for (caps, level, allowed) in [
        (&["log:info"][..], "info", true),
        (&["log:info"][..], "warn", false),
        (&[][..], "info", false),
    ] {
        let grants = granted(caps);
        let mut calls = session(&host, &grants, &budget, &mut audit);
        let argument = serde_json::json!({"level": level, "message": "hello"}).to_string();
        let result = calls.call("synra:plugin/host#log", &argument);
        if allowed {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert_eq!(result.unwrap_err().code, CallError::CAPABILITY_DENIED);
        }
    }
    assert_eq!(host.called(), ["log"]);
    assert_eq!(
        audit.iter().map(|entry| entry.outcome).collect::<Vec<_>>(),
        [
            AuditOutcome::Allowed,
            AuditOutcome::Denied,
            AuditOutcome::Denied
        ]
    );
}

#[test]
fn scoped_log_wildcards_accept_the_five_levels_but_never_an_invented_target() {
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for level in ["trace", "debug", "info", "warn", "error"] {
            let argument = serde_json::json!({"level": level, "message": "hello"}).to_string();
            assert!(calls.call("synra:plugin/host#log", &argument).is_ok());
        }
        for level in ["*", "unknown", "INFO", "info:extra"] {
            let argument = serde_json::json!({"level": level, "message": "hello"}).to_string();
            assert_eq!(
                calls
                    .call("synra:plugin/host#log", &argument)
                    .unwrap_err()
                    .code,
                CallError::BAD_ARGUMENT
            );
        }
    }
    assert_eq!(host.called(), vec!["log"; 5]);
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Failed)
            .count(),
        4
    );
}

#[test]
fn scoped_log_escaped_json_levels_preserve_their_concrete_authority() {
    let host = Stub::default();
    let grants = granted(&["log:info"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    assert!(
        calls
            .call(
                "synra:plugin/host#log",
                r#"{"level":"i\u006efo","message":"hello"}"#
            )
            .is_ok()
    );
    assert_eq!(host.called(), ["log"]);
}
