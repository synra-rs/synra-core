use synra_capability::CapabilitySet;
use synra_observe::audit::AuditOutcome;
use super::super::CallError;
use crate::test_host::Stub;
use super::{all_capabilities, budget, granted, session};

#[test]
fn a_call_the_contract_does_not_declare_is_refused_before_anything_is_counted() {
    // ★ Not "refused because it is gated and unheld" — refused because it is not a function. The table is generated
    // from the WIT file, so a name it does not list is a name nothing implements.
    let host = Stub::default();
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    for name in [
        "synra:plugin/host#teleport",
        "synra:plugin/host#storage-get-all",
        "wasi:filesystem/types@0.2.0",
        "storage-get",
        "",
    ] {
        match calls.call(name, "") {
            Err(error) => assert_eq!(error.code, CallError::UNKNOWN_FUNCTION, "{name}"),
            Ok(answer) => panic!("{name} was accepted: {answer}"),
        }
    }
    assert!(host.called().is_empty(), "nothing reached the host");
    assert!(audit.is_empty(), "a call to nothing is not a cost to bill");
}

#[test]
fn a_gated_call_without_the_capability_is_refused_and_does_not_reach_the_host() {
    // ★ The property that makes the gate a gate: a refusal that still performed the call would be a refusal that did
    // nothing. The stub records every call that got through, and it is asked to have none.
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let gated = [
        ("synra:plugin/host#storage-set", r#"{"key":"k","value":"v"}"#),
        ("synra:plugin/host#storage-get", "known"),
        ("synra:plugin/host#device-list", ""),
        ("synra:plugin/host#device-send", r#"{"target":"d","event":"e","payload":"{}"}"#),
        ("synra:plugin/host#network-fetch", r#"{"url":"https://example"}"#),
        ("synra:plugin/host#platform-open-url", "https://example"),
        ("synra:plugin/host#secret-get", "token"),
        ("synra:plugin/host#transfer-send", r#"{"target":"d","event":"k","payload":"{}"}"#),
        ("synra:plugin/host#action-declare", r#"{"name":"n","schema":"{}"}"#),
    ];
    for (import, argument) in gated {
        match calls.call(import, argument) {
            Err(error) => {
                assert_eq!(error.code, CallError::CAPABILITY_DENIED, "{import}");
                // The refusal names the capability, so a plugin author knows what to ask the user for.
                assert!(error.message.contains(':'), "{import}: {}", error.message);
            }
            Ok(answer) => panic!("{import} was accepted: {answer}"),
        }
    }
    assert!(host.called().is_empty(), "a refused call reached the host: {:?}", host.called());
    // And every refusal is in the audit, because "which plugin tried to do what it could not" is what it is read for.
    assert_eq!(audit.len(), gated.len());
    assert!(audit.iter().all(|entry| entry.outcome == AuditOutcome::Denied));
}

#[test]
fn the_ungated_functions_reach_the_host_with_nothing_granted() {
    // ★ The five `env-*` queries exist because a plugin needs the answers *before* it can decide what to ask for;
    // gating them would mean requesting a capability to discover whether it wants it.
    let host = Stub::default();
    let grants = CapabilitySet::new();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    assert_eq!(calls.call("synra:plugin/host#env-sdk-version", ""), Ok("1.0.0".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-host-kind", ""), Ok("headless".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-locale", ""), Ok("en-GB".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-dark-mode", ""), Ok("true".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-can", "log:*"), Ok("true".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#env-can", "storage:local:write"), Ok("false".to_owned()));
    assert_eq!(calls.call("synra:plugin/host#plugin-id", ""), Ok("@acme/chat".to_owned()));
    assert_eq!(
        calls.call("synra:plugin/host#platform-capabilities", ""),
        Ok("[\"platform:notify\"]".to_owned())
    );
    // None of these is audited: there is no capability for them to be a record *about*.
    assert!(audit.is_empty(), "{audit:?}");
}

#[test]
fn a_capability_that_covers_one_function_does_not_cover_another() {
    // The gate is per function and not per domain: holding `storage:local:read` must not let a plugin write.
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    assert_eq!(calls.call("synra:plugin/host#storage-get", "known"), Ok("a value".to_owned()));
    match calls.call("synra:plugin/host#storage-set", r#"{"key":"k","value":"v"}"#) {
        Err(error) => assert_eq!(error.code, CallError::CAPABILITY_DENIED),
        other => panic!("a write was accepted with a read grant: {other:?}"),
    }
    assert_eq!(host.called(), vec!["storage-get".to_owned()]);
}
