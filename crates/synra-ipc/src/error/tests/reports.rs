use synra_protocol::ErrorCode;
use synra_protocol::error::SuggestedAction;
use super::super::{IpcError, MessageKey};
use super::ALL_CODES;

#[test]
fn an_error_carries_what_the_interface_acts_on() {
    let error = IpcError::new(ErrorCode::CapabilityDenied, "error.capability_denied")
        .expect("builds")
        .with_params(serde_json::json!({ "capability": "platform:open-url" }))
        .with_action(SuggestedAction::RequestCapability {
            capability: "platform:open-url".to_owned(),
        });

    assert_eq!(error.code, ErrorCode::CapabilityDenied);
    assert_eq!(error.message.as_str(), "error.capability_denied");
    assert_eq!(error.params["capability"], "platform:open-url");
    assert!(!error.retryable, "a missing grant is not fixed by retrying");
    assert_eq!(error.actions.len(), 1);
    assert!(error.has_something_to_offer(), "there is a button to render");
}

#[test]
fn retryability_comes_from_the_code_and_is_not_re_derived() {
    // The kernel already decided whether a code is worth retrying; a second opinion in the interface is one
    // that can disagree with the kernel the user is actually talking to.
    for code in ALL_CODES {
        let error = IpcError::unknown(*code);
        assert_eq!(error.retryable, code.retryable(), "{code:?}");
    }
}

#[test]
fn an_error_with_neither_a_retry_nor_an_action_offers_nothing() {
    let error = IpcError::new(ErrorCode::CapabilityDenied, "error.capability_denied").expect("builds");
    assert!(!error.has_something_to_offer());
}

#[test]
fn every_code_produces_a_usable_key() {
    // The interface has to translate the key, so a code whose key is not one is a code the interface shows
    // nothing for.
    for code in ALL_CODES {
        let error = IpcError::unknown(*code);
        let key = error.message.as_str();
        assert!(key.starts_with("error."), "{code:?} -> {key}");
        assert!(!key.contains(' '), "{code:?} -> {key}");
        assert!(MessageKey::parse(key).is_ok(), "{code:?} -> {key}");
    }
}

#[test]
fn the_key_matches_the_wire_code() {
    // Derived from serde's own serialisation, so the key and the code cannot disagree — a hand-written table
    // would be one more place to update when a code is added.
    for code in ALL_CODES {
        let wire = serde_json::to_value(code)
            .expect("serialises")
            .as_str()
            .expect("a string")
            .to_owned();
        let error = IpcError::unknown(*code);
        assert_eq!(error.message.as_str(), format!("error.{wire}"), "{code:?}");
    }
}

#[test]
fn a_kernel_error_is_carried_across_with_its_judgement_intact() {
    let kernel = synra_protocol::SynraError::new(ErrorCode::Timeout, "the peer did not answer")
        .with_trace("operation-trace")
        .with_details(serde_json::json!({"pluginCode":"hostFailed"}))
        .with_action(SuggestedAction::Retry);
    let ipc = IpcError::from_synra_error(&kernel);

    assert_eq!(ipc.code, ErrorCode::Timeout);
    assert_eq!(ipc.message.as_str(), "error.timeout");
    assert!(ipc.retryable);
    assert_eq!(ipc.actions.len(), 1);
    // The kernel's sentence is kept as a detail rather than as the message: a log reader and a user need
    // different things from the same failure.
    assert_eq!(
        ipc.details.as_ref().expect("details")["kernelMessage"],
        "the peer did not answer"
    );
    assert_eq!(
        ipc.details.as_ref().expect("details")["context"],
        serde_json::json!({"pluginCode":"hostFailed"})
    );
    assert_eq!(
        ipc.details.as_ref().expect("details")["traceId"],
        "operation-trace"
    );
}

#[test]
fn a_kernel_error_with_no_actions_crosses_with_none() {
    let kernel = synra_protocol::SynraError::new(ErrorCode::Internal, "x");
    let ipc = IpcError::from_synra_error(&kernel);
    assert!(ipc.actions.is_empty());
    // The kernel's own judgement is carried across rather than re-derived, and the kernel treats `internal` as
    // retryable — an internal fault is often a race or a transient, and the retry budget is what bounds it.
    // Disagreeing here would be a second opinion that can contradict the kernel the user is talking to.
    assert_eq!(ipc.retryable, ErrorCode::Internal.retryable());
}

#[test]
fn a_code_the_kernel_calls_permanent_is_not_retried() {
    // The other side of the judgement: a missing grant is not fixed by asking again, and the interface uses
    // this to decide whether to offer a retry button.
    for code in [ErrorCode::CapabilityDenied, ErrorCode::NotPaired, ErrorCode::Unsupported] {
        assert!(!IpcError::unknown(code).retryable, "{code:?}");
    }
    for code in [ErrorCode::Timeout, ErrorCode::DeviceOffline, ErrorCode::TransportNotOpen] {
        assert!(IpcError::unknown(code).retryable, "{code:?}");
    }
}

#[test]
fn an_error_round_trips_through_json() {
    // The shape is what the interface parses, so a field that changes name is a field the interface cannot
    // read. `camelCase` throughout.
    let error = IpcError::new(ErrorCode::RateLimited, "error.rate_limited")
        .expect("builds")
        .with_params(serde_json::json!({ "retryAfterMs": 250 }))
        .with_details(serde_json::json!({ "scope": "events" }))
        .with_action(SuggestedAction::Retry);

    let json = serde_json::to_string(&error).expect("serialises");
    assert!(json.contains("\"message\":\"error.rate_limited\""), "{json}");
    assert!(json.contains("retryAfterMs"), "{json}");
    assert!(json.contains("\"retryable\":true"), "{json}");

    let back: IpcError = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, error);
}

#[test]
fn absent_optional_fields_are_omitted_rather_than_null() {
    // An explicit `null` and an absent field are different statements, and `deny_unknown_fields` consumers
    // elsewhere in the protocol treat the distinction as meaningful.
    let error = IpcError::new(ErrorCode::NotPaired, "error.not_paired").expect("builds");
    let json = serde_json::to_string(&error).expect("serialises");
    assert!(!json.contains("params"), "{json}");
    assert!(!json.contains("details"), "{json}");
    assert!(!json.contains("actions"), "{json}");
}

#[test]
fn an_interface_can_branch_on_the_code_without_parsing_a_sentence() {
    // The design document's requirement, as an executable statement: the code is a closed set, so a branch on
    // it is exhaustive and a typo is a compile error rather than a case that never runs.
    let error = IpcError::new(ErrorCode::CapabilityDenied, "error.capability_denied").expect("builds");
    let outcome = match error.code {
        ErrorCode::CapabilityDenied => "need_permission",
        ErrorCode::NotPaired => "need_pairing",
        ErrorCode::DeviceOffline => "offline",
        ErrorCode::Timeout | ErrorCode::RateLimited => "retry_later",
        _ => "other",
    };
    assert_eq!(outcome, "need_permission");
}
