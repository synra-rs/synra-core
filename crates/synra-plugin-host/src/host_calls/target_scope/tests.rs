use super::*;
use crate::{
    HostCalls,
    quota::{Budget, Quota},
    test_host::Stub,
};
use synra_observe::audit::AuditOutcome;

const DEVICE: &str = "00000000-0000-4000-8000-000000000001";
const OTHER: &str = "00000000-0000-4000-8000-000000000002";

fn grants(texts: &[&str]) -> CapabilitySet {
    CapabilitySet::parse_all(texts.iter().copied()).expect("grants")
}

fn check_call(grant: &str, import: &str, args: serde_json::Value, expected: Option<&str>) {
    let host = Stub::default();
    let held = grants(&[grant]);
    let budget = Budget::new(Quota::default());
    let mut audit = Vec::new();
    let mut calls = HostCalls::new(
        &host,
        PluginId::parse("@acme/chat").expect("plugin"),
        &held,
        &budget,
        &mut audit,
    );
    let result = calls.call(&format!("synra:plugin/host#{import}"), &args.to_string());
    match expected {
        None => assert!(result.is_ok(), "{grant} {args}: {result:?}"),
        Some(code) => assert_eq!(result.expect_err("refused").code, code, "{grant} {args}"),
    }
    assert_eq!(host.called().len(), usize::from(expected.is_none()));
    let outcome = if expected == Some(CallError::CAPABILITY_DENIED) {
        AuditOutcome::Denied
    } else if expected.is_some() {
        AuditOutcome::Failed
    } else {
        AuditOutcome::Allowed
    };
    assert_eq!(audit.len(), 1);
    assert_eq!(audit.first().expect("audit").outcome, outcome);
}

#[test]
fn device_grants_authorize_the_canonical_target_and_keep_event_ownership() {
    let exact = format!("device:send:{DEVICE}");
    for (grant, target, event, expected) in [
        (exact.as_str(), DEVICE, "_plugin.@acme/chat.ready", None),
        (
            exact.as_str(),
            OTHER,
            "_plugin.@acme/chat.ready",
            Some(CallError::CAPABILITY_DENIED),
        ),
        ("device:send:*", OTHER, "_plugin.@acme/chat.ready", None),
        ("device:**", OTHER, "_plugin.@acme/chat.ready", None),
        (
            "device:send:*",
            "@self",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            "Laptop",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            "*",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            "00000000000040008000000000000001",
            "_plugin.@acme/chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "device:send:*",
            DEVICE,
            "_plugin.@other/chat.ready",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "device:send:*",
            DEVICE,
            "_plugin.chat.ready",
            Some(CallError::BAD_ARGUMENT),
        ),
    ] {
        check_call(
            grant,
            "device-send",
            serde_json::json!({"target":target,"event":event,"payload":"{}"}),
            expected,
        );
    }
}

#[test]
fn action_grants_bind_the_full_package_and_a_literal_action() {
    for (grant, plugin, name, expected) in [
        (
            "action:invoke:@acme/formatter:format-date",
            "@acme/formatter",
            "format-date",
            None,
        ),
        (
            "action:invoke:@acme/formatter:format-date",
            "@other/formatter",
            "format-date",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "action:invoke:@acme/formatter:format-date",
            "@acme/formatter",
            "other",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "action:invoke:@acme/formatter:*",
            "@acme/formatter",
            "other",
            None,
        ),
        (
            "action:invoke:*:format-date",
            "@other/formatter",
            "format-date",
            None,
        ),
        ("action:invoke:*:*", "@acme/formatter", "format-date", None),
        ("action:invoke:**", "@acme/formatter", "format-date", None),
        (
            "action:invoke:*",
            "@acme/formatter",
            "format-date",
            Some(CallError::CAPABILITY_DENIED),
        ),
        (
            "action:invoke:*:*",
            "formatter",
            "format-date",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/*",
            "format-date",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/formatter",
            "*",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/formatter",
            "a:b",
            Some(CallError::BAD_ARGUMENT),
        ),
        (
            "action:invoke:*:*",
            "@acme/formatter",
            "",
            Some(CallError::BAD_ARGUMENT),
        ),
    ] {
        check_call(
            grant,
            "action-invoke",
            serde_json::json!({"plugin":plugin,"name":name,"args":"{}"}),
            expected,
        );
    }
    check_call(
        "action:declare:*",
        "action-declare",
        serde_json::json!({"name":"*","schema":"{}"}),
        Some(CallError::BAD_ARGUMENT),
    );
}

#[test]
fn import_families_admit_scoped_declarations_without_authorizing_other_calls() {
    for (import, allowed, denied) in [
        (
            "action-declare",
            "action:declare:format-date".to_owned(),
            "action:declare",
        ),
        (
            "device-send",
            format!("device:send:{DEVICE}"),
            "device:list",
        ),
        (
            "action-invoke",
            "action:invoke:@acme/formatter:format-date".to_owned(),
            "action:invoke:*",
        ),
    ] {
        let import = format!("synra:plugin/host#{import}");
        assert!(crate::permits(&import, &grants(&[&allowed])));
        assert!(
            crate::undeclared_imports(std::slice::from_ref(&import), &grants(&[&allowed]))
                .is_empty()
        );
        assert_eq!(
            crate::undeclared_imports(std::slice::from_ref(&import), &grants(&[denied])),
            std::slice::from_ref(&import)
        );
        assert!(!crate::permits(&import, &CapabilitySet::new()));
    }
}

#[test]
fn declarations_require_authority_for_the_actual_name() {
    for (grant, name, expected) in [
        ("action:declare:format-date", "format-date", None),
        (
            "action:declare:format-date",
            "other",
            Some(CallError::CAPABILITY_DENIED),
        ),
        ("action:declare:*", "other", None),
        (
            "action:declare",
            "format-date",
            Some(CallError::CAPABILITY_DENIED),
        ),
        ("action:declare:*", "a:b", Some(CallError::BAD_ARGUMENT)),
    ] {
        check_call(
            grant,
            "action-declare",
            serde_json::json!({"name":name,"schema":"{}"}),
            expected,
        );
    }
}

#[test]
fn authorization_precedes_rate_limits_and_refusals_name_the_actual_scope() {
    let host = Stub::default();
    let held = grants(&[
        &format!("device:send:{DEVICE}"),
        "action:invoke:@acme/formatter:format-date",
        "action:declare:format-date",
    ]);
    let budget = Budget::new(Quota {
        device_sends_per_sec: 0,
        host_calls_per_sec: 0,
        host_calls_burst: 0,
        ..Quota::default()
    });
    let mut audit = Vec::new();
    let mut calls = HostCalls::new(
        &host,
        PluginId::parse("@acme/chat").expect("plugin"),
        &held,
        &budget,
        &mut audit,
    );
    for (import, denied, allowed, missing) in [
        (
            "action-declare",
            serde_json::json!({"name":"other"}),
            serde_json::json!({"name":"format-date"}),
            "action:declare:other".to_owned(),
        ),
        (
            "device-send",
            serde_json::json!({"target":OTHER,"event":"_plugin.@acme/chat.ready"}),
            serde_json::json!({"target":DEVICE,"event":"_plugin.@acme/chat.ready"}),
            format!("device:send:{OTHER}"),
        ),
        (
            "action-invoke",
            serde_json::json!({"plugin":"@other/formatter","name":"format-date"}),
            serde_json::json!({"plugin":"@acme/formatter","name":"format-date"}),
            "action:invoke:@other/formatter:format-date".to_owned(),
        ),
    ] {
        let import = format!("synra:plugin/host#{import}");
        let refusal = calls
            .call(&import, &denied.to_string())
            .expect_err("wrong scope");
        assert_eq!(refusal.code, CallError::CAPABILITY_DENIED);
        assert!(refusal.details.expect("details").contains(&missing));
        assert_eq!(
            calls
                .call(&import, &allowed.to_string())
                .expect_err("zero rate")
                .code,
            CallError::RATE_LIMITED
        );
    }
    assert!(host.called().is_empty());
}
