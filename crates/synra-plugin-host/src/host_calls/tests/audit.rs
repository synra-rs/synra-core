use synra_observe::audit::AuditOutcome;
use synra_store::sqlite::now_ms;
use crate::test_host::Stub;
use super::{budget, granted, plugin, session};

#[test]
fn the_gate_records_its_four_metrics() {
    // ★ The design's `gate_*` metrics, from the one place that knows their answers.
    //
    // `RingRecorder` was written, tested and reachable from nothing: every one of the ~30 metrics in the design's list was
    // unwired, and the recorder had no producer at all. This is the first — the gate, because it is where "was it allowed,
    // for which plugin, against which capability, and if not, was it the set or the limiter" is already decided.
    let host = Stub::default();
    let grants = granted(&["device:list"]);
    let budget = budget();
    let recorder = synra_observe::metrics::RingRecorder::new();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit).with_metrics(&recorder);

    // One allowed, one denied.
    let _ = calls.call("synra:plugin/host#device-list", "");
    let _ = calls.call("synra:plugin/host#device-send", "{}");

    let snapshot = recorder.snapshot();
    assert_eq!(
        snapshot.get("gate_checks_total{result=allowed}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the allowed check"
    );
    assert_eq!(
        snapshot.get("gate_checks_total{result=denied}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "and the refused one"
    );
    // ★ And the refusal names the capability, which is the label the design asks `gate_denied_total` to carry — it is the
    // question "which permission do plugins keep asking for and not have", and a count without it cannot answer that.
    assert_eq!(
        snapshot.get("gate_denied_total{capability=device:send:*}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "named rather than counted in the abstract"
    );
}

#[test]
fn a_gated_call_records_how_long_it_took() {
    // ★ Nothing in production had ever called `histogram_observe`; only the recorder's own tests did. A histogram no
    // caller uses is a shape rather than a measurement — and the number was already in the caller's hand, because
    // `elapsed_ms` went into the audit entry and nowhere else.
    //
    // The gate metrics above answer "what was decided"; this answers "how slow is it", which is a question about a
    // distribution and cannot be read off any number of audit rows.
    let host = Stub::default();
    let grants = granted(&["device:list"]);
    let budget = budget();
    let recorder = synra_observe::metrics::RingRecorder::new();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit).with_metrics(&recorder);

    let _ = calls.call("synra:plugin/host#device-list", "");

    let snapshot = recorder.snapshot();
    // Labelled by the import, which is what a call is — the same shape `gate_denied_total` carries a capability in — and
    // the recorder's own cardinality guard is what bounds the series a caller could create.
    assert!(
        snapshot.get("host_call_ms{import=synra:plugin/host#device-list}").is_some(),
        "the duration was not recorded"
    );
}

#[test]
fn a_refusal_tells_a_plugin_what_it_already_holds_in_that_domain() {
    // ★ The wiring rather than the derivation.
    //
    // `CapabilityDenied::of` is tested in its own crate. What this asserts is that the gate hands it the **session's own
    // grants** — a refusal built against an empty set would look identical from the outside and would tell every author
    // "you hold nothing in that domain", which is exactly the kind of quiet wrong answer that makes an error message
    // useless.
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let refused = calls
        .call("synra:plugin/host#storage-set", r#"{"key":"k","value":"v"}"#)
        .expect_err("the write capability is not held");
    let details: serde_json::Value =
        serde_json::from_str(refused.details.as_deref().expect("details")).expect("valid JSON");

    assert_eq!(details["capability"], "storage:local:write");
    assert_eq!(details["granted"][0], "storage:local:read", "what the plugin actually holds");
    assert!(
        details["suggestion"].as_str().is_some_and(|text| text.contains("already holds")),
        "and the suggestion notices it: {details}"
    );
}

#[test]
fn every_gated_call_is_audited_against_the_capability_it_needed() {
    let host = Stub::default();
    let grants = granted(&["storage:local:read"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let _ = calls.call("synra:plugin/host#storage-get", "known");
    let _ = calls.call("synra:plugin/host#storage-delete", "k");

    assert_eq!(audit.len(), 2, "both calls are recorded, the refused one included");
    let first = audit.first().expect("a record");
    assert_eq!(first.plugin, plugin());
    assert_eq!(first.capability.to_string(), "storage:local:read");
    assert_eq!(first.outcome, AuditOutcome::Allowed);
    assert!(first.at_ms >= 0, "a timestamp is always set");
    assert!(first.elapsed_ms.is_some(), "how long it took is recorded");
}

#[test]
fn the_audit_names_the_plugin_that_called_and_never_the_arguments() {
    // The design document is explicit: the record is about the permission, and the capability describes a destination
    // rather than a content. A secret written here must not appear in the audit.
    let host = Stub::default();
    let grants = granted(&["storage:secure:write"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let _ = calls.call("synra:plugin/host#secret-set", r#"{"key":"token","value":"hunter2"}"#);
    let rendered = format!("{audit:?}");
    assert!(!rendered.contains("hunter2"), "the secret is in the audit: {rendered}");
    assert!(rendered.contains("@acme/chat"), "{rendered}");
}

#[test]
fn a_debug_form_names_the_plugin_and_how_much_has_been_audited() {
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let calls = session(&host, &grants, &budget, &mut audit);
    let text = format!("{calls:?}");
    assert!(text.contains("HostCalls"), "{text}");
    assert!(text.contains("@acme/chat"), "{text}");
    assert_eq!(calls.plugin(), &plugin());
    assert_eq!(calls.grants().len(), 1);
}

#[test]
fn the_clock_the_session_uses_is_the_stores() {
    // One clock for the kernel: an audit entry and a device's `last_seen_ms` must be comparable, and two clocks would
    // make a plugin's call appear to have happened before the device it addressed.
    let host = Stub::default();
    let grants = granted(&["log:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);
    let before = now_ms();
    let _ = calls.call("synra:plugin/host#log", r#"{"level":"info","message":"x"}"#);
    let after = now_ms();
    let at = audit.first().map(|entry| entry.at_ms).expect("a record");
    assert!(at >= before && at <= after, "{before} <= {at} <= {after}");
}
