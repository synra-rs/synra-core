use synra_capability::CapabilitySet;
use synra_protocol::{ErrorCode, PluginId};
use super::super::{AdmissionContext, AdmissionRefusal, AdmissionStep, PluginKey, admit};
use super::{capability, invocation, permissive};

#[test]
fn every_step_explains_itself_for_a_log_line() {
    for step in [
        AdmissionStep::SenderPaired,
        AdmissionStep::PluginActive,
        AdmissionStep::ActionDeclared,
        AdmissionStep::PluginGrant,
        AdmissionStep::HostCapability,
    ] {
        assert!(!step.as_str().is_empty(), "{step:?}");
        assert!(!step.as_str().contains(' '), "{step:?}");
        assert!(step.number() >= 2 && step.number() <= 6, "{step:?}");
        // The display form names both, so a reader can find the step in the design document.
        let text = step.to_string();
        assert!(text.contains(step.as_str()), "{text}");
        assert!(text.contains(&step.number().to_string()), "{text}");
    }
}

#[test]
fn a_refusal_displays_the_step_and_the_reason() {
    let refusal = AdmissionRefusal {
        step: AdmissionStep::PluginGrant,
        detail: "the plugin has not been granted device:send:peer".to_owned(),
        code: ErrorCode::CapabilityDenied,
    };
    let text = refusal.to_string();
    assert!(text.contains("step 5"), "{text}");
    assert!(text.contains("device:send:peer"), "{text}");
}

// ── Outcomes ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_accepted_intent_produces_a_successful_outcome() {
    let invocation = invocation();
    let outcome = admit(&invocation, &permissive());
    assert!(outcome.ok);
    assert_eq!(outcome.intent_id, invocation.intent_id);
    assert!(outcome.error.is_none());
}

#[test]
fn a_refused_intent_produces_a_structured_outcome_rather_than_a_protocol_error() {
    // The receiving device understood the request and decided not to perform it, so the sender is told why in a
    // form it can show a user — not given a protocol failure it would report as a connection problem.
    let invocation = invocation();
    let context = permissive().with_sender_paired(false);
    let outcome = admit(&invocation, &context);
    assert!(!outcome.ok);
    assert_eq!(outcome.intent_id, invocation.intent_id);
    let error = outcome.error.expect("an error report");
    assert_eq!(error.code, ErrorCode::NotPaired);
    assert!(!error.message.is_empty());
}

#[test]
fn a_refusal_reaches_the_sender_with_its_reason() {
    // The message is what the sender shows, so a refusal that lost its detail would be a call the user cannot
    // diagnose.
    let invocation = invocation();
    let context = AdmissionContext::new(CapabilitySet::new())
        .with_required(vec![capability("device:send:peer")]);
    let outcome = admit(&invocation, &context);
    let error = outcome.error.expect("an error report");
    assert!(
        error.message.contains("device:send:peer"),
        "the refusal lost its detail: {}",
        error.message
    );
}

// ── Keys ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_plugin_key_round_trips_through_an_id() {
    let id = PluginId::parse("@synra-plugin/chat").expect("a valid id");
    let key = PluginKey::from(&id);
    assert_eq!(key.as_str(), "@synra-plugin/chat");
    assert_eq!(key.to_plugin_id().expect("parses"), id);
    assert_eq!(key.to_string(), "@synra-plugin/chat");
}

#[test]
fn a_plugin_key_that_is_not_a_valid_id_says_so_rather_than_panicking() {
    // A key can be built from a stored string, and a stored string can be from an older version.
    let key = PluginKey::new("not an id");
    assert!(key.to_plugin_id().is_err());
    assert_eq!(key.as_str(), "not an id");
}

#[test]
fn a_plugin_key_orders_deterministically() {
    // The key is used as a map key and, in the registry, as part of a sorted route list — so its ordering has to be
    // stable rather than depending on insertion order.
    let mut keys = [
        PluginKey::new("@b/plugin"),
        PluginKey::new("@a/plugin"),
        PluginKey::new("@c/plugin"),
    ];
    keys.sort();
    let names: Vec<&str> = keys.iter().map(PluginKey::as_str).collect();
    assert_eq!(names, vec!["@a/plugin", "@b/plugin", "@c/plugin"]);
}
