use synra_observe::audit::AuditOutcome;
use synra_protocol::ids::PluginId;
use super::super::{CallError, HostCalls};
use crate::host_surface;
use crate::test_host::Stub;
use super::{all_capabilities, budget, granted, session};

#[test]
fn a_plugin_cannot_emit_an_event_in_another_plugins_namespace() {
    // ★ One plugin speaking as another.
    //
    // `EventName::check_emittable_by` was written, tested and documented as the enforcement point — its own doc says
    // "The host calls this on every outbound plugin event. It is the difference between 'plugins have their own
    // namespace' being true and it being a sentence in a document" — and **the host did not call it**. Every call site
    // was in its own test module, so a plugin could emit `_plugin.@acme/notes.something` and every subscriber would believe it
    // came from `notes`.
    let host = Stub::with_devices(&[]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    let refused = calls
        .call(
            "synra:plugin/host#event-emit",
            r#"{"event":"_plugin.@acme/notes.something","payload":"{}"}"#,
        )
        .expect_err("another plugin's namespace is not this plugin's to use");

    assert_eq!(refused.code, CallError::CAPABILITY_DENIED);
    // The message names whose namespace it is, because "denied" alone does not tell an author what to change.
    assert!(refused.message.contains("notes"), "{}", refused.message);
}

#[test]
fn a_plugin_cannot_emit_a_host_event() {
    // ★ The other half, and the more dangerous one: a plugin telling the kernel, and every other plugin, that
    // something happened that did not. `_synra.device.changed` is the kernel's own statement about the device list.
    let host = Stub::with_devices(&[]);
    let grants = all_capabilities();
    let budget = budget();
    let mut audit = Vec::new();
    let mut calls = session(&host, &grants, &budget, &mut audit);

    for event in ["_synra.device.changed", "device.hello", "synra.internal.anything"] {
        let refused = calls
            .call(
                "synra:plugin/host#event-emit",
                &format!(r#"{{"event":"{event}","payload":"{{}}"}}"#),
            )
            .expect_err("a host event is not a plugin's to emit");

        assert_eq!(refused.code, CallError::CAPABILITY_DENIED, "{event}");
        // And it names the event, so an author reading the refusal knows which call to change rather than guessing
        // among the several an event-emitting plugin makes.
        assert!(refused.message.contains(event), "{}", refused.message);
        // ★ The capability is not the reason, and the message must not suggest it is: the plugin holds
        // `event:emit:*`, which is what let this call reach the check at all. What it lacks is a namespace, and
        // sending an author to look for a permission they already have is the failure this distinction avoids.
        assert!(
            !refused.message.contains("capability") && !refused.message.contains("permission"),
            "{}",
            refused.message
        );
    }
}

#[test]
fn plugins_with_the_same_package_name_cannot_emit_each_others_events() {
    let host = Stub::default();
    let grants = granted(&["event:emit:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    let argument = r#"{"event":"_plugin.@acme/chat.ready","payload":"{}"}"#;
    let mut owner = HostCalls::new(
        &host,
        PluginId::parse("@acme/chat").unwrap(),
        &grants,
        &budget,
        &mut audit,
    );
    assert!(owner.call("synra:plugin/host#event-emit", argument).is_ok());
    let mut other = HostCalls::new(
        &host,
        PluginId::parse("@other/chat").unwrap(),
        &grants,
        &budget,
        &mut audit,
    );
    assert_eq!(
        other
            .call("synra:plugin/host#event-emit", argument)
            .unwrap_err()
            .code,
        CallError::CAPABILITY_DENIED
    );
    assert_eq!(host.called(), ["event-emit"]);
}

#[test]
fn scoped_events_authorize_the_concrete_name_and_recheck_revocation() {
    let host = Stub::default();
    let budget = budget();
    let mut audit = Vec::new();
    for (caps, event, allowed) in [
        (
            &["event:emit:_plugin.@acme/chat.ready"][..],
            "_plugin.@acme/chat.ready",
            true,
        ),
        (
            &["event:emit:_plugin.@acme/chat.ready"][..],
            "_plugin.@acme/chat.other",
            false,
        ),
        (&[][..], "_plugin.@acme/chat.ready", false),
    ] {
        let grants = granted(caps);
        let mut calls = session(&host, &grants, &budget, &mut audit);
        let argument = serde_json::json!({"event": event, "payload": "{}"}).to_string();
        let result = calls.call("synra:plugin/host#event-emit", &argument);
        if allowed {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert_eq!(result.unwrap_err().code, CallError::CAPABILITY_DENIED);
        }
    }
    assert_eq!(host.called(), ["event-emit"]);
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Denied)
            .count(),
        2
    );
    for cap in [
        "event:emit:_plugin.@acme/chat.ready",
        "event:emit:_plugin.@acme/chat.*",
        "event:**",
    ] {
        assert!(host_surface::permits(
            "synra:plugin/host#event-emit",
            &granted(&[cap])
        ));
    }
}

#[test]
fn event_capabilities_cannot_override_identity_or_invent_event_names() {
    let host = Stub::default();
    let grants = granted(&["event:emit:*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        for (event, expected) in [
            ("_plugin.@other/chat.ready", CallError::CAPABILITY_DENIED),
            (
                "_plugin.@acme/synra-plugin-chat.ready",
                CallError::CAPABILITY_DENIED,
            ),
            ("_plugin.chat.ready", CallError::BAD_ARGUMENT),
            ("_plugin.@acme/chat.*", CallError::BAD_ARGUMENT),
            ("_synra.device.changed", CallError::CAPABILITY_DENIED),
        ] {
            let argument = serde_json::json!({"event": event}).to_string();
            assert_eq!(
                calls
                    .call("synra:plugin/host#event-emit", &argument)
                    .unwrap_err()
                    .code,
                expected
            );
        }
    }
    assert!(host.called().is_empty());
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Denied)
            .count(),
        3
    );
    assert_eq!(
        audit
            .iter()
            .filter(|entry| entry.outcome == AuditOutcome::Failed)
            .count(),
        2
    );
}

#[test]
fn escaped_event_owner_strings_preserve_their_authority_and_maximal_names_fit() {
    let host = Stub::default();
    let grants = granted(&["event:emit:_plugin.@acme/chat.*"]);
    let budget = budget();
    let mut audit = Vec::new();
    {
        let mut calls = session(&host, &grants, &budget, &mut audit);
        assert!(
            calls
                .call(
                    "synra:plugin/host#event-emit",
                    r#"{"event":"_plugin.@acme\/chat.ready","payload":"{}"}"#
                )
                .is_ok()
        );
        let prefix = "_plugin.@acme/chat.";
        let event = format!(
            "{prefix}{}",
            "x".repeat(synra_protocol::event::MAX_EVENT_NAME_LEN - prefix.len())
        );
        let argument = serde_json::json!({"event": event}).to_string();
        assert!(
            calls
                .call("synra:plugin/host#event-emit", &argument)
                .is_ok()
        );
    }
    assert_eq!(host.called(), ["event-emit", "event-emit"]);
    assert_eq!(
        synra_protocol::event::MAX_EVENT_NAME_LEN + "event:subscribe:".len(),
        synra_capability::capability::MAX_LEN
    );
}
