use super::super::{
    AckPolicy, DataPlaneEvent, EventName, EventNameError, NO_AUTO_ACK, PLUGIN_EMITTABLE,
    SYSTEM_PREFIX, ack_policy, builtin, events,
};
use super::slug;

#[test]
fn a_plugin_may_emit_its_own_events() {
    let chat = slug("chat");
    let name = EventName::plugin(&chat, "text").expect("valid");
    assert_eq!(name.check_emittable_by(&chat), Ok(()));
}

#[test]
fn a_plugin_may_not_emit_another_plugins_events() {
    // The difference between "plugins have their own namespace" being true and being a sentence
    // in a document.
    let chat = slug("chat");
    let notes = slug("notes");
    let name = EventName::plugin(&chat, "text").expect("valid");

    assert!(matches!(
        name.check_emittable_by(&notes),
        Err(EventNameError::ForeignNamespace { actual, attempted })
            if actual == "@acme/chat" && attempted == "@acme/notes"
    ));
}

#[test]
fn a_plugin_may_not_emit_host_events_by_default() {
    let chat = slug("chat");
    for reserved in [
        events::INTENT_INVOKE,
        builtin::TRANSFER_COMPLETED,
        "file.transfer.chunk",
    ] {
        let name = EventName::parse(reserved).expect("valid");
        assert!(
            matches!(
                name.check_emittable_by(&chat),
                Err(EventNameError::ReservedForHost(_))
            ),
            "{reserved} should be reserved for the host",
        );
    }
}

#[test]
fn only_the_whitelisted_host_events_are_plugin_emittable() {
    let chat = slug("chat");
    for allowed in PLUGIN_EMITTABLE {
        let name = EventName::parse(allowed).expect("valid");
        assert_eq!(name.check_emittable_by(&chat), Ok(()), "{allowed} should be allowed");
    }
}

#[test]
fn ack_policy_lives_on_the_event_not_on_the_direction() {
    // Reliability must not depend on who dialled. This is the regression guard: the function
    // takes only an event name, so there is no direction available to consult.
    let ack = |name: &str| ack_policy(&EventName::parse(name).expect("valid"));

    assert_eq!(ack(events::PING), AckPolicy::FireAndForget);
    assert_eq!(ack(events::PONG), AckPolicy::FireAndForget);
    assert_eq!(ack(events::HELLO), AckPolicy::FireAndForget);
    assert_eq!(ack(events::BYE), AckPolicy::FireAndForget);

    // Everything a user would notice losing.
    assert_eq!(ack(events::INTENT_INVOKE), AckPolicy::Await);
    assert_eq!(ack("_plugin.@acme/chat.text"), AckPolicy::Await);
    assert_eq!(ack(builtin::TRANSFER_COMPLETED), AckPolicy::Await);
}

#[test]
fn no_auto_ack_contains_only_transport_events() {
    // An exception list that grew to include a business event would silently make that event
    // unreliable, with no test failing and no log line.
    for name in NO_AUTO_ACK {
        assert!(
            name.starts_with("device."),
            "{name} is not a transport event; the ack policy should not exempt it",
        );
    }
}

#[test]
fn data_plane_events_round_trip_through_their_names() {
    for event in [
        DataPlaneEvent::FileTransferRequest,
        DataPlaneEvent::FileTransferChunk,
        DataPlaneEvent::FileTransferComplete,
        DataPlaneEvent::FileTransferAbort,
        DataPlaneEvent::FileTransferProgress,
    ] {
        assert_eq!(DataPlaneEvent::from_str_opt(event.as_str()), Some(event));
        assert_eq!(event.to_string(), event.as_str());
        let name = EventName::parse(event.as_str()).expect("valid");
        assert!(name.is_data_plane(), "{name} should be data plane");
    }

    assert_eq!(DataPlaneEvent::from_str_opt("file.transfer.nope"), None);
    assert_eq!(DataPlaneEvent::from_str_opt("device.ping"), None);
}

/// Every name this crate defines, in one list so the tests below can check all of them.
const ALL_DEFINED: &[&str] = &[
    builtin::DEVICE_CHANGED,
    builtin::DEVICE_OFFLINE,
    builtin::DEVICE_RENAMED,
    builtin::SHARE_RECEIVED,
    builtin::INTENT_COMPLETED,
    builtin::INTENT_FAILED,
    builtin::TRANSFER_COMPLETED,
    builtin::TRANSFER_FAILED,
    builtin::TRANSFER_PROGRESS,
    builtin::CLIPBOARD_RECEIVED,
    builtin::PLUGIN_INSTALLED,
    builtin::PLUGIN_UPDATED,
    builtin::PLUGIN_UNINSTALLED,
    builtin::PLUGIN_CAPABILITY_CHANGED,
    builtin::HOST_FOREGROUND,
    builtin::HOST_BACKGROUND,
    builtin::NETWORK_CHANGED,
    events::HELLO,
    events::HELLO_ACK,
    events::ACK,
    events::PING,
    events::PONG,
    events::BYE,
    events::ERROR,
    events::INTENT_INVOKE,
    events::INTENT_RESULT,
    events::INTENT_CANCEL,
    events::PLUGIN_QUERY,
    events::PLUGIN_QUERY_REPLY,
    events::PLUGIN_SYNC_RESULT,
];

#[test]
fn every_defined_name_is_valid_and_unique() {
    // A typo in a constant would otherwise only surface when a plugin failed to subscribe.
    let mut seen = std::collections::HashSet::new();
    for name in ALL_DEFINED {
        assert!(seen.insert(name), "duplicate event name: {name}");
        assert!(EventName::parse(name).is_ok(), "{name} does not parse");
    }
}

#[test]
fn transport_events_the_kernel_owns_are_never_plugin_subscribable() {
    // A built-in outside `_synra.` would be indistinguishable from a data-plane name, and a
    // plugin subscribing to it would be subscribing to the kernel's own link protocol.
    for name in [
        builtin::DEVICE_CHANGED,
        builtin::SHARE_RECEIVED,
        builtin::TRANSFER_COMPLETED,
        builtin::PLUGIN_INSTALLED,
        builtin::HOST_FOREGROUND,
        builtin::NETWORK_CHANGED,
    ] {
        assert!(name.starts_with(SYSTEM_PREFIX), "{name} is not under {SYSTEM_PREFIX}");
    }
}

#[test]
fn plugin_emittable_names_are_valid_event_names() {
    for name in PLUGIN_EMITTABLE {
        assert!(EventName::parse(name).is_ok(), "{name} does not parse");
    }
}

#[test]
fn events_round_trip_through_json_as_bare_strings() {
    let name = EventName::parse("_plugin.@acme/chat.text").expect("valid");
    let json = serde_json::to_string(&name).expect("serialises");
    assert_eq!(json, "\"_plugin.@acme/chat.text\"");

    let back: EventName = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, name);

    // An invalid name must not deserialise: validation on the way in means a value of this type
    // is always well formed.
    assert!(serde_json::from_str::<EventName>("\"not a name\"").is_err());
}

#[test]
fn display_matches_the_wire_form() {
    let name = EventName::parse(builtin::DEVICE_CHANGED).expect("valid");
    assert_eq!(name.to_string(), builtin::DEVICE_CHANGED);
}
