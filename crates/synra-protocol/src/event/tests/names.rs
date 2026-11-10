use crate::ids::PluginId;
use rstest::rstest;
use super::super::{EventName, EventNameError, MAX_EVENT_NAME_LEN, events};
use super::slug;

#[test]
fn host_events_parse_and_are_recognised() {
    let name = EventName::parse(events::BYE).expect("valid");
    assert!(name.is_transport(), "device.* is the link protocol");
    assert!(!name.is_system(), "only _synra.* is the host event namespace");
    assert!(!name.is_plugin());
    assert!(!name.is_data_plane());
    assert_eq!(name.plugin_scope(), None);
    assert_eq!(name.as_str(), "device.bye");
}

#[test]
fn data_plane_names_are_bare() {
    let name = EventName::parse("file.transfer.chunk").expect("valid");
    assert!(name.is_data_plane());
    assert!(!name.is_system());
    assert!(!name.is_plugin());
}

#[test]
fn plugin_events_expose_their_owner() {
    let name = EventName::parse("_plugin.@acme/chat.text").expect("valid");
    assert!(name.is_plugin());
    assert_eq!(name.plugin_scope(), Some(("@acme/chat", "text")));
    // Dotted logical names nest, and still report the owner correctly.
    let nested = EventName::parse("_plugin.@acme/chat.room.message").expect("valid");
    assert_eq!(nested.plugin_scope(), Some(("@acme/chat", "room.message")));
}

#[rstest]
#[case("")]
#[case("device..ping")]
#[case("_synra.")]
#[case("_synra..x")]
#[case("synra.internal.")]
#[case("_plugin.@acme/chat")]
#[case("_plugin..text")]
#[case("_plugin.Chat.text")]
#[case("_plugin.@acme/chat.")]
fn malformed_names_are_rejected(#[case] name: &str) {
    assert!(EventName::parse(name).is_err(), "{name:?} should not parse");
}

#[test]
fn package_scope_and_conventional_prefixes_cannot_alias_event_owners() {
    let owner = PluginId::parse("@acme/chat").unwrap();
    let name = EventName::plugin(&owner, "ready").unwrap();
    for foreign in ["@other/chat", "@acme/synra-plugin-chat", "@acme/chat-extra"] {
        let foreign = PluginId::parse(foreign).unwrap();
        assert_ne!(owner.event_namespace(), foreign.event_namespace());
        assert!(matches!(
            name.check_emittable_by(&foreign),
            Err(EventNameError::ForeignNamespace { .. })
        ));
    }
    assert_eq!(name.check_emittable_by(&owner), Ok(()));
    for legacy in ["_plugin.chat.ready", "_plugin.synra-plugin-chat.ready"] {
        assert!(EventName::parse(legacy).is_err());
    }
}

#[test]
fn maximal_package_ids_still_have_a_bounded_event_namespace() {
    let owner = PluginId::parse(&format!("@{}/{}", "a".repeat(62), "b".repeat(64))).unwrap();
    assert_eq!(owner.as_str().len(), crate::ids::MAX_PLUGIN_ID_LEN);
    let logical = "x".repeat(MAX_EVENT_NAME_LEN - owner.event_namespace().len());
    let name = EventName::plugin(&owner, &logical).unwrap();
    assert_eq!(name.as_str().len(), MAX_EVENT_NAME_LEN);
    assert_eq!(name.check_emittable_by(&owner), Ok(()));
    assert!(matches!(
        EventName::plugin(&owner, &format!("{logical}x")),
        Err(EventNameError::TooLong { .. })
    ));
}

#[test]
fn names_have_a_length_limit() {
    let long = "a".repeat(MAX_EVENT_NAME_LEN + 1);
    assert!(matches!(
        EventName::parse(&long),
        Err(EventNameError::TooLong { .. })
    ));
}

#[test]
fn a_wildcard_is_not_a_sendable_event_name() {
    // `*` belongs to `handles` patterns, which describe what a plugin wants to receive. A
    // pattern is not a name: nothing can be sent as `_plugin.@acme/chat.*`. Keeping the two grammars
    // apart means an `EventName` is always something a peer could legitimately have sent.
    for pattern in ["_plugin.@acme/chat.*", "_synra.*", "file.*", "*"] {
        assert!(
            EventName::parse(pattern).is_err(),
            "{pattern:?} is a pattern, not a name",
        );
    }
    // The matching grammar accepts them; see `inbound::HandlePattern`.
    assert!(crate::inbound::HandlePattern::parse("_plugin.@acme/chat.*").is_ok());
}

#[test]
fn characters_outside_the_grammar_are_refused() {
    // A name that could be read as a path, a shell argument or a URL fragment is refused, so a
    // name can never be passed to another system and mean something there.
    for name in [
        "_plugin.@acme/chat.a/b",
        "device.pi ng",
        "device.ping;rm",
        "a..b",
    ] {
        assert!(EventName::parse(name).is_err(), "{name:?} should not parse");
    }
}

#[test]
fn constructors_produce_the_expected_shape() {
    assert_eq!(
        EventName::system("device.changed").expect("valid").as_str(),
        "_synra.device.changed"
    );
    assert_eq!(
        EventName::plugin(&slug("chat"), "text").expect("valid").as_str(),
        "_plugin.@acme/chat.text"
    );
    assert_eq!(
        EventName::internal("host.boot").expect("valid").as_str(),
        "synra.internal.host.boot"
    );
    assert!(EventName::internal("host.boot").expect("valid").is_internal());
}
