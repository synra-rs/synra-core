//! Event names: the grammar, the catalogue, and what a plugin is allowed to emit.
//!
//! # Two kinds of event, and why the line matters
//!
//! * **Built-in events** are the host's. Their names are defined here, their payload shapes are
//!   defined by the host, and they describe *capabilities* — "a device came online", "a transfer
//!   finished and its digest checked out", "a share arrived that no plugin claimed".
//! * **Plugin events** are an author's. They live under `_plugin.<full-plugin-id>.`, and the plugin declares
//!   their payload shape in its manifest.
//!
//! The host does not try to guess what a plugin's events mean. It cannot: the whole point of a
//! plugin is that it knows something the host does not. So the host reports what happened, and the
//! plugin decides what it means.
//!
//! # The namespace rule is enforced, not documented
//!
//! [`EventName::plugin`] preserves the complete identity it is given, and [`EventName::plugin_scope`] tells a
//! caller whether a name belongs to a plugin and which one. A plugin that could emit
//! `_plugin.@acme/someone-else.thing` could impersonate another plugin, so the check lives in the type
//! rather than in a convention someone has to remember.
//!
//! # Names are interned elsewhere
//!
//! Comparison here is by string, which is correct but not free. Routing does not use it: the host
//! resolves a name to a small integer once and looks that up thereafter, so the per-frame cost is an
//! array index rather than a string compare.
/// Prefix for host-defined events.
pub const SYSTEM_PREFIX: &str = "_synra.";

/// Prefix for plugin-defined events.
pub const PLUGIN_PREFIX: &str = "_plugin.";

/// Prefix reserved for events that never leave the process.
pub const INTERNAL_PREFIX: &str = "synra.internal.";

/// Event-name byte bound, leaving 16 bytes for the longest event capability prefix.
/// Full package identities remain within the shared 256-byte capability grammar limit.
pub const MAX_EVENT_NAME_LEN: usize = 240;

/// The largest gap a consumer is told the *size* of.
///
/// # Why a gap has a size at all, and why it is capped
///
/// When events are lost — a subscriber that fell behind, a link that reconnected — the consumer learns that it missed
/// some and, when it is worth saying, how many. The count is useful: one missed event is a hiccup, and ten thousand is
/// a subscriber that stopped keeping up and a bug worth reporting.
///
/// Beyond the cap the consumer is told only that there was a gap, which is the same instruction — re-read the snapshot
/// — without a number it would believe. A *reported* count of four billion says nothing.
pub const MAX_COUNTED_GAP: u32 = 1_000;

mod name;
mod catalog;

pub use catalog::*;
pub use name::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::PluginId;
    use rstest::rstest;

    fn slug(text: &str) -> PluginId {
        PluginId::parse(&format!("@acme/{text}")).expect("valid plugin id")
    }

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
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::ids::PluginId;
    use proptest::prelude::*;

    fn slug_text() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9-]{0,20}".prop_map(|text| {
            let trimmed = text.trim_end_matches('-');
            if trimmed.is_empty() { "a".to_owned() } else { trimmed.to_owned() }
        })
    }

    fn logical_text() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z][a-z0-9]{0,8}", 1..4).prop_map(|parts| parts.join("."))
    }

    proptest! {
        /// Anything a constructor accepts parses back to itself and reports the owner it was given.
        #[test]
        fn plugin_events_name_their_owner(slug in slug_text(), logical in logical_text()) {
            let slug = PluginId::parse(&format!("@acme/{slug}")).expect("valid generated identity");
            let name = EventName::plugin(&slug, &logical).expect("builds");
            prop_assert!(name.is_plugin());
            prop_assert_eq!(name.plugin_scope().map(|(owner, _)| owner), Some(slug.as_str()));
            prop_assert_eq!(name.check_emittable_by(&slug), Ok(()));
        }

        /// A plugin can never emit under a namespace it does not own, whatever the names are.
        #[test]
        fn foreign_namespaces_are_always_refused(
            owner in slug_text(),
            other in slug_text(),
            logical in logical_text(),
        ) {
            prop_assume!(owner != other);
            let owner = PluginId::parse(&format!("@acme/{owner}")).expect("valid");
            let other = PluginId::parse(&format!("@acme/{other}")).expect("valid");
            let name = EventName::plugin(&owner, &logical).expect("builds");
            prop_assert!(name.check_emittable_by(&other).is_err());
        }

        /// Arbitrary text either parses or is rejected. It never panics, and a parsed name survives
        /// a trip through the wire format unchanged.
        #[test]
        fn parse_is_total_and_round_trips(text in ".{0,140}") {
            if let Ok(name) = EventName::parse(&text) {
                // The wire form is the input, unchanged.
                prop_assert_eq!(name.as_str(), text.as_str());

                let json = serde_json::to_string(&name).expect("serialises");
                let back: EventName = serde_json::from_str(&json).expect("deserialises");
                prop_assert_eq!(back, name);
            }
        }
    }
}

