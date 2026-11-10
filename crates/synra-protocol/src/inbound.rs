//! Inbound dispatch: what happens to a message once it has been read off the wire.
//!
//! The frame layer is **structure**; this layer is **content**. The difference dictates the whole
//! design, and the two rules look contradictory until you separate them:
//!
//! * A structural problem closes the link. If a length field is wrong, every subsequent frame
//!   boundary is wrong, so continuing produces nonsense indefinitely.
//! * An unknown *event* is recorded and ignored. A newer peer may legitimately send something this
//!   build has never heard of, and the stream is still perfectly readable. Closing the link would
//!   make a version difference look like corruption.
//!
//! # What this module decides
//!
//! Given a validated envelope, classify it into one of four kinds, and produce the routing decision:
//!
//! | Kind | Delivered to plugins? | On an unrecognised name |
//! |---|---|---|
//! | [`Inbound::Transport`] | never | — (the frame layer owns these) |
//! | [`Inbound::Kernel`] | never | refused as a protocol violation |
//! | [`Inbound::Builtin`] | yes, to subscribers | — |
//! | [`Inbound::DataPlane`] | yes, to subscribers | refused: they drive a state machine |
//! | [`Inbound::Plugin`] | yes, to subscribers | recorded and ignored |
//!
//! # Why `handles` patterns are a separate grammar
//!
//! A [`HandlePattern`] may contain `*`, and an [`EventName`] may not. That separation is load-bearing:
//! `_plugin.@acme/chat.*` describes what a plugin wants to *receive* and can never be sent, so a routing
//! table built from names never has to ask whether one of its entries is a pattern. Two grammars,
//! two types, no ambiguity.
//!
//! # High-frequency events
//!
//! [`builtin::TRANSFER_PROGRESS`] and [`builtin::NETWORK_CHANGED`] are marked as coalescable. They
//! exist so a user interface can show progress, and a progress report superseded by the next one has
//! no value — delivering all of them spends a plugin invocation per frame to tell it something it
//! already knows. [`CoalesceBuffer`] keeps only the newest of each, so a slow consumer sees the
//! current state rather than a queue of history.
//!
//! Nothing else is coalescable, and the list is closed. Coalescing a business event would silently
//! drop it, which is a different thing from dropping a stale progress report.

#[path = "inbound/builtin/mod.rs"]
mod builtin_events;
mod classify;
mod coalesce;
mod handles;
mod pattern;

pub use builtin_events::{BuiltinEvent, BuiltinParseError, DeviceSnapshot, NetworkChangeKind, ShareItem};
pub use classify::{Inbound, UnknownReason};
pub use coalesce::{CoalesceBuffer, coalescable_names};
pub use handles::{HandleSet, HandleSetError, inbound_error_to_synra};
pub use pattern::{HandlePattern, PatternError, MAX_PATTERN_WILDCARDS, MAX_WILDCARD_RULES};

#[cfg(test)]
use crate::envelope::Envelope;
#[cfg(test)]
use crate::error::ErrorCode;
#[cfg(test)]
use crate::event::{builtin, events, DataPlaneEvent, EventName};
#[cfg(test)]
use crate::ids::PluginId;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, OutboundSpec};
    use crate::event::EventName;
    use crate::ids::{DeviceId, TraceId};

    #[test]
    fn package_patterns_keep_publisher_identity_and_have_a_length_bound() {
        let pattern = HandlePattern::parse("_plugin.@acme/chat.*").unwrap();
        assert!(pattern.matches("_plugin.@acme/chat.ready"));
        assert!(!pattern.matches("_plugin.@other/chat.ready"));
        assert!(!pattern.matches("_plugin.@acme/synra-plugin-chat.ready"));
        for bad in [
            "_plugin.chat.*",
            "_plugin.@acme/../chat.*",
            "_plugin.@acme/chat.topic/extra",
        ] {
            assert!(HandlePattern::parse(bad).is_err(), "{bad}");
        }
        let prefix = "_plugin.@acme/chat.";
        let at_limit = format!(
            "{prefix}{}",
            "x".repeat(crate::event::MAX_EVENT_NAME_LEN - prefix.len())
        );
        assert!(HandlePattern::parse(&at_limit).is_ok());
        assert!(matches!(
            HandlePattern::parse(&format!("{at_limit}x")),
            Err(PatternError::TooLong { .. })
        ));
    }

    fn slug(text: &str) -> PluginId {
        PluginId::parse(&format!("@acme/{text}")).expect("valid plugin id")
    }

    fn envelope(event: &str, from: DeviceId, target: DeviceId) -> Envelope {
        Envelope::outbound(
            OutboundSpec {
                event: EventName::parse(event).expect("valid event"),
                target,
                from,
                trace_id: TraceId::new(),
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&()>,
        )
        .expect("builds")
    }

    // ── HandlePattern ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_exact_pattern_matches_only_itself() {
        let pattern = HandlePattern::parse("_synra.transfer.completed").expect("valid");
        assert!(pattern.is_exact());
        assert_eq!(pattern.wildcard_count(), 0);
        assert!(pattern.matches("_synra.transfer.completed"));
        assert!(!pattern.matches("_synra.transfer.failed"));
        // A prefix is not a match: `handles` is not a glob language.
        assert!(!pattern.matches("_synra.transfer.completed.extra"));
    }

    #[test]
    fn a_trailing_wildcard_matches_exactly_one_segment() {
        let pattern = HandlePattern::parse("_plugin.@acme/chat.*").expect("valid");
        assert!(!pattern.is_exact());
        assert_eq!(pattern.wildcard_count(), 1);

        assert!(pattern.matches("_plugin.@acme/chat.text"));
        assert!(pattern.matches("_plugin.@acme/chat.typing"));
        // Deeper names do not match. A pattern that could match an unbounded number of segments
        // makes "which plugin gets this event" unanswerable from a manifest.
        assert!(!pattern.matches("_plugin.@acme/chat.room.message"));
        // And neither does a shorter one.
        assert!(!pattern.matches("_plugin.@acme/chat"));
        // Nor another plugin's namespace.
        assert!(!pattern.matches("_plugin.@acme/notes.text"));
    }

    #[test]
    fn a_wildcard_family_matches_its_prefix_only() {
        let pattern = HandlePattern::parse("file.transfer.*").expect("valid");
        assert!(pattern.matches("file.transfer.chunk"));
        assert!(pattern.matches("file.transfer.complete"));
        assert!(!pattern.matches("file.other.chunk"));
        // The prefix must end at a segment boundary, not mid-character.
        assert!(!pattern.matches("file.transferX.chunk"));
    }

    #[test]
    fn multiple_trailing_wildcards_are_allowed() {
        let pattern = HandlePattern::parse("_synra.*.*").expect("valid");
        assert_eq!(pattern.wildcard_count(), 2);
        assert!(pattern.matches("_synra.device.changed"));
        assert!(!pattern.matches("_synra.device.changed.now"));

        // An all-wildcard pattern matches any name of the right length.
        let any_two = HandlePattern::parse("*.*").expect("valid");
        assert!(any_two.matches("a.b"));
        assert!(!any_two.matches("a.b.c"));
        assert!(!any_two.matches("a"));
    }

    #[test]
    fn a_partial_wildcard_is_refused() {
        // `tex*` is a different feature. Accepting it silently would make a manifest mean something
        // its author did not intend.
        assert!(matches!(
            HandlePattern::parse("_plugin.@acme/chat.tex*"),
            Err(PatternError::PartialWildcard(_))
        ));
        assert!(HandlePattern::parse("_plugin.*chat.text").is_err());
    }

    #[test]
    fn malformed_patterns_are_refused() {
        assert!(matches!(HandlePattern::parse(""), Err(PatternError::Empty)));
        assert!(matches!(
            HandlePattern::parse("_plugin..text"),
            Err(PatternError::EmptySegment(_))
        ));
        assert!(matches!(
            HandlePattern::parse("_plugin.@acme/chat.a/b"),
            Err(PatternError::BadCharacter { .. })
        ));
        assert!(matches!(
            HandlePattern::parse("_plugin.@acme/chat.a b"),
            Err(PatternError::BadCharacter { .. })
        ));
    }

    #[test]
    fn wildcard_count_is_bounded() {
        // One wildcard too many.
        let mut pattern = String::from("x");
        for _ in 0..=MAX_PATTERN_WILDCARDS {
            pattern.push_str(".*");
        }
        assert!(matches!(
            HandlePattern::parse(&pattern),
            Err(PatternError::TooManyWildcards { .. })
        ));

        // Exactly at the limit is fine.
        let mut at_limit = String::from("x");
        for _ in 0..MAX_PATTERN_WILDCARDS {
            at_limit.push_str(".*");
        }
        assert!(HandlePattern::parse(&at_limit).is_ok());
    }

    #[test]
    fn exact_patterns_and_wildcards_agree_with_event_names() {
        // A pattern that parses must be able to match at least one *sendable* name, or the plugin
        // declares a subscription that can never fire.
        let pattern = HandlePattern::parse("_plugin.@acme/chat.*").expect("valid");
        assert!(pattern.matches("_plugin.@acme/chat.text"));
        assert!(EventName::parse("_plugin.@acme/chat.text").is_ok());
    }

    // ── HandleSet ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_handle_set_separates_exact_from_wildcards() {
        let set = HandleSet::compile([
            "_synra.transfer.completed",
            "_synra.device.changed",
            "_plugin.@acme/chat.*",
        ])
        .expect("compiles");

        assert_eq!(set.exact_count(), 2);
        assert_eq!(set.wildcard_count(), 1);
        assert!(!set.is_empty());

        assert!(set.matches("_synra.transfer.completed"));
        assert!(set.matches("_plugin.@acme/chat.text"));
        assert!(!set.matches("_synra.share.received"));
        assert!(!set.matches("_plugin.@acme/notes.text"));
    }

    #[test]
    fn an_empty_handle_set_matches_nothing() {
        let set = HandleSet::compile(Vec::<String>::new()).expect("compiles");
        assert!(set.is_empty());
        assert!(!set.matches("_synra.device.changed"));
    }

    #[test]
    fn a_bad_pattern_fails_the_whole_declaration() {
        // Better to refuse at load than to install a plugin whose subscriptions are silently
        // missing an entry.
        let result = HandleSet::compile(["_synra.device.changed", "not a pattern"]);
        assert!(matches!(result, Err(HandleSetError::Pattern(_))));
    }

    #[test]
    fn wildcard_rules_are_bounded() {
        let many: Vec<String> = (0..=MAX_WILDCARD_RULES)
            .map(|i| format!("_plugin.@acme/p{i}.*"))
            .collect();
        assert!(matches!(
            HandleSet::compile(many),
            Err(HandleSetError::TooManyWildcards { max: MAX_WILDCARD_RULES })
        ));

        let at_limit: Vec<String> = (0..MAX_WILDCARD_RULES)
            .map(|i| format!("_plugin.@acme/p{i}.*"))
            .collect();
        assert!(HandleSet::compile(at_limit).is_ok());
    }

    // ── Classification ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transport_events_are_never_plugin_visible() {
        // A plugin that could observe or inject these would be inside the transport rather than on
        // top of it.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for name in [
            events::HELLO,
            events::HELLO_ACK,
            events::ACK,
            events::PING,
            events::PONG,
            events::BYE,
            events::ERROR,
        ] {
            let inbound = Inbound::classify(envelope(name, a, b));
            assert!(matches!(inbound, Inbound::Transport { .. }), "{name}");
            assert!(!inbound.is_plugin_visible(), "{name}");
            assert!(!inbound.is_ignorable(), "{name}");
        }
    }

    #[test]
    fn kernel_events_are_never_plugin_visible() {
        // These drive the kernel's own sessions. A plugin able to see them could observe every
        // intent the user dispatches.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for name in [
            events::INTENT_INVOKE,
            events::INTENT_RESULT,
            events::INTENT_CANCEL,
            events::PLUGIN_QUERY,
            events::PLUGIN_QUERY_REPLY,
            events::PLUGIN_SYNC_RESULT,
        ] {
            let inbound = Inbound::classify(envelope(name, a, b));
            assert!(matches!(inbound, Inbound::Kernel { .. }), "{name}");
            assert!(!inbound.is_plugin_visible(), "{name}");
        }
    }

    #[test]
    fn builtin_events_are_plugin_visible() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for name in builtin::ALL {
            let inbound = Inbound::classify(envelope(name, a, b));
            assert!(matches!(inbound, Inbound::Builtin { .. }), "{name}");
            assert!(inbound.is_plugin_visible(), "{name}");
        }
    }

    #[test]
    fn data_plane_events_are_classified_as_such() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for event in [
            DataPlaneEvent::FileTransferRequest,
            DataPlaneEvent::FileTransferChunk,
            DataPlaneEvent::FileTransferComplete,
            DataPlaneEvent::FileTransferAbort,
            DataPlaneEvent::FileTransferProgress,
        ] {
            let inbound = Inbound::classify(envelope(event.as_str(), a, b));
            match inbound {
                Inbound::DataPlane { event: got, .. } => assert_eq!(got, event),
                other => panic!("expected a data-plane event, got {other:?}"),
            }
            assert!(inbound.is_plugin_visible());
        }
    }

    #[test]
    fn plugin_events_report_their_owner() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let inbound = Inbound::classify(envelope("_plugin.@acme/chat.text", a, b));
        match inbound {
            Inbound::Plugin { owner, .. } => assert_eq!(owner, slug("chat")),
            other => panic!("expected a plugin event, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_builtin_is_recorded_and_ignored() {
        // A newer peer may send an event this version has never heard of. The frames are perfectly
        // readable, so refusing the link would make a version difference look like corruption.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let inbound = Inbound::classify(envelope("_synra.device.teleported", a, b));

        match &inbound {
            Inbound::Unknown { reason, .. } => {
                assert_eq!(*reason, UnknownReason::NotInCatalogue);
            }
            other => panic!("expected an unknown event, got {other:?}"),
        }
        assert!(inbound.is_ignorable(), "an unknown built-in must not break the link");
        assert!(!inbound.is_plugin_visible(), "nobody can have subscribed to it");
    }

    #[test]
    fn an_unknown_data_plane_event_is_not_ignorable() {
        // Data-plane events drive a transfer state machine. Silently ignoring one leaves the
        // transfer stuck with no error anywhere, which is worse than a clear refusal.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let inbound = Inbound::classify(envelope("file.transfer.teleport", a, b));

        match &inbound {
            Inbound::Unknown { reason, .. } => {
                assert_eq!(*reason, UnknownReason::UnrecognisedDataPlane);
            }
            other => panic!("expected an unknown data-plane event, got {other:?}"),
        }
        assert!(!inbound.is_ignorable());

        let error = inbound_error_to_synra(UnknownReason::UnrecognisedDataPlane, inbound.event());
        assert_eq!(error.code, ErrorCode::ProtocolViolation);
    }

    #[test]
    fn an_unknown_builtin_maps_to_not_found() {
        let name = EventName::parse("_synra.device.teleported").expect("valid");
        let error = inbound_error_to_synra(UnknownReason::NotInCatalogue, &name);
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[test]
    fn every_classified_message_keeps_its_envelope() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let original = envelope("_plugin.@acme/chat.text", a, b);
        let request_id = original.request_id;

        for inbound in [
            Inbound::classify(envelope("device.ping", a, b)),
            Inbound::classify(envelope(builtin::DEVICE_CHANGED, a, b)),
            Inbound::classify(envelope("file.transfer.chunk", a, b)),
            Inbound::classify(original),
            Inbound::classify(envelope("_synra.unknown.thing", a, b)),
        ] {
            assert_eq!(inbound.envelope().from, a);
            assert_eq!(inbound.envelope().target, b);
            // And the message can be taken back out without losing anything.
            let recovered = inbound.into_envelope();
            assert_eq!(recovered.from, a);
        }

        assert_ne!(request_id, crate::ids::RequestId::new());
    }

    // ── Coalescing ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn only_high_frequency_events_are_coalescable() {
        assert_eq!(
            coalescable_names(),
            &[builtin::TRANSFER_PROGRESS, builtin::NETWORK_CHANGED]
        );

        let progress = BuiltinEvent::parse(
            &EventName::parse(builtin::TRANSFER_PROGRESS).expect("valid"),
            None,
        )
        .expect("a known built-in");
        assert!(progress.is_coalescable());
        assert_eq!(progress.name(), builtin::TRANSFER_PROGRESS);

        // A business event must never be coalesced: dropping one silently is not the same as
        // dropping a stale progress report.
        let completed = BuiltinEvent::parse(
            &EventName::parse(builtin::TRANSFER_COMPLETED).expect("valid"),
            None,
        )
        .expect("a known built-in");
        assert!(!completed.is_coalescable());

        for name in coalescable_names() {
            assert!(
                name.starts_with("_synra."),
                "{name} is coalescable but is not a host progress event",
            );
        }
    }

    #[test]
    fn a_progress_report_replaces_its_predecessor() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();

        assert!(!buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b))));
        assert_eq!(buffer.len(), 1);

        // The second one is coalesced, so a slow consumer sees the current state rather than a
        // queue of history.
        assert!(buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b))));
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn a_coalesced_entry_keeps_its_place_in_the_queue() {
        // Moving it to the end would reorder it behind events that arrived later but matter less.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();

        buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b)));
        buffer.push(Inbound::classify(envelope(builtin::DEVICE_CHANGED, a, b)));
        buffer.push(Inbound::classify(envelope(builtin::NETWORK_CHANGED, a, b)));
        buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b)));

        let drained = buffer.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].event.as_str(), builtin::TRANSFER_PROGRESS);
        assert_eq!(drained[1].event.as_str(), builtin::DEVICE_CHANGED);
        assert_eq!(drained[2].event.as_str(), builtin::NETWORK_CHANGED);
        assert!(buffer.is_empty());
    }

    #[test]
    fn ordinary_events_are_never_dropped_by_coalescing() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();

        for _ in 0..5 {
            buffer.push(Inbound::classify(envelope(builtin::PLUGIN_INSTALLED, a, b)));
        }
        // Five distinct events, five entries: a business event is not superseded by the next one.
        assert_eq!(buffer.len(), 5);
    }

    #[test]
    fn draining_empties_the_buffer() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();
        buffer.push(Inbound::classify(envelope(builtin::HOST_FOREGROUND, a, b)));

        assert_eq!(buffer.drain().len(), 1);
        assert!(buffer.is_empty());
        assert!(buffer.drain().is_empty());
    }
}
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A compiled pattern matches exactly the names it should, checked against a reference
        /// implementation written the obvious way. The fast path and the obvious path must agree.
        #[test]
        fn pattern_matching_agrees_with_a_reference(
            prefix in "[a-z][a-z0-9]{0,6}",
            wildcards in 0u8..3,
            extra_segments in 0usize..3,
        ) {
            let mut pattern = prefix.clone();
            for _ in 0..wildcards {
                pattern.push_str(".*");
            }
            let pattern = HandlePattern::parse(&pattern).expect("the generator makes valid patterns");

            // Reference: split both and compare segment by segment, with `*` matching any one.
            let reference = |name: &str| {
                let expected: Vec<&str> = pattern.as_str().split('.').collect();
                let actual: Vec<&str> = name.split('.').collect();
                expected.len() == actual.len()
                    && expected
                        .iter()
                        .zip(&actual)
                        .all(|(want, got)| *want == "*" || want == got)
            };

            let mut candidate = prefix;
            for _ in 0..extra_segments {
                candidate.push_str(".seg");
            }
            prop_assert_eq!(pattern.matches(&candidate), reference(&candidate));
        }

        /// Any text either compiles as a pattern or is refused with a reason. It never panics, and a
        /// compiled pattern never matches a name with a different segment count.
        #[test]
        fn pattern_parsing_is_total(text in ".{0,60}") {
            if let Ok(pattern) = HandlePattern::parse(&text) {
                let segments = pattern.as_str().split('.').count();
                let wrong_count = "a.".repeat(segments + 1);
                prop_assert!(!pattern.matches(&wrong_count), "matched a name of the wrong length");
            }
        }

        /// Classification is total: any valid event name produces exactly one kind, and only the
        /// plugin-visible kinds may reach a plugin.
        ///
        /// The generator always produces at least two segments after the namespace, because a plugin
        /// event is `_plugin.<slug>.<name>` and `_plugin.a` alone is not a name at all.
        #[test]
        fn classification_is_total(
            name in "(_synra|_plugin|device|file)\\.[a-z]{1,10}(\\.[a-z]{1,10}){1,3}",
        ) {
            let event = match EventName::parse(&name) {
                Ok(event) => event,
                // A generated shape the grammar rejects is not a case worth asserting about; the
                // grammar has its own tests.
                Err(_) => return Ok(()),
            };
            let envelope = Envelope::outbound(
                crate::envelope::OutboundSpec {
                    event,
                    target: crate::ids::DeviceId::new(),
                    from: crate::ids::DeviceId::new(),
                    trace_id: crate::ids::TraceId::new(),
                    sent_at_ms: 0,
                    ttl_ms: None,
                },
                None::<&()>,
            ).expect("builds");

            let inbound = Inbound::classify(envelope);
            // Transport and kernel messages are never plugin visible; that is the invariant the
            // kernel relies on when it assumes an established link's plugin traffic is legitimate.
            match &inbound {
                Inbound::Transport { .. } | Inbound::Kernel { .. } => {
                    prop_assert!(!inbound.is_plugin_visible());
                }
                Inbound::Unknown { envelope, .. } => {
                    prop_assert!(!inbound.is_plugin_visible());
                    prop_assert_eq!(&envelope.event, inbound.event());
                }
                _ => {
                    prop_assert!(inbound.is_plugin_visible());
                }
            }
        }
    }
}

