use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use crate::envelope::Envelope;
use crate::event::EventName;

use super::{HandlePattern, Inbound};

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/inbound.txt"
        )))),
        ..ProptestConfig::default()
    })]

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
