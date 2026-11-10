use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use synra_protocol::inbound::{HandlePattern, MAX_WILDCARD_RULES};
use super::{EventId, EventRegistry, MAX_DISTINCT_NAMES, RouteOutcome, PluginKey};

/// A plugin name.
fn arbitrary_plugin() -> impl Strategy<Value = PluginKey> {
    prop_oneof![
        Just(PluginKey::new("@a/one")),
        Just(PluginKey::new("@b/two")),
        Just(PluginKey::new("@c/three")),
    ]
}

/// A rule that always parses.
fn arbitrary_rule() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("device.ping".to_owned()),
        Just("device.pong".to_owned()),
        Just("_synra.device.*".to_owned()),
        Just("_synra.transfer.*".to_owned()),
        Just("_synra.*".to_owned()),
        Just("_plugin.@acme/chat.text".to_owned()),
    ]
}

/// An event name, including ones nobody subscribes to.
fn arbitrary_event() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("device.ping".to_owned()),
        Just("device.pong".to_owned()),
        Just("_synra.device.changed".to_owned()),
        Just("_synra.transfer.completed".to_owned()),
        Just("_synra.device.offline".to_owned()),
        Just("_plugin.@acme/chat.text".to_owned()),
        Just("_synra.unknown.thing".to_owned()),
    ]
}

proptest! {
    // Keep using the saved regression seeds from before this suite moved.
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/routing.txt"
        )))),
        ..ProptestConfig::default()
    })]

    /// A routed event names only plugins that hold a rule matching it. The property an attacker would try to
    /// defeat: no sequence of registrations makes an event reach a plugin that did not subscribe to it.
    #[test]
    fn routing_only_reaches_matching_subscribers(
        registrations in proptest::collection::vec((arbitrary_plugin(), proptest::collection::vec(arbitrary_rule(), 0..3)), 0..8),
        event in arbitrary_event(),
    ) {
        let mut registry = EventRegistry::new();
        let mut accepted: Vec<(PluginKey, Vec<String>)> = Vec::new();
        // A plugin that registers twice is a duplicate, so the expectation only holds for the first registration.
        let mut registered: Vec<PluginKey> = Vec::new();
        for (plugin, rules) in registrations {
            if registered.contains(&plugin) {
                continue;
            }
            if registry.register(&plugin, &rules).is_ok() {
                registered.push(plugin.clone());
                accepted.push((plugin, rules));
            }
        }

        if let RouteOutcome::Routed(plugins) = registry.route(&event) {
            for plugin in &plugins {
                let rules = accepted
                    .iter()
                    .find(|(candidate, _)| candidate == plugin)
                    .map(|(_, rules)| rules.clone())
                    .unwrap_or_default();
                let matches = rules.iter().any(|rule| {
                    if rule.contains('*') {
                        HandlePattern::parse(rule).map(|pattern| pattern.matches(&event)).unwrap_or(false)
                    }
                    else {
                        rule == &event
                    }
                });
                prop_assert!(matches, "{} received {} without a matching rule", plugin, event);
            }
            // And no plugin appears twice, which would run its handler twice for one event.
            let mut sorted = plugins.clone();
            sorted.sort();
            sorted.dedup();
            prop_assert_eq!(sorted.len(), plugins.len(), "a plugin was named twice");
        }
    }

    /// No route survives an unregister, for any sequence of registrations and removals. A route table holding a
    /// handle to an unloaded plugin is a use-after-free waiting for the right event.
    #[test]
    fn no_route_survives_an_unregister(
        operations in proptest::collection::vec(
            (any::<bool>(), arbitrary_plugin(), proptest::collection::vec(arbitrary_rule(), 1..3)),
            0..20,
        ),
        event in arbitrary_event(),
    ) {
        let mut registry = EventRegistry::new();
        // `currently_removed` rather than a history: a plugin that is unregistered and then registered again is a
        // subscriber, and a test that remembered every removal would report that as a leak.
        let mut currently_removed: Vec<PluginKey> = Vec::new();

        for (is_register, plugin, rules) in operations {
            if is_register {
                if registry.register(&plugin, &rules).is_ok() {
                    currently_removed.retain(|candidate| candidate != &plugin);
                }
            }
            else {
                registry.unregister(&plugin);
                if !currently_removed.contains(&plugin) {
                    currently_removed.push(plugin);
                }
            }
        }

        if let RouteOutcome::Routed(plugins) = registry.route(&event) {
            for plugin in &plugins {
                prop_assert!(
                    !currently_removed.contains(plugin),
                    "{} was unregistered and still receives {}",
                    plugin,
                    event,
                );
            }
        }
    }

    /// The distinct-name count never exceeds the bound, whatever names arrive. It is what stops a peer streaming
    /// unrecognised names from growing the kernel's memory without limit.
    #[test]
    fn the_name_count_never_exceeds_the_bound(names in proptest::collection::vec("[_a-z.]{1,24}", 0..2000)) {
        let mut registry = EventRegistry::new();
        for name in names {
            let _ = registry.route(&name);
            prop_assert!(
                registry.distinct_names() <= MAX_DISTINCT_NAMES,
                "held {} of {}",
                registry.distinct_names(),
                MAX_DISTINCT_NAMES,
            );
        }
    }

    /// The wildcard rule count never exceeds the bound. Unlike the name bound this one is enforced at registration,
    /// because the wildcard rules are scanned on every frame and their number is the per-frame cost.
    #[test]
    fn the_wildcard_count_never_exceeds_the_bound(
        registrations in proptest::collection::vec(
            (arbitrary_plugin(), proptest::collection::vec("_synra\\.[a-z]{1,4}\\.[*]", 1..8)),
            0..40,
        ),
    ) {
        let mut registry = EventRegistry::new();
        for (plugin, rules) in registrations {
            let _ = registry.register(&plugin, &rules);
            prop_assert!(
                registry.wildcard_rules() <= MAX_WILDCARD_RULES,
                "held {} of {}",
                registry.wildcard_rules(),
                MAX_WILDCARD_RULES,
            );
        }
    }

    /// A number is stable: once a name has one, the same name always answers with the same number and the number
    /// always answers with the same name. Renumbering would invalidate every route that was compiled against it.
    #[test]
    fn a_number_is_stable(
        names in proptest::collection::vec("[_a-z.]{1,24}", 1..40),
        probes in proptest::collection::vec("[_a-z.]{1,24}", 0..40),
    ) {
        let mut registry = EventRegistry::new();
        for name in &names {
            let _ = registry.route(name);
        }
        // Record the numbers.
        let recorded: Vec<(String, Option<EventId>)> =
            names.iter().map(|name| (name.clone(), registry.id_for(name))).collect();

        for probe in &probes {
            let _ = registry.route(probe);
        }

        for (name, id) in recorded {
            prop_assert_eq!(registry.id_for(&name), id, "{} was renumbered", name);
            if let Some(id) = id {
                prop_assert_eq!(registry.name_for(id), Some(name.as_str()));
            }
        }
    }
}
