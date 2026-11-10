use synra_protocol::inbound::MAX_WILDCARD_RULES;
use super::super::{MAX_DISTINCT_NAMES, RouteOutcome, RouterError};
use super::{key, registry, rules};

#[test]
fn a_duplicate_rule_is_refused() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");
    match registry.register(&key("@a/one"), &rules(&["device.ping"])) {
        Err(RouterError::Duplicate { plugin, rule }) => {
            assert_eq!(plugin, "@a/one");
            assert_eq!(rule, "device.ping");
        }
        other => panic!("expected a duplicate refusal, got {other:?}"),
    }
}

#[test]
fn two_plugins_may_hold_the_same_rule() {
    // The rule is the same and the subscribers differ, which is ordinary.
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["_synra.device.*"]))
        .expect("registers");
    registry
        .register(&key("@b/two"), &rules(&["_synra.device.*"]))
        .expect("registers");
    assert_eq!(registry.subscriber_count(), 2);
}

#[test]
fn a_bad_rule_is_refused() {
    let mut registry = registry();
    for rule in ["", "has space", "_synra.*.*.*.*.*"] {
        assert!(
            matches!(
                registry.register(&key("@a/one"), &rules(&[rule])),
                Err(RouterError::BadRule { .. })
            ),
            "{rule:?} should be refused"
        );
    }
    // And nothing was registered.
    assert_eq!(registry.subscriber_count(), 0);
    assert_eq!(registry.wildcard_rules(), 0);
}

#[test]
fn a_bad_rule_refuses_the_whole_registration() {
    // Registering the good rules would leave a plugin that receives some of what it asked for and none of what it
    // did not, which reads as a plugin with a bug rather than as a manifest that was refused.
    let mut registry = registry();
    let result = registry.register(&key("@a/one"), &rules(&["device.ping", "has space"]));
    assert!(result.is_err());
    assert_eq!(
        registry.subscriber_count(),
        0,
        "a partial registration happened"
    );
    assert!(matches!(
        registry.route("device.ping"),
        RouteOutcome::Nobody
    ));
}

#[test]
fn the_wildcard_bound_is_enforced() {
    let mut registry = registry();
    // Fill the bound with rules that all parse.
    let many: Vec<String> = (0..MAX_WILDCARD_RULES)
        .map(|index| format!("_synra.f{index}.*"))
        .collect();
    registry
        .register(&key("@a/one"), &many)
        .expect("registers up to the bound");

    match registry.register(&key("@b/two"), &rules(&["_synra.extra.*"])) {
        Err(RouterError::TooManyWildcards { limit }) => assert_eq!(limit, MAX_WILDCARD_RULES),
        other => panic!("expected a wildcard refusal, got {other:?}"),
    }
    // And the refusal did not register the second plugin.
    assert_eq!(registry.subscriber_count(), 1);
}

#[test]
fn the_bounds_are_the_documented_ones() {
    // The values the design document gives, asserted so raising one is a decision rather than an accident. The\n        // wildcard bound is also `synra_protocol`'s, and `register` enforces it against that constant.
    assert_eq!(MAX_DISTINCT_NAMES, 1_024);
    assert_eq!(MAX_WILDCARD_RULES, 64);
}

// ── The bound on names ────────────────────────────────────────────────────────────────────────

#[test]
fn an_unknown_name_past_the_bound_is_dropped_rather_than_numbered() {
    // A dropped event is a feature that does not work; unbounded memory is a device that stops working.
    let mut registry = registry();
    for index in 0..MAX_DISTINCT_NAMES {
        let _ = registry.route(&format!("_synra.streaming.{index}"));
    }
    assert_eq!(registry.distinct_names(), MAX_DISTINCT_NAMES);

    match registry.route("_synra.one.too.many") {
        RouteOutcome::Unknown { distinct } => assert_eq!(distinct, MAX_DISTINCT_NAMES),
        other => panic!("expected an unknown outcome, got {other:?}"),
    }
    assert_eq!(
        registry.distinct_names(),
        MAX_DISTINCT_NAMES,
        "the bound was exceeded"
    );
}

#[test]
fn a_known_name_still_routes_once_the_registry_is_full() {
    // The bound is on *new* names. A device whose registry is full must still deliver the events its plugins
    // actually asked for, or the bound would break every plugin rather than only the unrecognised traffic.
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["_synra.device.changed"]))
        .expect("registers");
    for index in 0..MAX_DISTINCT_NAMES {
        let _ = registry.route(&format!("_synra.streaming.{index}"));
    }

    match registry.route("_synra.device.changed") {
        RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
        other => panic!("a known event was dropped once the registry filled: {other:?}"),
    }
}

#[test]
fn a_full_registry_does_not_grow_further() {
    // The property that makes the bound a bound.
    let mut registry = registry();
    for index in 0..(MAX_DISTINCT_NAMES * 2) {
        let _ = registry.route(&format!("_synra.flood.{index}"));
    }
    assert_eq!(registry.distinct_names(), MAX_DISTINCT_NAMES);
}
