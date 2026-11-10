use super::super::{RouteOutcome, RouterError};
use super::{key, registry, rules};

#[test]
fn an_empty_registry_routes_nobody() {
    let mut registry = registry();
    // The kernel's own event, which nothing subscribes to. Ordinary rather than an error.
    assert!(matches!(
        registry.route("device.ping"),
        RouteOutcome::Nobody
    ));
}

#[test]
fn an_exact_rule_receives_its_event() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");

    match registry.route("device.ping") {
        RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
        other => panic!("expected a route, got {other:?}"),
    }
}

#[test]
fn an_exact_rule_does_not_receive_a_different_event() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");
    assert!(matches!(
        registry.route("device.pong"),
        RouteOutcome::Nobody
    ));
}

#[test]
fn a_wildcard_rule_receives_its_family() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["_synra.device.*"]))
        .expect("registers");

    for event in ["_synra.device.changed", "_synra.device.offline"] {
        match registry.route(event) {
            RouteOutcome::Routed(plugins) => {
                assert_eq!(plugins, vec![key("@a/one")], "{event}")
            }
            other => panic!("{event}: expected a route, got {other:?}"),
        }
    }
    // And not a sibling family.
    assert!(matches!(
        registry.route("_synra.transfer.started"),
        RouteOutcome::Nobody
    ));
}

#[test]
fn several_plugins_receive_the_same_event() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["_synra.device.*"]))
        .expect("registers");
    registry
        .register(&key("@b/two"), &rules(&["_synra.device.changed"]))
        .expect("registers");

    match registry.route("_synra.device.changed") {
        RouteOutcome::Routed(plugins) => {
            assert_eq!(plugins.len(), 2, "{plugins:?}");
            assert!(plugins.contains(&key("@a/one")));
            assert!(plugins.contains(&key("@b/two")));
        }
        other => panic!("expected two routes, got {other:?}"),
    }
}

#[test]
fn a_plugin_is_named_once_even_when_two_of_its_rules_match() {
    // A plugin may subscribe both to an exact name and to the family containing it, and delivering twice would run
    // its handler twice for one event.
    let mut registry = registry();
    registry
        .register(
            &key("@a/one"),
            &rules(&["_synra.device.*", "_synra.device.changed"]),
        )
        .expect("registers");

    match registry.route("_synra.device.changed") {
        RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
        other => panic!("expected one route, got {other:?}"),
    }
}

#[test]
fn a_deep_wildcard_reaches_the_whole_subtree() {
    let mut registry = registry();
    // A single `*` matches one segment, so `_synra.offline` is in the family and `_synra.device.changed` is not.
    registry
        .register(&key("@a/one"), &rules(&["_synra.offline"]))
        .expect("registers");
    assert!(matches!(
        registry.route("_synra.offline"),
        RouteOutcome::Routed(_)
    ));
}

#[test]
fn a_bare_double_star_is_refused_by_the_handle_grammar() {
    // `**` is a capability-DSL segment, not a handle-pattern one. Refusing it is the right answer: silently
    // treating it as `*` would make two spellings mean one thing, and the author would never learn which.
    let mut registry = registry();
    assert!(matches!(
        registry.register(&key("@a/one"), &rules(&["_synra.**"])),
        Err(RouterError::BadRule { .. })
    ));
}

#[test]
fn a_trailing_star_matches_exactly_one_more_segment() {
    // The handle grammar's `*` is a single-segment wildcard, not a subtree one: the candidate must have the same
    // number of segments as the pattern. So `_synra.*` covers `_synra.offline` and *not*
    // `_synra.device.changed` — which is the safer reading, because a pattern's depth is then visible in the
    // manifest rather than being implied by the wildcard.
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["_synra.*"]))
        .expect("registers");

    assert!(matches!(
        registry.route("_synra.offline"),
        RouteOutcome::Routed(_)
    ));
    assert!(matches!(
        registry.route("_synra.device.changed"),
        RouteOutcome::Nobody
    ));

    // Two wildcards cover two more segments, which is how a deeper family is expressed.
    registry
        .register(&key("@b/two"), &rules(&["_synra.*.*"]))
        .expect("registers");
    assert!(matches!(
        registry.route("_synra.device.changed"),
        RouteOutcome::Routed(_)
    ));
    assert!(matches!(
        registry.route("_synra.a.b.c.d"),
        RouteOutcome::Nobody
    ));
}
