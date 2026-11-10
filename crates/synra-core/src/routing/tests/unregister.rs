use super::super::RouteOutcome;
use super::{key, registry, rules};

#[test]
fn unregistering_removes_every_rule() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping", "_synra.device.*"]))
        .expect("registers");
    assert_eq!(registry.unregister(&key("@a/one")), 2);

    assert!(matches!(
        registry.route("device.ping"),
        RouteOutcome::Nobody
    ));
    assert!(matches!(
        registry.route("_synra.device.changed"),
        RouteOutcome::Nobody
    ));
    assert_eq!(registry.wildcard_rules(), 0);
}

#[test]
fn unregistering_leaves_other_plugins_alone() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");
    registry
        .register(&key("@b/two"), &rules(&["device.ping"]))
        .expect("registers");

    registry.unregister(&key("@a/one"));
    match registry.route("device.ping") {
        RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@b/two")]),
        other => panic!("the other plugin lost its route: {other:?}"),
    }
}

#[test]
fn unregistering_an_unknown_plugin_is_not_an_error() {
    let mut registry = registry();
    assert_eq!(registry.unregister(&key("@a/one")), 0);
}

#[test]
fn a_number_survives_an_unregister() {
    // Renumbering would invalidate every other plugin's routes, so an identifier whose subscribers are gone is
    // kept rather than reused.
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");
    let id = registry.id_for("device.ping").expect("numbered");

    registry.unregister(&key("@a/one"));
    assert_eq!(registry.id_for("device.ping"), Some(id));
    assert_eq!(registry.name_for(id), Some("device.ping"));
}

#[test]
fn a_plugin_may_register_again_after_unregistering() {
    // A plugin that is deactivated and reactivated must be able to subscribe again.
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");
    registry.unregister(&key("@a/one"));
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers again");

    match registry.route("device.ping") {
        RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
        other => panic!("expected a route, got {other:?}"),
    }
}
