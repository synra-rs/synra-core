use super::super::EventId;
use super::{key, registry, rules};

#[test]
fn a_number_is_assigned_once_and_reused() {
    // The whole point: the string comparison happens on the first sighting and never again.
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");

    let first = registry
        .id_for("device.ping")
        .expect("numbered at registration");
    let _ = registry.route("device.ping");
    assert_eq!(registry.id_for("device.ping"), Some(first));
    assert_eq!(registry.distinct_names(), 1);
}

#[test]
fn an_unknown_name_is_numbered_when_it_arrives() {
    // A plugin may subscribe to a family a newer peer emits, so a name nobody declared is still numbered — up to
    // the bound — rather than refused.
    let mut registry = registry();
    assert_eq!(registry.distinct_names(), 0);
    let _ = registry.route("_synra.something.new");
    assert_eq!(registry.distinct_names(), 1);
}

#[test]
fn an_event_name_round_trips_through_its_number() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping"]))
        .expect("registers");
    let id = registry.id_for("device.ping").expect("numbered");
    assert_eq!(registry.name_for(id), Some("device.ping"));
    assert!(id.get() < 1024);
}

#[test]
fn a_number_that_was_never_assigned_has_no_name() {
    let registry = registry();
    assert_eq!(registry.name_for(EventId::from_raw(999)), None);
}
