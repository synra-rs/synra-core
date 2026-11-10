use super::*;

#[test]
fn routing_an_event_stays_within_its_budget() {
    // The design document's third path: an event name is looked up per event, and a lookup that built a `String`
    // key would allocate once per event per subscriber.
    let mut registry = synra_core::routing::EventRegistry::new();
    let plugin = synra_core::admission::PluginKey::new("@synra-plugin/chat");
    registry
        .register(&plugin, &["device.*".to_owned()])
        .expect("the rule registers");
    // The route is warmed outside the measurement: the *first* call registers the name, which is a one-time cost
    // and not the path being asserted about.
    let _ = registry.route("device.ping");

    warm_the_counter();
    let (outcome, count) = CounterGuard::counted(|| registry.route("device.ping"));
    assert!(
        !matches!(outcome, synra_core::routing::RouteOutcome::Unknown { .. }),
        "the event did not route: {outcome:?}"
    );
    assert!(within(count, ROUTING_BUDGET), "routing an event allocated: {count}, budget {ROUTING_BUDGET}");
}

#[test]
fn a_lookup_that_misses_stays_within_its_budget() {
    // The case a hostile or merely out-of-date peer produces: a name no plugin registered, arriving per event. A
    // router that lowered the name into an owned key to look it up would allocate exactly here, on a path a peer
    // controls — which is the shape of a denial of service.
    let mut registry = synra_core::routing::EventRegistry::new();
    let plugin = synra_core::admission::PluginKey::new("@synra-plugin/chat");
    registry
        .register(&plugin, &["device.*".to_owned()])
        .expect("the rule registers");

    // The router answers `Nobody` rather than `Unknown`: an event name the kernel has never seen and one no plugin
    // subscribed to are the same event as far as routing goes, and the caller's next step is the same. What is
    // being asserted here is that answering costs no allocation — a router forced to lower the name into an owned
    // key to look it up would allocate exactly on this path.
    warm_the_counter();
    let (outcome, count) = CounterGuard::counted(|| registry.route("teleport.away"));
    assert!(
        matches!(outcome, synra_core::routing::RouteOutcome::Nobody),
        "an event with no subscriber routed: {outcome:?}"
    );
    assert!(
        within(count, MISSED_LOOKUP_BUDGET),
        "a missed lookup allocated: {count}, budget {MISSED_LOOKUP_BUDGET}"
    );
}
