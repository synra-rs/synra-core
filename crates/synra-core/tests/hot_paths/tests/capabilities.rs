use super::*;

#[test]
fn matching_a_capability_allocates_nothing() {
    // ★ Hot path #2. The gate runs before every plugin call, and a capability is a string the kernel compares.
    let mut grants = CapabilitySet::new();
    grants.insert_str("log:*").expect("a valid capability");
    grants.insert_str("storage:local:read").expect("a valid capability");
    grants.insert_str("device:send:dev_a").expect("a valid capability");

    let wanted = Capability::parse("log:write").expect("a valid capability");

    warm_the_counter();
    let (verdict, count) = CounterGuard::counted(|| grants.contains(&wanted));
    assert!(verdict, "the grant did not match");
    assert!(AllocationBudget::NONE.allows(count), "matching a capability allocated: {count}");
}

#[test]
fn matching_a_capability_that_is_absent_allocates_nothing() {
    // The refusal is the common case in a strict installation — a plugin asking for something it was not granted —
    // so it must not be the expensive one. A `contains` that built a key to look up would allocate exactly here.
    let mut grants = CapabilitySet::new();
    grants.insert_str("log:*").expect("a valid capability");

    let wanted = Capability::parse("network:fetch:example.com").expect("a valid capability");

    warm_the_counter();
    let (verdict, count) = CounterGuard::counted(|| grants.contains(&wanted));
    assert!(!verdict, "the grant matched something it should not");
    assert!(AllocationBudget::NONE.allows(count), "a refused match allocated: {count}");
}

#[test]
fn the_gate_permits_an_ungated_function_without_allocating() {
    // The check that runs before every plugin call, on the path where nothing needs to be checked. It reads a
    // static table, so the whole point is that it touches no heap.
    let grants = CapabilitySet::new();
    let import = "synra:plugin/host#env-sdk-version";

    warm_the_counter();
    let (verdict, count) = CounterGuard::counted(|| synra_plugin_host::permits(import, &grants));
    assert!(verdict, "an ungated function was refused");
    assert!(
        within(count, GATED_CALL_BUDGET),
        "the gated call allocated: {count}, budget {GATED_CALL_BUDGET}"
    );
}

#[test]
fn parsing_a_qualified_plugin_event_owns_only_the_event_name() {
    let text = "_plugin.@acme/long-package-name.ready";
    warm_the_counter();
    let (name, count) = CounterGuard::counted(|| {
        synra_protocol::event::EventName::parse(text).expect("a qualified event")
    });
    assert_eq!(name.as_str(), text);
    assert!(
        within(count, 1),
        "event ownership validation allocated a discarded id: {count}"
    );
}
