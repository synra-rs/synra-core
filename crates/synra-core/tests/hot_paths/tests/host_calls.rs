use super::*;

#[test]
fn a_gated_host_call_stays_within_its_budget() {
    // Measure table lookup and grant coverage together for the import availability path.
    let import = "synra:plugin/host#log";
    for (capability, allowed) in [
        ("log:*", true),
        ("log:**", true),
        ("log:info", true),
        ("log:warn", true),
        ("log:unknown", false),
        ("network:fetch:*", false),
    ] {
        let mut grants = CapabilitySet::new();
        grants.insert_str(capability).expect("a valid capability");

        warm_the_counter();
        let (verdict, count) =
            CounterGuard::counted(|| synra_plugin_host::permits(import, &grants));
        assert_eq!(verdict, allowed, "{capability}");
        assert!(
            AllocationBudget::NONE.allows(count),
            "log availability allocated: {count}"
        );
        assert!(
            within(count, GATED_CALL_BUDGET),
            "the gated call allocated for {capability}: {count}, budget {GATED_CALL_BUDGET}"
        );
    }
}
