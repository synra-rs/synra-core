use super::*;

#[test]
fn a_guest_cannot_grow_past_the_ceiling_its_budget_names() {
    // ★ The sandbox's second promise, against a real component: a plugin that allocates without bound is stopped by the
    // number the kernel chose rather than by the machine running out.
    //
    // The guest asks to grow until it is refused and then traps, so reaching the trap **is** the evidence: `memory.grow`
    // returns -1 when the limiter says no, and a guest that never hears "no" would loop rather than trap.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GROWS_UNTIL_REFUSED, "@acme/greedy");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let ceiling = 1024 * 1024;
    let budget = CallBudget {
        // ★ Fuel has to be granted, and generously, because `None` here is **zero** rather than unlimited: the first
        // version of this test passed `None` and got `FuelExhausted { fuel: 0 }`, which is the engine being right and the
        // test being wrong about what it was asking for.
        //
        // A million instructions against a guest whose whole job is sixteen `memory.grow`s and a comparison is not a second
        // limit that could fire — and it cannot quietly become one, because the assertion below is on the outcome: if fuel
        // ran out the test would fail and say so rather than passing as though memory had been the reason.
        fuel: Some(1_000_000),
        timeout: None,
        max_memory_growth: Some(ceiling),
    };
    let outcome = instance.call(&Work::Deactivate, budget).expect("a call");

    match outcome {
        // ★ The limit is compared to the number the **budget** named, not merely checked for being a memory outcome.
        //
        // The engine has a ceiling of its own (`INSTANTIATION_CEILING`, sixteen mebibytes) that exists whether or not
        // anybody asked for one, so a test that only asserted "it was memory" would pass against an engine that ignored
        // the budget entirely. Naming the number is what makes this about the budget.
        CallOutcome::MemoryExceeded { limit } => assert_eq!(limit, ceiling),
        other => panic!("expected the memory ceiling to end it, got {other:?}"),
    }
}

#[test]
fn a_memory_ceiling_is_installed_before_the_guest_runs() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // Nothing is allowed before a budget says so: an instance created outside a call cannot grow at all, which is what
    // stops a start function from escaping the ceiling.
    assert_eq!(instance.memory_bytes(), 0);
    let budget = CallBudget {
        fuel: Some(1_000_000),
        timeout: None,
        max_memory_growth: Some(8 * 1024 * 1024),
    };
    let _ = instance.call(&Work::Deactivate, budget);
    assert_eq!(instance.memory_bytes(), 8 * 1024 * 1024);
}
