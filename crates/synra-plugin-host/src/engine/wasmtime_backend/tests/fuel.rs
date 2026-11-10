use super::*;

#[test]
fn a_guest_that_loops_for_ever_is_stopped_by_its_instruction_budget() {
    // ★ The sandbox's first promise, against a **real component** rather than a scripted outcome.
    //
    // This test used to be `#[ignore]`d: it lifted the looping core function as `activate`, whose `string`/`outcome`
    // signature meant the hand-written `.wat` had to implement the canonical ABI by hand and did not. `deactivate` is
    // `func()`, so the same limit is now tested on a guest that really runs — and what is being tested is the engine's
    // enforcement rather than the kernel's handling of an outcome somebody scripted.
    //
    // The distinction matters for exactly the reason the ignored version existed: `Scripted::FuelExhausted` proves what
    // the kernel does when it is *told* the fuel ran out, and nothing about whether it ever does.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let budget = CallBudget {
        fuel: Some(100_000),
        // No wall-clock budget, so the *instruction* budget is the only thing that can end this. A test that set both
        // would pass whichever limit fired first and would not say which one worked.
        timeout: None,
        max_memory_growth: None,
    };
    let outcome = instance.call(&Work::Deactivate, budget).expect("a call");

    match outcome {
        CallOutcome::FuelExhausted { fuel } => assert_eq!(fuel, 100_000),
        other => panic!("expected the fuel budget to end it, got {other:?}"),
    }
    // ★ Exactly the budget: a guest stopped by fuel has a zero remainder, so the pair-around-the-call arithmetic is
    // `granted - 0`. Asserted before the second call, which would replace the reading with its own.
    assert_eq!(
        instance.last_fuel_consumed(),
        Some(100_000),
        "an exhausted budget reports what it was given"
    );
    // And the instance survived: one bad call is not a dead plugin, which is what makes the next call possible.
    assert!(
        instance
            .call(&Work::Deactivate, CallBudget::unlimited())
            .is_ok()
    );
}

#[test]
fn a_budget_that_names_no_ceiling_is_still_bounded() {
    // ★ The one layer where `None` must **not** mean "no limit", and the reason is worth a test rather than a
    // comment.
    //
    // The other two layers read `None` as "the caller named no limit for this layer", and rounds 95 to 97 fixed the engine
    // to honour that. Memory is different: a budget that names no ceiling is held to `INSTANTIATION_CEILING`, the sixteen
    // mebibytes an instance is created with. That is deliberate — `execute_budget()` in `synra-core` names no memory
    // ceiling, so an action is bounded by time alone, and the instantiation ceiling is the last-resort cap that stops a
    // hostile `execute` from eating the machine.
    //
    // ★ Which is exactly why it is pinned.
    //
    // The inconsistency is visible, and the obvious "fix" — making `None` clear the ceiling, as the other two layers now do
    // — would **remove the sandbox's last resort**. A future reader who notices the asymmetry should find this test and the
    // number in it rather than a commit that quietly uncapped memory.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GROWS_UNTIL_REFUSED, "@acme/greedy");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // No ceiling named, and enough instructions that the guest reaches the wall rather than its budget.
    let outcome = instance
        .call(
            &Work::Deactivate,
            CallBudget {
                fuel: Some(1_000_000),
                timeout: None,
                max_memory_growth: None,
            },
        )
        .expect("a call");

    match outcome {
        // ★ And the number is the ceiling **in force**, not the budget's absence.
        //
        // `classify` reported `budget.max_memory_growth.unwrap_or(0)` — so this outcome used to name a limit of **zero** when
        // the wall the guest hit was sixteen mebibytes. That is the number a plugin author would go and change.
        // ★ Asserted against the constant rather than the number, which is the difference between a test that
        // checks the ceiling is reported and one that checks the arithmetic somebody typed matches theirs.
        CallOutcome::MemoryExceeded { limit } => assert_eq!(
            limit, INSTANTIATION_CEILING as u64,
            "an unnamed ceiling is the instantiation ceiling, and the outcome must name it"
        ),
        other => panic!(
            "a guest that grows without bound must hit the instantiation ceiling, got {other:?}"
        ),
    }
}

#[test]
fn a_call_that_asks_for_no_fuel_is_given_fuel_rather_than_left_at_zero() {
    // ★ "No instruction limit" is the one budget the engine cannot express by doing nothing.
    //
    // Every store is built with `consume_fuel(true)` and starts at **zero**. Setting fuel only when the budget names an
    // amount left a call that named none with nothing to spend, so a guest trapped at once with `FuelExhausted { fuel: 0 }`
    // — a plugin reported as out of instructions when its budget said there was no limit. A reused instance was worse rather
    // than better: it inherited the previous call's remainder, which can also be zero.
    //
    // ★ On a fresh instance, and about the tank rather than about reuse.
    //
    // The first version of this test called the same instance twice after draining it, and what it found was a different
    // bug entirely: a **trapped** component instance cannot be entered again, so reuse after a stop is not something the
    // engine offers. Discarding such an instance is `PluginSet`'s job — `a_plugin_that_exhausts_its_budget_is_not_broken_afterwards`
    // in `synra-core` is where that lives — and asserting it here would have been asserting a contract this layer never
    // made.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // Unlimited instructions, bounded by the clock so the test cannot hang. Both facts matter: without the fuel the guest
    // stops before it starts, and without the clock it never stops.
    let started = std::time::Instant::now();
    let outcome = instance
        .call(
            &Work::Deactivate,
            CallBudget {
                fuel: None,
                timeout: Some(Duration::from_millis(250)),
                max_memory_growth: None,
            },
        )
        .expect("a call");

    match outcome {
        CallOutcome::Timeout { .. } => {}
        other => {
            panic!("a budget with no instruction limit should run until its clock, got {other:?}")
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "and it should stop near that clock rather than running on"
    );
}
