use super::*;

#[test]
fn a_real_guest_that_loops_is_stopped_by_the_wall_clock_not_by_zero() {
    // ★ The other half of the round-95 fix, and the half nothing covered.
    //
    // Disarming the deadline for `timeout: None` is only correct if `timeout: Some(_)` still **arms** one and still stops a
    // real guest. The test beside this one proves the disarming; this proves the arming, with a guest that genuinely never
    // returns, so an error in either branch cannot hide behind the other.
    //
    // ★ And it asserts the **duration in the outcome**, which is what `after: 0ns` was.
    //
    // That value was the signature of the bug: a call interrupted by the instantiation deadline it never asked for reported
    // a timeout of zero, because the budget had no duration to name. A real wall-clock stop has a duration to name, and it
    // is the one the budget asked for.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // Enough fuel to run for far longer than the clock allows, so the layer that stops this is the wall clock rather than
    // the instruction budget — otherwise the test would pass for the wrong reason.
    let budget = CallBudget {
        fuel: Some(1_000_000_000),
        timeout: Some(Duration::from_millis(250)),
        max_memory_growth: None,
    };

    let started = std::time::Instant::now();
    let outcome = instance.call(&Work::Deactivate, budget).expect("a call");
    let elapsed = started.elapsed();

    match outcome {
        CallOutcome::Timeout { after } => assert_eq!(
            after,
            Duration::from_millis(250),
            "the outcome names the budget's duration, not zero"
        ),
        other => panic!("a real infinite loop must be stopped by its wall clock, got {other:?}"),
    }
    // And it stopped near the deadline rather than running until its fuel ran out, which is what makes the assertion above
    // about the clock rather than about a coincidence.
    assert!(
        elapsed < Duration::from_secs(30),
        "it ran for {elapsed:?}, so something other than the 250ms budget stopped it"
    );
}

#[test]
fn a_budget_with_no_time_limit_leaves_no_deadline_armed() {
    // Advance beyond the constructor's finite deadline before making an unlimited call.
    // Retaining startup's deadline would interrupt the call deterministically.
    let (backend, executor) = backend_and_executor();
    let artifact = compile(&backend, STOPS, "@acme/stops");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // The epoch is already past the deadline instantiation armed.
    let ticks = ticks_for(INSTANTIATION_TIMEOUT);
    for _ in 0..=ticks {
        executor.epoch().advance();
    }

    let outcome = instance
        .call(
            &Work::Deactivate,
            CallBudget {
                fuel: None,
                timeout: None,
                max_memory_growth: None,
            },
        )
        .expect("a call");

    assert!(
        !matches!(outcome, CallOutcome::Timeout { .. }),
        "a budget with no wall clock was timed out anyway: {outcome:?}"
    );
    // And the observable state agrees: nothing is armed, rather than a tick that cannot be told from a real deadline.
    assert_eq!(instance.deadline_epoch(), None);
}

#[test]
fn a_wall_clock_budget_arms_a_deadline_on_the_store() {
    // ★ The number a timeout is enforced by. `deadline_epoch` is what the instance was actually given, so a test that
    // only asserted "it returned Timeout" cannot pass against an engine that never armed one.
    // ★ The fixture is the looping one, so the call this arms a deadline for is a call that genuinely runs — and keeps
    // running until the deadline stops it. The fixture this test used to use had a canonical-ABI bug, so its call trapped
    // immediately and the deadline was asserted around a trap rather than around work.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    assert_eq!(
        instance.deadline_epoch(),
        None,
        "no call deadline has been recorded before a call"
    );
    let budget = CallBudget {
        fuel: None,
        timeout: Some(Duration::from_millis(250)),
        max_memory_growth: None,
    };
    let _ = instance.call(&Work::Deactivate, budget);
    // 250ms at the executor's ten-millisecond period: twenty-five ticks, and at least one whatever the arithmetic —
    // a deadline of zero would be a call that fails immediately.
    assert_eq!(instance.deadline_epoch(), Some(25));
}

/// ★ An engine built with no executor must still have something advancing its epoch.
///
/// `WasmtimeBackend::new` used to be `with_epoch(kind, Epoch::new())` — a fresh counter that no thread ever moved. The
/// store was told "your deadline is tick N" and the counter stayed at zero, so the wall-clock layer armed a deadline
/// that could not arrive. This is the test for the private-epoch half of that: the counter has to move on its own.
#[test]
fn an_engine_with_its_own_epoch_advances_it() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");

    let tick = next_tick(backend.epoch())
        .recv_timeout(Duration::from_secs(2))
        .expect("the backend's own ticker advances its epoch");
    assert!(tick > 0);
}

/// ★ The epoch has to be joined to the engine, not merely held beside it.
///
/// `Epoch` is the counter a ticker moves. A wasmtime deadline is measured against the engine's **own** counter, which
/// moves only when `Engine::increment_epoch` is called — and nothing called it. So an engine could hold a perfectly
/// lively epoch and still never time a guest out, which is what "it holds the epoch" was mistaken for.
///
/// The assertion is on the observer count because that is the only externally visible trace of the join. It is not a
/// statement about internals for its own sake: an engine with zero observers is an engine the ticker cannot reach, and
/// that is the exact condition that made this layer inert.
#[test]
fn an_engine_sharing_an_epoch_is_joined_to_it() {
    let executor = WasmExecutor::start(2, 4).expect("an executor");
    let backend =
        WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, executor.epoch().clone())
            .expect("an engine");

    let described = format!("{:?}", backend.epoch());
    assert!(
        described.contains("observers: 1"),
        "the engine is not observing the epoch, so advancing it moves nothing wasmtime measures: {described}"
    );
}

#[test]
fn a_ticker_advances_the_epoch_shared_with_wasmtime() {
    let epoch = Epoch::new();
    let backend = WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, epoch.clone())
        .expect("an engine");

    let tick = next_tick(&epoch);
    let ticker = EpochTicker::start(epoch);
    assert!(ticker.is_running());
    let observed = tick.recv_timeout(Duration::from_secs(2)).expect("the ticker advances");

    assert!(backend.epoch().now() >= observed);
    let artifact = compile(&backend, EMPTY, "@acme/empty");
    assert_eq!(artifact.digest().len(), 64);
}

#[test]
fn a_scripted_epoch_and_a_real_one_are_the_same_clock() {
    // A backend built without an epoch would silently diverge. This asserts the shared one is the one reported.
    let epoch = Epoch::new();
    let backend = WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, epoch.clone())
        .expect("an engine");
    let before = backend.epoch().now();
    let _ = epoch.advance();
    assert_eq!(backend.epoch().now(), before + 1);
}
