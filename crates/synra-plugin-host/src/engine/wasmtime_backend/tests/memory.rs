use super::*;

const WASM_PAGE: u64 = 64 * 1024;

#[test]
fn the_limiter_traps_with_the_effective_host_ceiling() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GROWS_MEMORY, "@acme/grows");

    for (requested, enforced) in [
        (Some(1024 * 1024), 1024 * 1024),
        (None, INSTANTIATION_CEILING as u64),
    ] {
        let mut instance = instantiate(&backend, artifact.as_ref());
        assert_eq!(instance.memory_bytes(), 0, "no call yet");
        let budget = CallBudget {
            fuel: Some(1_000_000),
            max_memory_growth: requested,
            ..CallBudget::unlimited()
        };
        assert_eq!(
            instance.call(&Work::Deactivate, budget).unwrap(),
            CallOutcome::MemoryExceeded { limit: enforced }
        );
        assert_eq!(instance.memory_bytes(), enforced);
    }
}

#[test]
fn refusing_a_modules_own_growth_does_not_reclassify_a_later_trap() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(
        &backend,
        r#"(component
          (core module $m
            (memory 1 1)
            (func (export "stop")
              (drop (memory.grow (i32.const 1)))
              (drop (i32.div_s (i32.const 1) (i32.const 0)))))
          (core instance $i (instantiate $m))
          (func $stop (canon lift (core func $i "stop")))
          (instance $life (export "deactivate" (func $stop)))
          (export "synra:plugin/lifecycle@1.0.0" (instance $life)))"#,
        "@acme/refuses-then-traps",
    );
    let mut instance = instantiate(&backend, artifact.as_ref());
    let outcome = instance
        .call(&Work::Deactivate, CallBudget::unlimited())
        .unwrap();
    let CallOutcome::Trap { detail } = outcome else {
        panic!("expected the division trap, got {outcome:?}");
    };
    assert!(detail.contains("divide by zero"), "{detail}");
    assert!(
        detail.contains("requested 131072 bytes with a linear memory maximum of 65536 bytes"),
        "{detail}"
    );
}

#[test]
fn a_reused_instance_replaces_budgets_and_clears_growth_observations() {
    let (backend, executor) = backend_and_executor();
    let artifact = compile(
        &backend,
        r#"(component
          (core module $m
            (memory $fixed 1 1)
            (memory $growable 1)
            (global $called (mut i32) (i32.const 0))
            (func (export "stop") (local $i i32)
              (if (i32.eqz (global.get $called)) (then
                (if (i32.ne (memory.grow $fixed (i32.const 1)) (i32.const -1))
                  (then unreachable))
                (global.set $called (i32.const 1))
                (return)))
              (if (i32.eq (global.get $called) (i32.const 1)) (then
                (loop $count
                  (local.set $i (i32.add (local.get $i) (i32.const 1)))
                  (br_if $count (i32.lt_u (local.get $i) (i32.const 1000000))))
                (if (i32.ne (memory.grow $growable (i32.const 1)) (i32.const 1))
                  (then unreachable))
                (global.set $called (i32.const 2))
                (return)))
              (drop (i32.div_s (i32.const 1) (i32.const 0)))))
          (core instance $i (instantiate $m))
          (func $stop (canon lift (core func $i "stop")))
          (instance $life (export "deactivate" (func $stop)))
          (export "synra:plugin/lifecycle@1.0.0" (instance $life)))"#,
        "@acme/reuses-budgets",
    );
    let mut instance = instantiate(&backend, artifact.as_ref());
    let budget = CallBudget {
        fuel: Some(50),
        timeout: Some(Duration::from_secs(5)),
        max_memory_growth: Some(WASM_PAGE),
    };
    assert!(instance.call(&Work::Deactivate, budget).unwrap().is_ok());
    let previous_deadline = instance.deadline_epoch().unwrap();
    for _ in 0..=previous_deadline {
        executor.epoch().advance();
    }

    // The guest counts to one million and grows its second memory under the default ceiling.
    assert!(
        instance
            .call(&Work::Deactivate, CallBudget::unlimited())
            .unwrap()
            .is_ok()
    );
    assert!(instance.last_fuel_consumed().unwrap() > budget.fuel.unwrap());
    assert_eq!(instance.deadline_epoch(), None);
    assert_eq!(instance.memory_bytes(), INSTANTIATION_CEILING as u64);

    let outcome = instance
        .call(&Work::Deactivate, CallBudget::unlimited())
        .unwrap();
    let CallOutcome::Trap { detail } = outcome else {
        panic!("expected the division trap after the budget reset, got {outcome:?}");
    };
    assert!(detail.contains("divide by zero"), "{detail}");
    assert!(
        !detail.contains("growth request was also refused"),
        "{detail}"
    );
}

#[test]
fn an_oversized_minimum_fails_at_instantiation() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(
        &backend,
        r#"(component
          (core module $m (memory 257))
          (core instance $i (instantiate $m))
          (instance $life)
          (export "synra:plugin/lifecycle@1.0.0" (instance $life)))"#,
        "@acme/oversized-minimum",
    );
    let Err(BackendError::Instantiate { detail }) = handle(&backend).instantiate(artifact.as_ref())
    else {
        panic!("the memory ceiling must reject the instance before its first call");
    };
    assert!(
        detail.contains(&format!("host ceiling of {INSTANTIATION_CEILING} bytes")),
        "{detail}"
    );
}
