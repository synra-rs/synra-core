use super::*;

#[test]
fn a_guest_that_loops_is_stopped_by_its_instruction_budget() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());
    let budget = CallBudget {
        fuel: Some(100_000),
        timeout: Some(Duration::from_secs(5)),
        max_memory_growth: None,
    };
    assert_eq!(
        instance.call(&Work::Deactivate, budget).unwrap(),
        CallOutcome::FuelExhausted { fuel: 100_000 }
    );
    assert_eq!(instance.last_fuel_consumed(), Some(100_000));
}

#[test]
fn a_call_that_asks_for_no_fuel_can_exceed_the_startup_budget() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(
        &backend,
        r#"(component
          (core module $m
            (func (export "stop") (local $i i32)
              (loop $count
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $count (i32.lt_u (local.get $i) (i32.const 1000000))))))
          (core instance $i (instantiate $m))
          (func $stop (canon lift (core func $i "stop")))
          (instance $life (export "deactivate" (func $stop)))
          (export "synra:plugin/lifecycle@1.0.0" (instance $life)))"#,
        "@acme/counts",
    );
    let mut instance = instantiate(&backend, artifact.as_ref());
    let budget = CallBudget {
        timeout: Some(Duration::from_secs(5)),
        ..CallBudget::unlimited()
    };
    assert!(instance.call(&Work::Deactivate, budget).unwrap().is_ok());
    assert!(
        instance.last_fuel_consumed().unwrap() > super::super::config::INSTANTIATION_FUEL,
        "the call could not finish if it inherited the startup fuel budget"
    );
}
