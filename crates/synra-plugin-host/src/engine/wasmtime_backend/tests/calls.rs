use super::*;

#[test]
fn a_call_reaches_the_guest_and_its_answer_comes_back() {
    // ★ The one test that proves the whole path: a call goes in, the guest runs, and bytes the **host never built** come
    // back out. Everything else in this file tests a part of it — the lookup, the instantiation, the limits, the traps.
    //
    // ★ And its assertion used to be a tautology.
    //
    // The ignored version ended with `assert!(!text.is_empty() || text.is_empty())`, which is true for every string there
    // is — so even with a working fixture it would have proved nothing about what came back. It now names the answer, and
    // the answer is twenty-one characters the guest wrote into its own memory.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, ANSWERS, "@acme/answers");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let outcome = instance
        .call(
            &Work::CanHandle {
                item_json: "{\"mime\":\"text/plain\"}".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .expect("a call");

    match outcome {
        CallOutcome::Ok(text) => assert_eq!(text, "hello from the plugin"),
        other => panic!("expected the guest's own string, got {other:?}"),
    }
    assert_eq!(
        instance.host_calls(),
        0,
        "the guest called nothing; the string is its own"
    );
    // ★ The reading the plugin group's `plugin_fuel_consumed` histogram is built from: the store is set to the budget
    // before the call and the remainder is read after, so a guest that ran spent something. `unlimited` gives `u64::MAX`,
    // which is why the assertion is "more than zero" rather than a number only this fixture could name.
    assert!(
        instance.last_fuel_consumed().is_some_and(|fuel| fuel > 0),
        "a call that reached the guest reports the fuel it spent"
    );
}

#[test]
fn a_call_to_an_export_the_component_does_not_have_is_a_named_trap() {
    // An export the contract requires and the component lacks. The message names the interface and the function, so
    // a plugin author knows what to add.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, EMPTY, "@acme/empty");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let outcome = instance
        .call(
            &Work::CanHandle {
                item_json: "{}".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .expect("a call");
    match outcome {
        CallOutcome::Trap { detail } => assert!(detail.contains("share.can-handle"), "{detail}"),
        other => panic!("expected a trap, got {other:?}"),
    }
}
