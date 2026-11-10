use synra_capability::CapabilitySet;
use synra_plugin_host::{Backend, InstancePolicy, Work};
use super::super::{PluginSet, PluginSpec};
use super::{host, id};

// ── A real malicious guest, through the kernel ────────────────────────────────────────────────────

#[test]
fn a_plugin_that_exhausts_its_budget_is_not_broken_afterwards() {
    // """ + S + """ A bad call must not cost the plugin its **next** call, and this was broken.
    //
    // `PluginSet` throws an instance away when a panic unwinds out of a call — the comment there is explicit about why
    // ("the store is in a state nothing can reason about"). It kept the instance when the **engine** stopped the guest, and a
    // trapped component instance cannot be entered again: wasmtime answers the next call with
    // `Trap { detail: "wasm trap: cannot enter component instance" }`.
    //
    // So one budget overrun made a plugin permanently broken: every later call to it failed with a trap that says nothing
    // about the plugin and everything about the instance the kernel was reusing. The user's remedy would be to restart the
    // app.
    let engine = synra_plugin_host::engine::WasmtimeBackend::new(
        synra_plugin_host::BackendKind::WasmtimeCranelift,
    )
    .expect("an engine");
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(engine)), host());
    set.load(PluginSpec {
        id: id("@synra/aaa-spins"),
        version: "1.0.0".to_owned(),
        wasm: synra_testkit::component::deactivation_component(true)
            .expect("a complete looping guest"),
        grants: CapabilitySet::new(),
        policy: InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .expect("loads");

    let spins = id("@synra/aaa-spins");
    let wasteful = synra_plugin_host::CallBudget {
        fuel: Some(1_000),
        timeout: None,
        max_memory_growth: None,
    };
    let first = set
        .call(&spins, &Work::Deactivate, wasteful, 1_000)
        .expect("a call");
    assert!(
        matches!(first, synra_plugin_host::CallOutcome::FuelExhausted { .. }),
        "the loop must exhaust a thousand instructions, got {first:?}"
    );

    // """ + S + """ The call that matters: the same plugin, asked again with a budget it can meet.
    let generous = synra_plugin_host::CallBudget {
        fuel: None,
        timeout: Some(std::time::Duration::from_millis(250)),
        max_memory_growth: None,
    };
    let second = set.call(&spins, &Work::Deactivate, generous, 2_000).expect("a call");
    assert!(
        !matches!(second, synra_plugin_host::CallOutcome::Trap { .. }),
        "the plugin was asked again with a workable budget and trapped: {second:?}"
    );
    // And it really ran, rather than being reported as fine because nothing happened.
    assert!(
        matches!(second, synra_plugin_host::CallOutcome::Timeout { .. }),
        "an unlimited loop runs until its clock, got {second:?}"
    );
}

#[test]
fn a_real_guest_that_loops_is_stopped_without_costing_the_others() {
    // """ + S + """ The strongest form of `21 §5.1`'s sentence, and the one thing no double can stand in for.
    //
    // The isolation table above proves the **kernel's** handling of an outcome; the engine's own tests prove the engine
    // produces it. Neither runs a real guest **through the kernel**, which is the property a user has: a plugin whose bytes
    // contain `while true` must not stop the kernel, and the plugin beside it must keep working. So this loads a genuine
    // looping component into a `PluginSet` over the real engine, calls it, and then asks the other one.
    //
    // A scripted backend cannot do this. `Scripted::FuelExhausted` is a value somebody wrote down, and the failure it cannot
    // express is the one that matters: the engine really counting instructions and really stopping.
    let engine = synra_plugin_host::engine::WasmtimeBackend::new(
        synra_plugin_host::BackendKind::WasmtimeCranelift,
    )
    .expect("an engine");
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(engine)), host());

    for (name, looping) in [("@synra/aaa-spins", true), ("@synra/bbb-finishes", false)] {
        set.load(PluginSpec {
            id: id(name),
            version: "1.0.0".to_owned(),
            wasm: synra_testkit::component::deactivation_component(looping)
                .expect("a complete guest"),
            grants: CapabilitySet::new(),
            policy: InstancePolicy::Stateless,
            limit: 4,
            quota: synra_plugin_host::quota::Quota::default(),
        })
        .expect("loads");
    }

    // A bounded budget, so the loop cannot run forever and the test cannot hang if the engine does not count.
    let budget = synra_plugin_host::CallBudget {
        fuel: Some(100_000),
        timeout: None,
        max_memory_growth: None,
    };

    let spun = set
        .call(&id("@synra/aaa-spins"), &Work::Deactivate, budget, 1_000)
        .expect("a call");
    assert!(
        matches!(spun, synra_plugin_host::CallOutcome::FuelExhausted { .. }),
        "a real infinite loop must be stopped by its instruction budget, got {spun:?}"
    );

    // """ + S + """ And the kernel is still usable, with the other plugin in the same set: the plugin beside the malicious
    // one answers, twice, so a set left in a bad state fails here rather than at the next share.
    for now in [1_000_u64, 2_000] {
        let finished = set
            .call(&id("@synra/bbb-finishes"), &Work::Deactivate, budget, now)
            .expect("a call");
        assert!(
            !finished.is_misbehaviour(),
            "the plugin beside the looping one must keep working, got {finished:?}"
        );
    }
}
