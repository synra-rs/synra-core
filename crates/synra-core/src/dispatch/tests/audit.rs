use synra_plugin_host::{Backend, Scripted, ScriptedBackend};
use synra_protocol::ids::PluginId;
use super::super::PluginSet;
use super::{host, id, load};

#[test]
fn every_audited_call_reaches_the_sink_as_well_as_the_ring() {
    // ★ The two halves of one trail, and the assertion that they are the same trail.
    //
    // The ring is what the interface reads *now*; the sink is what survives a restart. A record written to one and not the
    // other is a trail that disagrees with itself the moment the process ends — so the two lists are compared rather than
    // each being checked for plausibility.
    //
    // ★ Why this drives the drain rather than a scripted call.
    //
    // The first version of this test ran a matching pass over scripted plugins and asserted the sink had seen something. It
    // had seen nothing, and was right to: `ScriptedBackend` answers from a table, so no guest runs, no host function is
    // called, and nothing is audited. The entries a sink receives are produced by a **real** component calling a host
    // function, which is what the `wasm-text` suite in `synra-plugin-host` drives. What is tested here is the seam this
    // round added — `drain_audit`, which is the one place the two halves are written — with the entries put where a real
    // call puts them.
    let backend = ScriptedBackend::new();
    let delivered = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let collected = std::sync::Arc::clone(&delivered);

    let mut set =
        PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host()).with_audit_sink(
            std::sync::Arc::new(move |entry: &synra_observe::audit::AuditEntry| {
                collected.lock().push(entry.clone());
            }),
        );
    load(&mut set, &backend, "@synra/aaa-notes", Scripted::Ok(r#"{"handled":true}"#.to_owned()));

    let plugin = id("@synra/aaa-notes");
    let entry = synra_observe::audit::AuditEntry::new(
        1_000,
        plugin.clone(),
        synra_capability::Capability::parse("device:list").expect("a capability"),
        synra_observe::audit::AuditOutcome::Allowed,
        Some(4),
    );

    assert!(
        set.drain_record_for_test(&plugin, entry.clone()),
        "the plugin has to be loaded for there to be a buffer to drain"
    );

    assert_eq!(*delivered.lock(), vec![entry.clone()], "the sink saw the record");
    assert_eq!(set.audit(), vec![entry], "and so did the ring");
}

#[test]
fn an_actions_trace_reaches_the_audit_entry_it_produced() {
    // ★ The audit's `trace_id` was in the DTO and in no record: the session inside the guest knows the capability and the
    // outcome, not which user action the call belongs to. `call_traced` is the funnel that knows both, and this is where
    // the stamping happens — on the entries that call produced, not on the buffer as a whole.
    let backend = ScriptedBackend::new();
    let delivered = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let collected = std::sync::Arc::clone(&delivered);
    let mut set =
        PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host()).with_audit_sink(
            std::sync::Arc::new(move |entry: &synra_observe::audit::AuditEntry| {
                collected.lock().push(entry.clone());
            }),
        );
    load(&mut set, &backend, "@synra/aaa-notes", Scripted::Ok(r#"{"handled":true}"#.to_owned()));
    let plugin = id("@synra/aaa-notes");
    let entry = synra_observe::audit::AuditEntry::new(
        1_000,
        plugin.clone(),
        synra_capability::Capability::parse("device:list").expect("a capability"),
        synra_observe::audit::AuditOutcome::Allowed,
        Some(4),
    );
    let trace = synra_protocol::ids::TraceId::new();

    assert!(set.drain_record_with_trace_for_test(&plugin, entry.clone(), Some(trace)));
    assert_eq!(set.audit()[0].trace, Some(trace), "the ring carries the action's trace");
    assert_eq!(delivered.lock()[0].trace, Some(trace), "and so does the durable half");

    // ★ And a call with no action behind it stays without. A drain that invented a trace would make every matching pass look
    // like part of one user action.
    assert!(set.drain_record_with_trace_for_test(&plugin, entry, None));
    assert_eq!(set.audit()[1].trace, None, "no action means no trace");
}

#[test]
fn clearing_one_plugins_history_leaves_the_other() {
    // ★ Clearing is a per-card action: the ring holds every plugin's calls, and a "clear" that took the whole ring would
    // erase what the user was about to read on the next card. The counts are part of the history too, so the assertion is
    // on what the ring answers after the removal rather than on the entries alone.
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/aaa-notes",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    load(
        &mut set,
        &backend,
        "@synra/bbb-notes",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );

    let cleared = id("@synra/aaa-notes");
    let kept = id("@synra/bbb-notes");
    let record = |plugin: &PluginId, at_ms: i64| {
        synra_observe::audit::AuditEntry::new(
            at_ms,
            plugin.clone(),
            synra_capability::Capability::parse("device:list").expect("a capability"),
            synra_observe::audit::AuditOutcome::Allowed,
            Some(1),
        )
    };
    assert!(set.drain_record_for_test(&cleared, record(&cleared, 1_000)));
    assert!(set.drain_record_for_test(&kept, record(&kept, 2_000)));

    set.clear_audit(&cleared);

    assert!(set.audit_for(&cleared).is_empty(), "the cleared plugin has no records left");
    assert_eq!(set.audit_for(&kept).len(), 1, "another plugin's records are not collateral");
}
