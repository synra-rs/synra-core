use synra_plugin_host::{Backend, Scripted, ScriptedBackend, Work};
use super::super::{Matcher, PluginSet, PluginSetError};
use super::{host, id, load, share_json};

#[test]
fn calling_a_plugin_that_is_not_loaded_says_so() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());
    let budget = Matcher::new(&mut set).budget();

    let error = set.call(&id("@synra/absent"), &Work::Deactivate, budget, 0);

    assert_eq!(
        error,
        Err(PluginSetError::NotLoaded {
            id: id("@synra/absent")
        })
    );
}

#[test]
fn a_call_is_counted_and_timed_per_plugin_and_interface() {
    // ★ The plugin group's first two metrics, recorded at the one funnel every call passes. The interface label is
    // `Work::interface` — the protocol's own spelling — so the panel, the card and the wire agree about what a call is.
    use synra_observe::metrics::Value;

    let backend = ScriptedBackend::new();
    let metrics = std::sync::Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host())
        .with_metrics(std::sync::Arc::clone(&metrics));
    load(
        &mut set,
        &backend,
        "@synra/aaa-notes",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    let work = Work::CanHandle { item_json: share_json().to_owned() };
    let budget = Matcher::new(&mut set).budget();

    set.call(&id("@synra/aaa-notes"), &work, budget, 1_000).expect("a call");

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.get("plugin_calls_total{interface=share,plugin=@synra/aaa-notes}"),
        Some(&Value::Counter(1)),
        "the call is counted against the plugin and the interface"
    );
    match snapshot.get("plugin_call_duration_us{interface=share,plugin=@synra/aaa-notes}") {
        Some(Value::Histogram(histogram)) => assert_eq!(histogram.count, 1),
        other => panic!("expected a duration histogram, got {other:?}"),
    }
    // ★ The scripted instance adds 4096 bytes on every call, so the gauge has to be that number: a constant zero would
    // also satisfy "the series exists", and the point is that the instance's own reading reached the recorder.
    assert_eq!(
        snapshot.get("plugin_memory_bytes{plugin=@synra/aaa-notes}"),
        Some(&Value::Gauge(4096)),
        "the instance's memory is reported for the plugin that ran"
    );
    // ★ And the report a card reads: the rung, the sentence, and the calls admitted so far. It is the same budget the
    // gate counted into, so a loaded plugin that ran has a report — and a plugin that is not loaded has none.
    let report = set.report_of("@synra/aaa-notes").expect("the plugin is loaded");
    assert_eq!(report.health, "good");
    // Zero because this guest makes no **host** calls — `admitted` counts the gate's, not the dispatcher's. A report of
    // zeroes would still be a report; what matters is that the loaded plugin has one and the unloaded id does not.
    assert_eq!(report.admitted, 0);
    assert!(!report.explanation.is_empty(), "the rung comes with its sentence");
    assert!(set.report_of("@synra/absent").is_none(), "nothing is loaded under that id");
    // ★ And no fuel reading: the scripted backend has no instruction counter, and `None` has to stay "nothing recorded"
    // rather than a zero — a histogram of zeroes would say this plugin spent no instructions when it spent an unknown
    // number. The `Some` side of the same branch is asserted in `wasmtime_tests`, where a real store reports it.
    assert!(
        snapshot.get("plugin_fuel_consumed{plugin=@synra/aaa-notes}").is_none(),
        "a backend without fuel must not report a zero"
    );
}

#[test]
fn a_trapped_call_is_counted_as_a_fault_with_its_outcome() {
    // ★ A trap is the case the health ladder was missing for years; the metric makes it visible without reading that
    // ladder, and the outcome label says which kind of misbehaviour it was rather than only that there was one.
    use synra_observe::metrics::Value;

    let backend = ScriptedBackend::new();
    let metrics = std::sync::Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host())
        .with_metrics(std::sync::Arc::clone(&metrics));
    load(
        &mut set,
        &backend,
        "@synra/bad",
        Scripted::Trap { detail: "boom".to_owned() },
    );
    let work = Work::CanHandle { item_json: share_json().to_owned() };
    let budget = Matcher::new(&mut set).budget();

    // A trap is an outcome, not a `PluginSetError`; the assertion is on the recorder, which is what the panel reads.
    let _ = set.call(&id("@synra/bad"), &work, budget, 1_000);

    assert_eq!(
        metrics.snapshot().get("plugin_faulted_total{outcome=trap,plugin=@synra/bad}"),
        Some(&Value::Counter(1)),
        "the trap is counted against the plugin that produced it"
    );
}

#[test]
fn the_pool_counters_tell_a_warm_call_from_a_cold_one() {
    // ★ "Hit" is the pool handing out a slot that already has an instance; "miss" is one that had to build it. The pair
    // is taken from the set's own `live` map before the call, so it describes what the pool served rather than what the
    // engine spent. A counter that only counted misses would make a warm pool look like a cold one for ever.
    use synra_observe::metrics::Value;

    let backend = ScriptedBackend::new();
    let metrics = std::sync::Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host())
        .with_metrics(std::sync::Arc::clone(&metrics));
    load(
        &mut set,
        &backend,
        "@synra/aaa-notes",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    let work = Work::CanHandle { item_json: share_json().to_owned() };
    let budget = Matcher::new(&mut set).budget();

    set.call(&id("@synra/aaa-notes"), &work, budget, 1_000).expect("a cold call");
    set.call(&id("@synra/aaa-notes"), &work, budget, 2_000).expect("a warm call");

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.get("plugin_pool_miss_total"),
        Some(&Value::Counter(1)),
        "the first call had to instantiate"
    );
    assert_eq!(
        snapshot.get("plugin_pool_hit_total"),
        Some(&Value::Counter(1)),
        "the second found the instance the first left"
    );
}
