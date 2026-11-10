use super::*;

// ── The intent counter ──────────────────────────────────────────────────────────────────────────

#[test]
fn a_share_nothing_can_answer_is_counted_as_refused() {
    // ★ The half that only exists because the counter is written before the `?`. An `intents_total` incremented on the
    // success path would count what was handled and say nothing about the shares that became files — and "why did
    // nothing answer this" is a question about the refusals.
    let dir = TempDir::new("intent-metric");
    let runtime = runtime(dir.path());

    // ★ 这个 fixture 里没有插件，而这**不会**让路由失败 —— 第一版测试就是这么假设的，它失败了：
    // 空插件集也会成功地把一个意图建立起来，返回 `Ok`。所以「路由成功」和「有人回答」是两件事，
    // 而这一条测的正是后者。
    let routed = runtime.intent_dispatch("text/plain", "hello");
    assert!(
        routed.is_ok(),
        "an empty plugin set failed to raise an intent: {routed:?}"
    );

    let snapshot = runtime.metrics.snapshot();
    assert_eq!(
        snapshot.get("intents_total{outcome=ok}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the intent was raised and not counted"
    );
    // 而**没人能处理它**：这是「为什么没人回答」真正的答案，`outcome=ok` 说不出这件事。
    assert_eq!(
        snapshot.get("intent_no_handler_total"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "nothing could handle it, and that is not recorded"
    );
    // ★ And the pass was measured. A histogram with no observations is a shape rather than a measurement, and the shell
    // writes the same name — two hosts describing one dispatch with two metric names would be the drift this workspace
    // keeps finding.
    match snapshot.get("intent_duration_ms") {
        Some(synra_observe::metrics::Value::Histogram(histogram)) => {
            assert!(histogram.count >= 1, "the dispatch was not measured");
        }
        other => panic!("expected a duration histogram, got {other:?}"),
    }
}


#[test]
fn a_store_write_is_counted_with_its_kind() {
    // ★ The store reports a write to the host that installed an observer, and the daemon's install is the same function
    // `serve` calls. A histogram that only existed in a test's own closure would not prove the daemon has one.
    let dir = TempDir::new("db-write-metrics");
    let runtime = runtime(dir.path());
    {
        let mut db = runtime.db();
        crate::runtime::observe_db_writes(&mut db, &runtime.metrics);
    }

    runtime
        .db()
        .set_config("test.key", &serde_json::json!(1), 1)
        .expect("the write is made");

    assert!(
        runtime
            .metrics
            .snapshot()
            .get("db_write_duration_us{kind=config}")
            .is_some(),
        "the store's write was not counted by the daemon's recorder"
    );
}

#[test]
fn the_remote_wait_outlasts_a_plugins_execution_budget() {
    // ★ The wait exists to cover an action running on the far side. A wait shorter than the plugin's own budget gave up
    // while the receiver was still legitimately working, and reported "dispatching" for an action that then succeeded.
    // The two numbers are read from their owners rather than written here, so changing the budget without the wait fails.
    assert!(
        crate::runtime::commands::REMOTE_RESULT_WAIT
            > std::time::Duration::from_millis(synra_core::dispatch::EXECUTE_BUDGET_MS),
        "a dispatched action is awaited for less time than a plugin may run"
    );
}
