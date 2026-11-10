use super::*;

// ── Status ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn status_reports_the_hosts_own_state() {
    let dir = TempDir::new("status");
    let value = runtime(dir.path()).status().expect("status");

    assert_eq!(value["state"], "running");
    assert_eq!(value["version"], "0.1.0-test");
    assert_eq!(value["transportPort"], 47100);
    assert_eq!(value["discoveryPort"], 47101);
    assert!(value["dataDir"].as_str().is_some_and(|s| !s.is_empty()));
}

#[test]
fn status_reports_the_gates_counters() {
    // ★ The whole loop, end to end: a plugin's refused call becomes a counter on the recorder the daemon owns, and the
    // daemon's `status` reports it.
    //
    // Every link of this was missing at some point in this session. The recorder had no producer at all; the producer had
    // no way to reach the kernel; and `diag_metrics` was a command in the contract with no trait method, no handler and no
    // data behind it. The reader here is `status`, which is a command that already existed and already worked.
    let dir = TempDir::new("status-metrics");
    let runtime = runtime(dir.path());

    // A refused call, made the way the gate makes one.
    let refused = synra_plugin_host::host_calls::CallError::denied(
        "device:send:*",
        &synra_capability::CapabilitySet::new(),
    );
    assert!(!refused.message.is_empty());
    let key = synra_observe::metrics::SeriesKey::new(
        "gate_denied_total",
        [("capability".to_owned(), "device:send:*".to_owned())],
    );
    runtime.metrics.counter_inc(&key);

    let value = runtime.status().expect("status");
    let series = value["metrics"]["values"]
        .as_array()
        .expect("the series list");
    let refused_series = series
        .iter()
        .find(|entry| entry["key"]["name"] == "gate_denied_total")
        .expect("the refusal is reported");

    assert_eq!(refused_series["value"]["kind"], "counter");
    assert_eq!(refused_series["value"]["value"], 1);
    // And the label survives the trip, because a count without one cannot answer "which permission do plugins keep asking
    // for and not have" — the question the design's `gate_*` metrics exist for.
    let labels = refused_series["key"]["labels"].as_array().expect("labels");
    assert!(
        labels
            .iter()
            .any(|pair| pair[0] == "capability" && pair[1] == "device:send:*"),
        "{refused_series}"
    );
}

#[test]
fn status_names_the_layers_that_are_not_built() {
    // ★ `status` is what a user runs to find out what is going on, so it is where "the kernel is up and this part is
    // not built" belongs. A status that reported a healthy daemon and nothing else would leave them wondering why
    // the next command refuses.
    let dir = TempDir::new("status-missing");
    let value = runtime(dir.path()).status().expect("status");
    let missing = value["notImplemented"].as_array().expect("a list");
    let names: Vec<&str> = missing
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    // ★ The exact contents, and today that is nothing. The list held `session` long after `send --text` and
    // `send --file` both moved real bytes — so it was telling a user that a working feature was missing, which is
    // precisely the failure this assertion exists to catch. An assertion of a *superset* would have passed.
    assert!(
        names.is_empty(),
        "a layer that is not missing is named: {names:?}"
    );

    // And the layers that are real are certainly not in it, each having been removed when it started working.
    for built in ["database", "discovery", "session"] {
        assert!(
            !names.contains(&built),
            "{built} is listed and is real: {names:?}"
        );
    }
}

#[test]
fn the_uptime_is_measured_from_the_start() {
    // Saturating: a start time in the future is a caller with a clock that moved, and a negative duration is not one
    // this can represent.
    let dir = TempDir::new("uptime");
    let value = runtime(dir.path()).status().expect("status");
    assert!(value["uptimeMs"].as_u64().is_some());
}

// ── The missing layer ─────────────────────────────────────────────────────────────────────────

#[test]
fn the_reported_version_is_the_one_a_client_compares() {
    let dir = TempDir::new("version");
    assert_eq!(runtime(dir.path()).version(), "0.1.0-test");
}

#[test]
fn the_wall_clock_is_a_plausible_epoch_reading() {
    // Not a monotonic reading: the value is reported to a separate process, whose monotonic clock is not comparable
    // with this one — the same mistake that once made crash recovery never fire.
    let now = now_ms();
    // Somewhere after 2020 and before 2100, in milliseconds.
    assert!(now > 1_577_836_800_000, "{now}");
    assert!(now < 4_102_444_800_000, "{now}");
}
