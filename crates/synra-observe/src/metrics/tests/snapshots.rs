use super::*;

#[test]
fn a_snapshot_is_sorted_so_two_exports_are_comparable() {
    // An unsorted export makes a diff of two bundles show every line as changed.
    let recorder = RingRecorder::new();
    for name in ["zebra", "alpha", "middle"] {
        recorder.counter_inc(&key(name));
    }

    let snapshot = recorder.snapshot();
    let rendered: Vec<String> = snapshot.values.iter().map(|s| s.key.render()).collect();
    assert_eq!(rendered, vec!["alpha", "middle", "zebra"]);
}

#[test]
fn an_empty_recorder_reports_nothing() {
    let recorder = RingRecorder::new();
    assert!(recorder.is_empty());
    assert_eq!(recorder.len(), 0);
    let snapshot = recorder.snapshot();
    assert!(snapshot.is_empty());
    assert!(snapshot.is_complete());
    assert_eq!(snapshot.get("anything"), None);
}

#[test]
fn clearing_a_recorder_removes_its_series() {
    let recorder = RingRecorder::new();
    recorder.counter_inc(&key("a"));
    recorder.clear();
    assert!(recorder.is_empty());
}

#[test]
fn the_cardinality_guard_admits_up_to_its_limit() {
    let guard = CardinalityGuard::with_max_series(3);
    assert!(guard.admit("metric"));
    assert!(guard.admit("metric"));
    assert!(guard.admit("metric"));
    // The fourth is refused.
    assert!(!guard.admit("metric"));
    assert_eq!(guard.series_count("metric"), 3);
    assert_eq!(guard.overflowed_total(), 1);
}

#[test]
fn the_cardinality_guard_counts_each_metric_separately() {
    // A single mislabelled metric must not consume the budget of every other.
    let guard = CardinalityGuard::with_max_series(1);
    assert!(guard.admit("a"));
    assert!(!guard.admit("a"));
    assert!(guard.admit("b"), "a full metric must not block another");
    assert_eq!(guard.metric_count(), 2);
}

#[test]
fn observations_beyond_the_limit_are_folded_rather_than_dropped() {
    // Dropping them would make the total silently wrong. Folding keeps the sum right and makes the
    // loss visible in the data.
    let recorder = RingRecorder::with_limits(2, vec![1.0, 10.0]);
    let metric = "frames_total";

    for event in ["a", "b", "c", "d"] {
        recorder.counter_inc(&labelled(metric, &[("event", event)]));
    }

    let snapshot = recorder.snapshot();
    // Two real series plus one overflow series.
    let totals: u64 = snapshot
        .values
        .iter()
        .filter_map(|series| match series.value {
            Value::Counter(value) => Some(value),
            _ => None,
        })
        .sum();
    assert_eq!(totals, 4, "no observation was lost");
    assert!(!snapshot.is_complete());
    assert_eq!(snapshot.overflowed_total, 2);
    assert!(
        snapshot.get("frames_total{event=overflow}").is_some(),
        "{:?}",
        snapshot.values
    );
}

#[test]
fn an_existing_series_is_reused_without_touching_the_guard() {
    // The hot path: a metric that already exists must not take a write lock or a guard check, or every
    // counter increment serialises the application.
    let recorder = RingRecorder::with_limits(1, vec![1.0]);
    let k = labelled("frames_total", &[("event", "ping")]);
    recorder.counter_inc(&k);

    for _ in 0..100 {
        recorder.counter_inc(&k);
    }
    assert_eq!(recorder.snapshot().get("frames_total{event=ping}"), Some(&Value::Counter(101)));
    // And the guard still holds exactly one series for the metric.
    assert_eq!(recorder.guard().series_count("frames_total"), 1);
    assert_eq!(recorder.guard().overflowed_total(), 0);
}

#[test]
fn the_snapshot_reports_the_limit_it_was_taken_under() {
    // A reader has to know whether an empty snapshot means "nothing happened" or "everything was
    // folded away", and the two are told apart by the overflow count and the limit together.
    let recorder = RingRecorder::with_limits(7, vec![1.0]);
    let snapshot = recorder.snapshot();
    assert_eq!(snapshot.max_series_per_metric, 7);
    assert!(snapshot.is_complete());
}
