//! The metrics module's tests.

use super::*;

fn key(name: &str) -> SeriesKey {
    SeriesKey::new(name, Vec::<(String, String)>::new())
}

fn labelled(name: &str, pairs: &[(&str, &str)]) -> SeriesKey {
    SeriesKey::new(
        name,
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    )
}

#[test]
fn a_series_key_sorts_its_labels() {
    // Two call sites that pass the same labels in a different order must be the same series, or the
    // same measurement appears twice and both halves look half as large.
    let a = labelled("frames", &[("event", "ping"), ("peer", "abc")]);
    let b = labelled("frames", &[("peer", "abc"), ("event", "ping")]);
    assert_eq!(a, b);
    assert_eq!(a.render(), "frames{event=ping,peer=abc}");
}

#[test]
fn a_series_key_renders_without_labels_too() {
    assert_eq!(key("uptime").render(), "uptime");
}

#[test]
fn an_overflowed_key_keeps_its_label_names() {
    // The names are what tell a reader which dimension was folded. Replacing them entirely would
    // produce a series that looks like it belongs to a metric with different labels.
    let overflowed = labelled("frames", &[("event", "a"), ("peer", "b")]).overflowed();
    assert_eq!(overflowed.render(), "frames{event=overflow,peer=overflow}");
}

#[test]
fn a_counter_accumulates() {
    let recorder = RingRecorder::new();
    let frames = key("frames_sent_total");
    recorder.counter_inc(&frames);
    recorder.counter_add(&frames, 4);

    assert_eq!(recorder.snapshot().get("frames_sent_total"), Some(&Value::Counter(5)));
    assert_eq!(recorder.len(), 1, "a counter is one series");
}

#[test]
fn a_gauge_takes_its_last_value() {
    let recorder = RingRecorder::new();
    let links = key("links_open");
    recorder.gauge_set(&links, 3);
    recorder.gauge_set(&links, 1);

    assert_eq!(recorder.snapshot().get("links_open"), Some(&Value::Gauge(1)));
}

#[test]
fn a_gauge_may_go_negative() {
    // A gauge that could not go negative would be useless for the things gauges are for: a delta, a
    // queue depth after a drain.
    let recorder = RingRecorder::new();
    recorder.gauge_set(&key("delta"), -5);
    assert_eq!(recorder.snapshot().get("delta"), Some(&Value::Gauge(-5)));
}

#[test]
fn a_histogram_counts_every_observation() {
    let recorder = RingRecorder::new();
    let durations = key("handshake_ms");
    for value in [0.5, 3.0, 3.0, 7.0, 8.0, 120.0, 60_000.0] {
        recorder.histogram_observe(&durations, value);
    }

    let snapshot = recorder.snapshot();
    let Some(Value::Histogram(histogram)) = snapshot.get("handshake_ms") else {
        panic!("expected a histogram");
    };
    assert_eq!(histogram.count, 7);
    // The sum is stored as scaled integers, so the assertion is approximate. The arithmetic is
    // 0.5 + 3 + 3 + 7 + 8 + 120 + 60000.
    assert!((histogram.sum - 60_141.5).abs() < 0.01, "{}", histogram.sum);

    // The cumulative counts are non-decreasing and end at the total, which is what a graph plots.
    // Asserting the individual buckets would restate the default bounds; asserting the shape does not.
    let cumulative = histogram.cumulative();
    assert!(cumulative.windows(2).all(|pair| pair[0].1 <= pair[1].1), "{cumulative:?}");
    assert_eq!(cumulative.last().map(|(_, count)| *count), Some(7));
    assert_eq!(cumulative.last().map(|(bound, _)| *bound), Some(f64::INFINITY));
}

#[test]
fn a_histogram_places_values_in_the_first_bound_they_fit() {
    let recorder = RingRecorder::with_limits(100, vec![1.0, 2.0, 4.0]);
    let metric = key("x");
    // Exactly on a bound counts as inside it, which is what a latency target means: "under 2 ms"
    // includes 2 ms.
    recorder.histogram_observe(&metric, 2.0);
    recorder.histogram_observe(&metric, 4.1);

    let snapshot = recorder.snapshot();
    let Some(Value::Histogram(histogram)) = snapshot.get("x") else {
        panic!("expected a histogram");
    };
    assert_eq!(histogram.buckets, vec![0, 1, 0, 1]);
}

#[test]
fn an_empty_histogram_reports_no_mean() {
    // A mean of zero and "no observations" are different facts, and a panel that showed 0 would claim
    // the operation was instantaneous.
    let recorder = RingRecorder::new();
    recorder.histogram_observe(&key("nothing"), 0.0);
    let snapshot = recorder.snapshot();
    let Some(Value::Histogram(histogram)) = snapshot.get("nothing") else {
        panic!("expected a histogram");
    };
    assert_eq!(histogram.mean(), Some(0.0), "one observation of zero is a real mean");
    // An empty histogram has no mean: "no observations" and "zero" are different facts, and a panel
    // that showed 0 would claim the operation was instantaneous.
    let empty = HistogramSnapshot { bounds: Vec::new(), buckets: Vec::new(), count: 0, sum: 0.0 };
    assert_eq!(empty.mean(), None, "no observations has no mean");
}

#[test]
fn unsorted_histogram_bounds_are_sorted() {
    // Bounds come from a configuration file, which a person edited. An unsorted list would put
    // observations in the wrong bucket, and the graph would be wrong rather than broken.
    let recorder = RingRecorder::with_limits(100, vec![10.0, 1.0, 5.0]);
    recorder.histogram_observe(&key("x"), 3.0);

    let snapshot = recorder.snapshot();
    let Some(Value::Histogram(histogram)) = snapshot.get("x") else {
        panic!("expected a histogram");
    };
    assert_eq!(histogram.bounds, vec![1.0, 5.0, 10.0]);
    // 3.0 fits in the 5.0 bucket, which is the second one after sorting.
    assert_eq!(histogram.buckets, vec![0, 1, 0, 0]);
}

#[test]
fn duplicate_histogram_bounds_are_collapsed() {
    let recorder = RingRecorder::with_limits(100, vec![1.0, 1.0, 2.0]);
    recorder.histogram_observe(&key("x"), 0.5);
    let snapshot = recorder.snapshot();
    let Some(Value::Histogram(histogram)) = snapshot.get("x") else {
        panic!("expected a histogram");
    };
    assert_eq!(histogram.bounds, vec![1.0, 2.0]);
    assert_eq!(histogram.buckets.len(), 3, "one per bound plus the open top bucket");
}

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

#[test]
fn default_bounds_are_ascending_and_cover_a_wide_range() {
    let bounds = default_histogram_bounds();
    assert!(bounds.windows(2).all(|pair| pair[0] < pair[1]), "{bounds:?}");
    assert!(bounds.first().is_some_and(|first| *first < 1.0), "sub-millisecond host calls");
    assert!(bounds.last().is_some_and(|last| *last >= 30_000.0), "a slow transfer");
}

#[test]
fn a_histogram_records_into_the_open_top_bucket() {
    let recorder = RingRecorder::with_limits(100, vec![1.0, 2.0]);
    recorder.histogram_observe(&key("x"), 1_000.0);

    let snapshot = recorder.snapshot();
    let Some(Value::Histogram(histogram)) = snapshot.get("x") else {
        panic!("expected a histogram");
    };
    // Two bounds means three buckets, and the value is in the last.
    assert_eq!(histogram.buckets, vec![0, 0, 1]);
    let cumulative = histogram.cumulative();
    assert_eq!(cumulative.last().map(|(_, c)| *c), Some(1));
}

#[test]
fn a_negative_observation_does_not_corrupt_the_sum() {
    // Durations are never negative, but a subtraction that went the wrong way produces one, and a sum
    // that wrapped would be a number nobody could interpret.
    let recorder = RingRecorder::new();
    recorder.histogram_observe(&key("x"), -5.0);
    let snapshot = recorder.snapshot();
    let Some(Value::Histogram(histogram)) = snapshot.get("x") else {
        panic!("expected a histogram");
    };
    assert!(histogram.sum >= 0.0, "{}", histogram.sum);
    assert_eq!(histogram.count, 1, "the observation is still counted");
}
