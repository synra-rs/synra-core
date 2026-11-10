use super::*;

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
