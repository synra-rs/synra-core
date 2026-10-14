//! The metrics module's property tests.

use super::*;
use proptest::prelude::*;

use std::collections::HashMap;

/// A metric with no labels, for a property that is about the value rather than the key.
fn key(name: &str) -> SeriesKey {
    SeriesKey::new(name, Vec::<(String, String)>::new())
}

/// A metric with one label, for a property that is about cardinality.
fn labelled(name: &str, pairs: &[(&str, &str)]) -> SeriesKey {
    SeriesKey::new(
        name,
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    )
}

proptest! {
    /// A series key is invariant under the order its labels were supplied in. Without this the same
    /// measurement becomes two series, and both halves look half as large.
    #[test]
    fn a_series_key_is_order_independent(
        pairs in proptest::collection::vec(("[a-z]{1,6}", "[a-z0-9]{1,6}"), 0..6),
    ) {
        let mut reversed = pairs.clone();
        reversed.reverse();

        let forward = SeriesKey::new(
            "m",
            pairs.iter().map(|(k, v)| (k.clone(), v.clone())),
        );
        let backward = SeriesKey::new(
            "m",
            reversed.iter().map(|(k, v)| (k.clone(), v.clone())),
        );
        prop_assert_eq!(forward, backward);
    }

    /// The guard admits at most `max_series` series per metric, whatever order the names arrive in.
    /// This is the bound that stops a plugin exhausting memory by being verbose.
    #[test]
    fn the_guard_never_admits_more_than_its_limit(
        max in 1usize..8,
        metrics in proptest::collection::vec("[a-z]{1,4}", 1..40),
    ) {
        let guard = CardinalityGuard::with_max_series(max);
        let mut admitted: HashMap<String, usize> = HashMap::new();
        for metric in &metrics {
            if guard.admit(metric) {
                *admitted.entry(metric.clone()).or_insert(0) += 1;
            }
        }
        for (metric, count) in &admitted {
            prop_assert!(*count <= max, "{} admitted {} times", metric, count);
            prop_assert_eq!(guard.series_count(metric), *count);
        }
    }

    /// A counter's total is exactly the sum of everything added, including through overflow. A
    /// silently dropped observation is the failure this design exists to avoid.
    #[test]
    fn no_observation_is_lost_to_overflow(
        max in 1usize..4,
        labels in proptest::collection::vec("[a-z]{1,4}", 1..20),
    ) {
        let recorder = RingRecorder::with_limits(max, vec![1.0, 10.0]);
        for label in &labels {
            recorder.counter_inc(&labelled("m", &[("k", label)]));
        }

        let total: u64 = recorder
            .snapshot()
            .values
            .iter()
            .filter_map(|series| match series.value {
                Value::Counter(value) => Some(value),
                _ => None,
            })
            .sum();
        prop_assert_eq!(total, labels.len() as u64);
    }

    /// A histogram's cumulative counts end at its observation count, and every observation lands in
    /// exactly one bucket. A value counted twice would make a graph's tail exceed its head.
    #[test]
    fn a_histogram_counts_each_observation_once(
        values in proptest::collection::vec(0.0f64..100_000.0, 0..60),
        bounds in proptest::collection::vec(1.0f64..10_000.0, 0..6),
    ) {
        let recorder = RingRecorder::with_limits(100, bounds);
        for value in &values {
            recorder.histogram_observe(&key("m"), *value);
        }

        let snapshot = recorder.snapshot();
        let Some(Value::Histogram(histogram)) = snapshot.get("m") else {
            return Ok(());
        };
        let total: u64 = histogram.buckets.iter().sum();
        prop_assert_eq!(total, values.len() as u64);
        prop_assert_eq!(histogram.count, values.len() as u64);
        prop_assert_eq!(
            histogram.cumulative().last().map(|(_, c)| *c),
            Some(values.len() as u64),
        );
    }
}
