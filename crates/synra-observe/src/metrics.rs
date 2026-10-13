//! Metrics: an in-memory recorder with a cardinality bound.
//!
//! # Why not an exporter
//!
//! There is no HTTP scrape endpoint and no push. A desktop application's metrics exist for exactly three
//! readers, all of them local:
//!
//! 1. the settings screen's performance panel,
//! 2. the diagnostic bundle a user chooses to export,
//! 3. a developer running with metrics printing enabled.
//!
//! The `metrics` crate is still the right facade — it keeps the call sites independent of the recorder —
//! but the recorder writes to memory and stops there.
//!
//! # Cardinality is the whole problem
//!
//! A metric labelled by an event name is a metric a plugin can explode. The plugin chooses event names;
//! each distinct one is a new time series; a loop generating names is a loop allocating map entries. The
//! label values here are therefore not trusted to be few.
//!
//! [`CardinalityGuard`] handles it in the only way that keeps the metric useful: it counts the series per
//! metric, and once a metric is full, new label combinations are folded into a single `overflow` series
//! rather than dropped. Dropping them would make the numbers silently wrong; folding them keeps the total
//! right and makes the loss visible in the data.
//!
//! The alternative — hashing the label set with a random seed — is not enough on its own. A random seed
//! stops an adversary choosing collisions, but it does not stop an adversary choosing *new labels*, which
//! is the attack that actually costs memory.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use parking_lot::RwLock;

/// How many distinct label combinations one metric may have.
///
/// A thousand is far more than any legitimate metric needs and small enough that a runaway one costs
/// kilobytes rather than megabytes. The number is per metric, so a single mislabelled metric cannot
/// consume the budget of every other.
pub const DEFAULT_MAX_SERIES_PER_METRIC: usize = 1_000;

/// The label value used for a combination that arrived after the metric was full.
pub const OVERFLOW_LABEL: &str = "overflow";

/// A metric's identity: a name and its label pairs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeriesKey {
    /// The metric name.
    pub name: String,
    /// The label pairs, sorted by key so that two calls with the same labels in a different order are
    /// the same series. A map keyed on insertion order would create a duplicate series per call site.
    pub labels: Vec<(String, String)>,
}

impl SeriesKey {
    /// Builds a key, sorting its labels.
    #[must_use]
    pub fn new(name: impl Into<String>, labels: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut labels: Vec<(String, String)> = labels.into_iter().collect();
        labels.sort();
        Self { name: name.into(), labels }
    }

    /// The key with `overflow` as its only label value.
    ///
    /// The label *names* are kept, so a reader can see which labels were folded rather than being handed a
    /// series that looks like it belongs to a metric with different dimensions.
    #[must_use]
    pub fn overflowed(&self) -> Self {
        Self {
            name: self.name.clone(),
            labels: self
                .labels
                .iter()
                .map(|(key, _)| (key.clone(), OVERFLOW_LABEL.to_owned()))
                .collect(),
        }
    }

    /// Renders the series the way a log line or a diagnostic export would show it.
    #[must_use]
    pub fn render(&self) -> String {
        if self.labels.is_empty() {
            return self.name.clone();
        }
        let labels: Vec<String> = self
            .labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        format!("{}{{{}}}", self.name, labels.join(","))
    }
}

/// A sum that only ever increases, or a value that goes up and down.
#[derive(Debug)]
enum Series {
    Counter(AtomicU64),
    Gauge(AtomicI64),
    Histogram(Histogram),
}

/// A fixed-bucket histogram.
///
/// Fixed buckets rather than a quantile sketch: the bucket boundaries are chosen from the design
/// document's latency targets, which are known, and a sketch would add a dependency and a per-series
/// allocation to answer a question nobody asks of a desktop application.
#[derive(Debug)]
pub struct Histogram {
    /// Upper bounds, ascending, in the metric's own unit.
    bounds: Vec<f64>,
    /// One counter per bound, plus a final bucket for everything above the last bound.
    buckets: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Builds a histogram with the given upper bounds.
    ///
    /// The bounds are sorted and de-duplicated, so an unsorted list from a configuration file cannot make
    /// the recorded values land in the wrong bucket.
    #[must_use]
    fn new(bounds: &[f64]) -> Self {
        let mut bounds = bounds.to_vec();
        bounds.sort_by(f64::total_cmp);
        bounds.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
        let buckets = (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Self { bounds, buckets, sum: AtomicU64::new(0), count: AtomicU64::new(0) }
    }

    /// Records one observation.
    fn observe(&self, value: f64) {
        // The first bound the value does not exceed; past the last bound means the final bucket.
        let index = self
            .bounds
            .iter()
            .position(|bound| value <= *bound)
            .unwrap_or(self.bounds.len());
        if let Some(bucket) = self.buckets.get(index) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        // Stored as a scaled integer because an `AtomicF64` does not exist and a lock per observation is
        // the one cost a histogram on a hot path cannot pay. Nanounits are enough precision for any
        // duration or byte count this application records.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let scaled = (value.max(0.0) * 1e9) as u64;
        self.sum.fetch_add(scaled, Ordering::Relaxed);
    }

    /// A snapshot of the histogram.
    #[must_use]
    pub fn snapshot(&self) -> HistogramSnapshot {
        #[allow(clippy::cast_precision_loss)]
        let sum = self.sum.load(Ordering::Relaxed) as f64 / 1e9;
        HistogramSnapshot {
            bounds: self.bounds.clone(),
            buckets: self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).collect(),
            count: self.count.load(Ordering::Relaxed),
            sum,
        }
    }
}

/// A histogram's values, for an export or a graph.
#[derive(Debug, Clone, PartialEq)]
pub struct HistogramSnapshot {
    /// The upper bounds, ascending.
    pub bounds: Vec<f64>,
    /// Counts, one per bound plus one for the open-ended top bucket.
    pub buckets: Vec<u64>,
    /// How many observations were made.
    pub count: u64,
    /// The sum of all observations.
    pub sum: f64,
}

impl HistogramSnapshot {
    /// The mean observation, if anything was recorded.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn mean(&self) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        Some(self.sum / self.count as f64)
    }

    /// The bucket boundaries with their cumulative counts, for a graph.
    #[must_use]
    pub fn cumulative(&self) -> Vec<(f64, u64)> {
        let mut total = 0u64;
        let mut out = Vec::with_capacity(self.buckets.len());
        for (index, count) in self.buckets.iter().enumerate() {
            total += count;
            // The final bucket has no upper bound; `f64::INFINITY` says so rather than inventing a number.
            let bound = self.bounds.get(index).copied().unwrap_or(f64::INFINITY);
            out.push((bound, total));
        }
        out
    }
}

/// Enforces the per-metric series limit.
///
/// Counts the series each metric has, and answers whether a new one may be admitted. Kept separate from
/// the recorder so the policy can be tested without constructing metrics, and so the recorder's hot path
/// stays a single map lookup in the common case.
#[derive(Debug)]
pub struct CardinalityGuard {
    max_series: usize,
    counts: RwLock<HashMap<String, usize>>,
    overflowed: AtomicU64,
}

impl CardinalityGuard {
    /// A guard with the default limit.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_series(DEFAULT_MAX_SERIES_PER_METRIC)
    }

    /// A guard with an explicit limit.
    #[must_use]
    pub fn with_max_series(max_series: usize) -> Self {
        Self {
            max_series,
            counts: RwLock::new(HashMap::new()),
            overflowed: AtomicU64::new(0),
        }
    }

    /// The limit.
    #[must_use]
    pub const fn max_series(&self) -> usize {
        self.max_series
    }

    /// Records a new series for a metric and reports whether it fits.
    ///
    /// `false` means the caller must fold the observation into the metric's overflow series. The count is
    /// incremented only for admitted series, so a metric that has overflowed does not keep growing its
    /// count.
    pub fn admit(&self, metric: &str) -> bool {
        // The read lock handles the common case — an already-known metric with room left — and is only
        // escalated when the count needs to change. Metrics are written from many tasks, so taking the
        // write lock per observation would serialise the application behind its own instrumentation.
        {
            let counts = self.counts.read();
            match counts.get(metric) {
                Some(count) if *count >= self.max_series => {
                    self.overflowed.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                _ => {}
            }
        }

        let mut counts = self.counts.write();
        let entry = counts.entry(metric.to_owned()).or_insert(0);
        if *entry >= self.max_series {
            drop(counts);
            self.overflowed.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        *entry += 1;
        true
    }

    /// How many series a metric has admitted.
    #[must_use]
    pub fn series_count(&self, metric: &str) -> usize {
        self.counts.read().get(metric).copied().unwrap_or(0)
    }

    /// How many observations were folded into an overflow series.
    #[must_use]
    pub fn overflowed_total(&self) -> u64 {
        self.overflowed.load(Ordering::Relaxed)
    }

    /// How many metrics are being tracked.
    #[must_use]
    pub fn metric_count(&self) -> usize {
        self.counts.read().len()
    }
}

impl Default for CardinalityGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// The in-memory recorder.
///
/// Not registered as the global recorder by construction: a library that installs a global on load takes
/// that decision away from the application, and a test that wanted its own recorder could not have one.
#[derive(Debug)]
pub struct RingRecorder {
    series: RwLock<HashMap<SeriesKey, Arc<Series>>>,
    guard: CardinalityGuard,
    bounds: Vec<f64>,
}

impl Default for RingRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl RingRecorder {
    /// A recorder with the default histogram bounds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            series: RwLock::new(HashMap::new()),
            guard: CardinalityGuard::new(),
            bounds: default_histogram_bounds(),
        }
    }

    /// A recorder with a different series limit and histogram bounds.
    #[must_use]
    pub fn with_limits(max_series: usize, bounds: Vec<f64>) -> Self {
        Self {
            series: RwLock::new(HashMap::new()),
            guard: CardinalityGuard::with_max_series(max_series),
            bounds,
        }
    }

    /// The cardinality guard, for a diagnostic export.
    #[must_use]
    pub const fn guard(&self) -> &CardinalityGuard {
        &self.guard
    }

    /// Adds to a counter.
    pub fn counter_add(&self, key: &SeriesKey, value: u64) {
        let series = self.series_for(key, |_bounds| Series::Counter(AtomicU64::new(0)), &self.bounds);
        if let Series::Counter(counter) = series.as_ref() {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }

    /// Increments a counter by one.
    pub fn counter_inc(&self, key: &SeriesKey) {
        self.counter_add(key, 1);
    }

    /// Sets a gauge's absolute value.
    pub fn gauge_set(&self, key: &SeriesKey, value: i64) {
        let series = self.series_for(key, |_| Series::Gauge(AtomicI64::new(0)), &self.bounds);
        if let Series::Gauge(gauge) = series.as_ref() {
            gauge.store(value, Ordering::Relaxed);
        }
    }

    /// Records a histogram observation.
    pub fn histogram_observe(&self, key: &SeriesKey, value: f64) {
        let series = self.series_for(key, |bounds| Series::Histogram(Histogram::new(bounds)), &self.bounds);
        if let Series::Histogram(histogram) = series.as_ref() {
            histogram.observe(value);
        }
    }

    /// A snapshot of every series.
    ///
    /// Sorted by rendered key, so two exports of the same state are byte-identical and a diff of two
    /// diagnostic bundles shows only what changed.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        // The read guard is bound to a local and dropped before the values are sorted, so the lock is not
        // held across work that does not need it. Clippy's `significant_drop_in_scrutinee` is the same
        // concern one level down: a guard inside an expression whose result outlives it.
        let mut values: Vec<SeriesValue> = {
            let series = self.series.read();
            series
            .iter()
            .map(|(key, series)| SeriesValue {
                key: key.clone(),
                value: match series.as_ref() {
                    Series::Counter(counter) => Value::Counter(counter.load(Ordering::Relaxed)),
                    Series::Gauge(gauge) => Value::Gauge(gauge.load(Ordering::Relaxed)),
                    Series::Histogram(histogram) => Value::Histogram(histogram.snapshot()),
                },
            })
            .collect()
        };
        values.sort_by_key(|series| series.key.render());

        MetricsSnapshot {
            values,
            overflowed_total: self.guard.overflowed_total(),
            max_series_per_metric: self.guard.max_series(),
        }
    }

    /// How many series are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.series.read().len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.series.read().is_empty()
    }

    /// Removes every series. For a test, and for a user who wants the performance panel to start over.
    pub fn clear(&self) {
        self.series.write().clear();
    }

    /// Finds or creates the series for a key, applying the cardinality policy.
    ///
    /// A new series is admitted only if the metric has room. When it does not, the observation is recorded
    /// against the metric's overflow series instead — never dropped, because a counter that silently stops
    /// counting is worse than one that reports a large `overflow` bucket.
    fn series_for(
        &self,
        key: &SeriesKey,
        create: impl Fn(&[f64]) -> Series,
        bounds: &[f64],
    ) -> Arc<Series> {
        // Fast path: the series already exists, so no guard check and no write lock.
        {
            let series = self.series.read();
            if let Some(existing) = series.get(key) {
                return Arc::clone(existing);
            }
        }

        let effective = if self.guard.admit(&key.name) {
            key.clone()
        }
        else {
            key.overflowed()
        };

        let mut series = self.series.write();
        // Re-checked under the write lock: two tasks can both miss the fast path for the same key.
        if let Some(existing) = series.get(&effective) {
            return Arc::clone(existing);
        }
        let created = Arc::new(create(bounds));
        series.insert(effective, Arc::clone(&created));
        created
    }
}

/// One series' value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A monotonically increasing total.
    Counter(u64),
    /// A current value.
    Gauge(i64),
    /// A distribution.
    Histogram(HistogramSnapshot),
}

/// One series in a snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesValue {
    /// The metric and its labels.
    pub key: SeriesKey,
    /// The value.
    pub value: Value,
}

/// A whole recorder's state.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MetricsSnapshot {
    /// Every series, sorted by rendered key.
    pub values: Vec<SeriesValue>,
    /// How many observations were folded into an overflow series.
    pub overflowed_total: u64,
    /// The series limit in force, so a reader knows whether the snapshot is complete.
    pub max_series_per_metric: usize,
}

impl MetricsSnapshot {
    /// Looks up a series by rendered key.
    #[must_use]
    pub fn get(&self, rendered: &str) -> Option<&Value> {
        self.values
            .iter()
            .find(|series| series.key.render() == rendered)
            .map(|series| &series.value)
    }

    /// How many series are present.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the snapshot is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Whether any observation was folded into an overflow series.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.overflowed_total == 0
    }
}

/// The histogram bounds used when none are supplied.
///
/// Chosen from the design document's latency targets: microseconds for a host call, milliseconds for a
/// handshake, seconds for a transfer. One set for every histogram rather than per-metric bounds, because a
/// per-metric choice is a decision nobody revisits and the panel plots them on the same axis anyway.
#[must_use]
pub fn default_histogram_bounds() -> Vec<f64> {
    vec![
        0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0,
        5_000.0, 10_000.0, 30_000.0,
    ]
}

#[cfg(test)]
mod tests {
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
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

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
}
