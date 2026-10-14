//! The cardinality guard, and the ring of recent readings.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use parking_lot::RwLock;

use super::histogram::Histogram;
use super::reading::{MetricsSnapshot, SeriesValue, Value, default_histogram_bounds};
use super::series::{DEFAULT_MAX_SERIES_PER_METRIC, Series, SeriesKey};
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
