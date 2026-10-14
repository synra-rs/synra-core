//! The buckets, the bounds they are cut at, and their snapshot.

use std::sync::atomic::{AtomicU64, Ordering};

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
    pub(super) fn new(bounds: &[f64]) -> Self {
        let mut bounds = bounds.to_vec();
        bounds.sort_by(f64::total_cmp);
        bounds.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
        let buckets = (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Self { bounds, buckets, sum: AtomicU64::new(0), count: AtomicU64::new(0) }
    }

    /// Records one observation.
    pub(super) fn observe(&self, value: f64) {
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
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
