//! What the interface reads.


use super::histogram::HistogramSnapshot;
use super::series::SeriesKey;
/// One series' value.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
pub enum Value {
    /// A monotonically increasing total.
    Counter(u64),
    /// A current value.
    Gauge(i64),
    /// A distribution.
    Histogram(HistogramSnapshot),
}

/// One series in a snapshot.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeriesValue {
    /// The metric and its labels.
    pub key: SeriesKey,
    /// The value.
    pub value: Value,
}

/// A whole recorder's state.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
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
