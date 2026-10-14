//! The key a series is named by, the limit on how many there may be, and the value it holds.

use std::sync::atomic::{AtomicI64, AtomicU64};


use super::histogram::Histogram;
/// How many distinct label combinations one metric may have.
///
/// A thousand is far more than any legitimate metric needs and small enough that a runaway one costs
/// kilobytes rather than megabytes. The number is per metric, so a single mislabelled metric cannot
/// consume the budget of every other.
pub const DEFAULT_MAX_SERIES_PER_METRIC: usize = 1_000;

/// The label value used for a combination that arrived after the metric was full.
pub const OVERFLOW_LABEL: &str = "overflow";

/// A metric's identity: a name and its label pairs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
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
pub(super) enum Series {
    Counter(AtomicU64),
    Gauge(AtomicI64),
    Histogram(Histogram),
}
