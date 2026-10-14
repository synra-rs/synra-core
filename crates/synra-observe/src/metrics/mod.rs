//! Counters, histograms and a bounded recorder.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: what a series *is* (its key, the limit on how many may exist, and the
//! enum that holds the value), the histogram that turns observations into buckets, the guard that bounds cardinality
//! and the ring that holds the recent past, and the snapshot the interface reads. In one file the guard — the part
//! that decides whether a metric stops being recorded — sat between a histogram snapshot and a ring buffer.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `series` | the key a series is named by, the limit on how many there may be, and the stored value |
//! | `histogram` | the buckets, the bounds they are cut at, and their snapshot |
//! | `recorder` | the cardinality guard, and the ring of recent readings |
//! | `reading` | what the interface reads |

mod series;
mod histogram;
mod recorder;
mod reading;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use histogram::{Histogram, HistogramSnapshot};
pub use reading::{MetricsSnapshot, SeriesValue, Value, default_histogram_bounds};
pub use recorder::{CardinalityGuard, RingRecorder};
pub use series::{DEFAULT_MAX_SERIES_PER_METRIC, OVERFLOW_LABEL, SeriesKey};
