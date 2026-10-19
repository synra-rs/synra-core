//! What the logger has counted.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counts what the writer has seen, so the diagnostics screen can report it.
#[derive(Debug, Default)]
pub struct LogStats {
    pub(super) lines: AtomicU64,
    pub(super) bytes: AtomicU64,
    pub(super) redactions: AtomicU64,
    pub(super) dropped: AtomicU64,
    pub(super) write_errors: AtomicU64,
    /// The most recent write failure's own words.
    ///
    /// A count says the logger is failing; this says *why*, and "the disk is full" and "the directory was removed" call
    /// for different actions. `parking_lot` rather than a `std` lock because the writer is already using it and a poisoned
    /// mutex must not be able to stop a log line from being counted.
    pub(super) last_error: parking_lot::Mutex<Option<String>>,
}

impl LogStats {
    /// How many lines have been written.
    #[must_use]
    pub fn lines(&self) -> u64 {
        self.lines.load(Ordering::Relaxed)
    }

    /// How many bytes have been written.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// How many values have been withheld.
    ///
    /// Reported because it is the one number that says whether the redaction policy is doing anything: a
    /// count of zero across a long session means either nothing sensitive was logged or the policy is not
    /// being applied, and both are worth knowing.
    #[must_use]
    pub fn redactions(&self) -> u64 {
        self.redactions.load(Ordering::Relaxed)
    }

    /// How many lines were discarded because the writer could not keep up.
    ///
    /// # Why a log line is ever discarded
    ///
    /// Because the alternative is worse: a synchronous writer blocks whatever was being logged — a transport thread, a
    /// command — for as long as the disk takes, and a diagnostics facility that slows the product down is one that gets
    /// turned off. The queue is bounded, so a flood over a loaded disk drops lines; this counter is what keeps that from
    /// being silent.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Counts one discarded line.
    pub(super) fn record_drop(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// How many lines reached the queue but could not be written to the file.
    ///
    /// # Why this is not an error a user sees immediately
    ///
    /// Because the writer is a background thread: there is no caller to return an error to, and a logger that logged its
    /// own failure would be a loop. The count is the report — the next `synra logs` says the file is behind, which is the
    /// actionable fact (a full disk, a removed directory).
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    /// Counts one failed write to the destination, keeping the failure's own sentence.
    pub(super) fn record_write_error(&self, detail: impl Into<String>) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock() = Some(detail.into());
    }

    /// The most recent write failure, when there was one.
    #[must_use]
    pub fn last_write_error(&self) -> Option<String> {
        self.last_error.lock().clone()
    }
}
