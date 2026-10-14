//! What the logger has counted.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counts what the writer has seen, so the diagnostics screen can report it.
#[derive(Debug, Default)]
pub struct LogStats {
    pub(super) lines: AtomicU64,
    pub(super) bytes: AtomicU64,
    pub(super) redactions: AtomicU64,
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
}
