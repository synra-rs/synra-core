use super::AuditEntry;

/// The default retention, in days.
///
/// Fourteen, matching the log retention. A record of what a plugin did is only useful while the user can
/// still remember the session it refers to.
pub const DEFAULT_RETENTION_DAYS: u32 = 14;

/// How long records are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Days to keep.
    pub days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self { days: DEFAULT_RETENTION_DAYS }
    }
}

impl Retention {
    /// The cutoff, in milliseconds since the epoch, before which records are stale.
    #[must_use]
    pub fn cutoff_ms(&self, now_ms: i64) -> i64 {
        let window = i64::from(self.days) * 24 * 60 * 60 * 1_000;
        now_ms.saturating_sub(window)
    }

    /// Whether a record should be removed.
    #[must_use]
    pub fn is_stale(&self, entry: &AuditEntry, now_ms: i64) -> bool {
        entry.at_ms < self.cutoff_ms(now_ms)
    }

    /// Checks the retention is usable.
    ///
    /// # Errors
    ///
    /// A description if the window is zero, which would delete every record as it was written and leave the
    /// user with an audit page that never shows anything.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.days == 0 {
            return Err("retention must be at least a day, or the audit page is always empty");
        }
        Ok(())
    }
}
