//! Late answers that outlived the connection they were meant for, kept until someone can deliver them.
//!
//! # Why a directory rather than a table
//!
//! Because the producer is the listener, which has no database handle on the connection thread and should not grow one: it
//! has the data directory, and the answer is a self-contained envelope. A file per answer is the smallest durable record
//! that does not couple the connection path to the store — and a file that fails to write is a warning, not a reason to
//! break the connection that just answered.
//!
//! # What bounds it
//!
//! Attempts and age. A device that is gone should not be dialled every thirty seconds for ever, and a bundle of envelopes
//! that nobody can deliver should not grow without end. Ten attempts or one day, whichever comes first; the entry is
//! removed and counted as dropped rather than silently kept.
//!
//! # What it is not
//!
//! A general outbox. Only answers that were already spoken (the receiver ran the action) are queued: the delivery is the
//! last step of work that really happened, which is why retrying it is right whereas retrying an unstarted action would
//! not be.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use synra_protocol::envelope::Envelope;

/// How many times one queued answer is tried before it is dropped.
pub const MAX_ATTEMPTS: u32 = 10;

/// How long an answer may wait before it is dropped as stale.
pub const MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// How many answers may wait at once.
///
/// ★ A bound on the **queue**, not only on one entry: ten attempts and a day are per answer, and a device that is gone while
/// this one keeps producing answers would otherwise fill the data directory with files that will all be dropped after a day
/// anyway. Past this, the oldest entry is removed first — it is the one closest to its own expiry.
pub const MAX_ENTRIES: usize = 100;

/// The directory under the data directory that holds the queue.
pub const DIRECTORY: &str = "late-results";

/// Distinguishes two answers queued in the same millisecond by this process.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One answer waiting to be delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    envelope: Envelope,
    attempts: u32,
    queued_ms: i64,
}

/// One entry read back from disk.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The file it came from.
    path: PathBuf,
    /// The answer to deliver.
    pub envelope: Envelope,
    /// How many times delivery has failed.
    pub attempts: u32,
    /// When it was queued.
    pub queued_ms: i64,
}

/// What one pass over the queue did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetrySummary {
    /// Answers that reached their device and were removed.
    pub delivered: usize,
    /// Answers that failed and remain queued.
    pub failed: usize,
    /// Answers that exhausted their attempts or their time and were removed.
    pub dropped: usize,
}

/// The queue under one data directory.
#[derive(Debug, Clone)]
pub struct LateQueue {
    directory: PathBuf,
}

impl LateQueue {
    /// The queue belonging to a data directory.
    #[must_use]
    pub fn in_data_dir(data_dir: &Path) -> Self {
        Self { directory: data_dir.join(DIRECTORY) }
    }

    /// The directory the entries live in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Stores an answer for a later attempt.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal. The caller reports it and continues: the connection has already been answered, and a
    /// queue that cannot be written is a warning rather than a reason to fail the work that produced the answer.
    pub fn push(&self, envelope: &Envelope, now_ms: i64) -> Result<(), String> {
        std::fs::create_dir_all(&self.directory).map_err(|error| error.to_string())?;
        self.prune_for_one_more();
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("late-{now_ms}-{}-{sequence}.json", std::process::id());
        let entry = Entry { envelope: envelope.clone(), attempts: 0, queued_ms: now_ms };
        let bytes = serde_json::to_vec(&entry).map_err(|error| error.to_string())?;
        std::fs::write(self.directory.join(name), bytes).map_err(|error| error.to_string())
    }

    /// How many answers are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|extension| extension == "json"))
            .count()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes the oldest entries until one more fits under [`MAX_ENTRIES`].
    ///
    /// The name starts with the queue time, so sorting the file names is sorting by age — and a file whose name is not one
    /// of this queue's is left alone. A failure to remove is not worth failing the push: the bound is a cleanup, and the
    /// answer being written is the one that matters.
    fn prune_for_one_more(&self) {
        while self.len() >= MAX_ENTRIES {
            let Ok(entries) = std::fs::read_dir(&self.directory) else {
                return;
            };
            let mut names: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
                .collect();
            names.sort();
            let Some(oldest) = names.first() else {
                return;
            };
            if std::fs::remove_file(oldest).is_err() {
                return;
            }
        }
    }

    /// Reads the entries that may still be tried, dropping the ones that are too old.
    ///
    /// A file that cannot be parsed is removed rather than retried for ever: it is not going to become an envelope.
    #[must_use]
    pub fn due(&self, now_ms: i64) -> Vec<Pending> {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return Vec::new();
        };
        let mut due = Vec::new();
        for file in entries.flatten() {
            let path = file.path();
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(entry) = serde_json::from_slice::<Entry>(&bytes) else {
                let _ = std::fs::remove_file(&path);
                continue;
            };
            if entry.attempts >= MAX_ATTEMPTS || now_ms.saturating_sub(entry.queued_ms) > MAX_AGE_MS {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            due.push(Pending {
                path,
                envelope: entry.envelope,
                attempts: entry.attempts,
                queued_ms: entry.queued_ms,
            });
        }
        due
    }

    /// Removes one entry, after it was delivered or dropped.
    pub fn remove(&self, pending: &Pending) {
        let _ = std::fs::remove_file(&pending.path);
    }

    /// Records one failed delivery; returns whether the entry is still queued.
    ///
    /// `false` means it was removed because the attempt bound was reached — the caller counts that as dropped.
    #[must_use]
    pub fn record_failure(&self, pending: &Pending) -> bool {
        let attempts = pending.attempts.saturating_add(1);
        if attempts >= MAX_ATTEMPTS {
            let _ = std::fs::remove_file(&pending.path);
            return false;
        }
        let entry = Entry {
            envelope: pending.envelope.clone(),
            attempts,
            queued_ms: pending.queued_ms,
        };
        let Ok(bytes) = serde_json::to_vec(&entry) else {
            return true;
        };
        std::fs::write(&pending.path, bytes).is_ok()
    }

    /// Tries every due entry once, and reports what happened.
    ///
    /// The delivery is a parameter so the queue's decisions — delivered, retry, drop — are testable without a listener.
    pub fn retry_with(
        &self,
        now_ms: i64,
        mut deliver: impl FnMut(&Envelope) -> Result<(), String>,
    ) -> RetrySummary {
        let mut summary = RetrySummary::default();
        for pending in self.due(now_ms) {
            match deliver(&pending.envelope) {
                Ok(()) => {
                    self.remove(&pending);
                    summary.delivered += 1;
                }
                Err(_) if self.record_failure(&pending) => summary.failed += 1,
                Err(_) => summary.dropped += 1,
            }
        }
        summary
    }
}

#[cfg(test)]
mod tests;
