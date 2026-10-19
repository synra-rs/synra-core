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
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("late-{now_ms}-{}-{sequence}.json", std::process::id());
        let entry = Entry { envelope: envelope.clone(), attempts: 0, queued_ms: now_ms };
        let bytes = serde_json::to_vec(&entry).map_err(|error| error.to_string())?;
        std::fs::write(self.directory.join(name), bytes).map_err(|error| error.to_string())
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
mod tests {
    use synra_protocol::event::EventName;
use synra_protocol::envelope::Envelope;
use synra_protocol::{DeviceId, RequestId, TraceId};

    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-late-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn envelope() -> Envelope {
        Envelope {
            request_id: RequestId::new(),
            event: EventName::parse(synra_protocol::event::events::INTENT_RESULT).expect("an event name"),
            target: DeviceId::new(),
            from: DeviceId::new(),
            reply_to: None,
            trace_id: TraceId::new(),
            payload: None,
            sent_at_ms: 0,
            ttl_ms: None,
        }
    }

    #[test]
    fn an_answer_is_stored_and_read_back() {
        let scratch = Scratch::new("round-trip");
        let queue = LateQueue::in_data_dir(&scratch.0);
        let before = envelope();
        queue.push(&before, 1_000).expect("queued");

        let due = queue.due(1_000);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 0);
        assert_eq!(due[0].envelope.request_id, before.request_id);
    }

    #[test]
    fn a_delivered_answer_is_removed() {
        let scratch = Scratch::new("delivered");
        let queue = LateQueue::in_data_dir(&scratch.0);
        queue.push(&envelope(), 1_000).expect("queued");

        let summary = queue.retry_with(1_000, |_| Ok(()));
        assert_eq!(summary, RetrySummary { delivered: 1, failed: 0, dropped: 0 });
        assert!(queue.due(1_000).is_empty());
    }

    #[test]
    fn a_failed_answer_is_retried_and_then_dropped_at_the_bound() {
        let scratch = Scratch::new("attempts");
        let queue = LateQueue::in_data_dir(&scratch.0);
        queue.push(&envelope(), 1_000).expect("queued");

        // Every attempt fails; each pass increments the counter until the bound removes the entry.
        for _ in 0..MAX_ATTEMPTS - 1 {
            let summary = queue.retry_with(1_000, |_| Err("gone".to_owned()));
            assert_eq!(summary, RetrySummary { delivered: 0, failed: 1, dropped: 0 });
        }
        let summary = queue.retry_with(1_000, |_| Err("gone".to_owned()));
        assert_eq!(summary, RetrySummary { delivered: 0, failed: 0, dropped: 1 });
        assert!(queue.due(1_000).is_empty(), "an entry over the bound must be gone");
    }

    #[test]
    fn an_answer_older_than_a_day_is_dropped_without_a_dial() {
        let scratch = Scratch::new("stale");
        let queue = LateQueue::in_data_dir(&scratch.0);
        queue.push(&envelope(), 1_000).expect("queued");

        let due = queue.due(1_000 + MAX_AGE_MS + 1);
        assert!(due.is_empty(), "a stale answer must not be dialled");
    }

    #[test]
    fn a_file_that_is_not_an_answer_is_removed_rather_than_retried() {
        let scratch = Scratch::new("corrupt");
        let queue = LateQueue::in_data_dir(&scratch.0);
        std::fs::create_dir_all(queue.directory()).expect("the queue directory");
        std::fs::write(queue.directory().join("late-broken.json"), b"not json").expect("a bad file");

        assert!(queue.due(1_000).is_empty());
        assert!(
            !queue.directory().join("late-broken.json").exists(),
            "a file that can never become an answer was left behind"
        );
    }
}
