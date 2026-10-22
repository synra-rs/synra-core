//! When an unanswered dispatch is sent again.
//!
//! # Why this is in the kernel and not in one host
//!
//! Because the window and the daemon both leave `Dispatching` intents behind when they stop, and both need the same
//! answer to "when is the next try": a schedule that survives a restart, grows with each failure, and stops at a bound. The
//! window had this first; the daemon's one-shot resend (19 §8.224) was the evidence that a second copy would be written if
//! it stayed there. The queue is a value — no threads, no sockets, no clock — so a test moves milliseconds instead of
//! waiting five minutes.
//!
//! # What it deliberately does not do
//!
//! It does not send anything, persist anything, or tell the interface. [`RetryQueue::row`] is the row a host writes and
//! [`RetryQueue::status`] is the sentence a host shows; which link to dial and which event to emit stay with the caller.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use synra_protocol::ids::IntentId;

use crate::supervisor::{Cancellation, RestartPolicy, TaskId};

/// How often a dispatch that is still in flight is sent again.
///
/// # Why these numbers
///
/// A dispatch that timed out has just spent `crate::dispatch::REMOTE_RESULT_WAIT` waiting; retrying immediately would be a
/// busy loop against a device that is asleep. Half a minute is long enough for a peer to come back from a suspend and short
/// enough to be useful; the cap is five minutes because a device that is off will be off for a while, and the attempt bound
/// (eight) is what keeps a day's worth of retries from becoming a day's worth of dials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// The wait before the first retry.
    pub initial: Duration,
    /// The longest wait between retries.
    pub max: Duration,
    /// How many retries before this pass gives up until the next start.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { initial: Duration::from_secs(30), max: Duration::from_secs(300), max_attempts: 8 }
    }
}

impl RetryPolicy {
    /// The wait before retry number `attempt`, jittered by the intent's own name.
    ///
    /// ★ Reusing the supervisor's policy rather than writing a second backoff: the shape (double, cap, add a name-derived
    /// jitter so two intents do not retry in lockstep) is already implemented and already tested.
    #[must_use]
    pub fn delay(self, id: IntentId, attempt: u32) -> Duration {
        RestartPolicy::Backoff { max_attempts: self.max_attempts, initial: self.initial, max: self.max }
            .delay_for(attempt, &TaskId::new(id.to_string()))
    }

    /// The same wait in the store's clock, saturating rather than wrapping.
    #[must_use]
    pub fn delay_ms(self, id: IntentId, attempt: u32) -> i64 {
        i64::try_from(self.delay(id, attempt).as_millis()).unwrap_or(i64::MAX)
    }
}

/// What a host tells the user about one intent's retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryStatus {
    /// How many retries have already been sent.
    pub attempts: u32,
    /// How many this pass will make before giving up.
    pub max_attempts: u32,
    /// Whether this pass stopped retrying. The intent itself is still in flight.
    pub gave_up: bool,
    /// When the next try is due, in milliseconds since the epoch. `None` when nothing is scheduled — a given-up entry,
    /// or one whose attempt is in flight at this moment.
    pub next_at_ms: Option<i64>,
}

/// When each outstanding dispatch is next due, and how many times it has been retried.
#[derive(Debug)]
pub struct RetryQueue {
    policy: RetryPolicy,
    /// How many retries have been scheduled, counting the next one. Missing means "not seen yet".
    attempts: HashMap<IntentId, u32>,
    /// When the next attempt is due, in milliseconds since the epoch. Missing means "not waiting".
    due: HashMap<IntentId, i64>,
    /// Intents this pass stopped retrying. Kept rather than forgotten because the interface is told "no answer yet" — the
    /// intent itself is still `Dispatching`, and the entry goes when the intent ends.
    gave_up: HashSet<IntentId>,
}

impl RetryQueue {
    /// An empty queue.
    #[must_use]
    pub fn new(policy: RetryPolicy) -> Self {
        Self { policy, attempts: HashMap::new(), due: HashMap::new(), gave_up: HashSet::new() }
    }

    /// Rebuilds the schedule from stored rows.
    ///
    /// # What is restored, and what is deliberately not
    ///
    /// The attempt count and the next due time are restored, so a restart does not send the backoff back to thirty seconds.
    /// A **given-up** row is not restored as given up: "gave up until the next start" is what the interface says, and the
    /// next start is this one. Such a row is returned in the second half of the answer for the caller to delete, and the
    /// intent gets a fresh first retry.
    ///
    /// Rows whose intent is no longer pending are returned the same way — a schedule for work that ended is not something
    /// to keep.
    #[must_use]
    pub fn restore(
        policy: RetryPolicy,
        rows: &[synra_store::IntentRetryRow],
        pending: &HashSet<IntentId>,
        now_ms: i64,
    ) -> (Self, Vec<String>) {
        let mut queue = Self::new(policy);
        let mut stale = Vec::new();
        let stored: HashMap<&str, &synra_store::IntentRetryRow> =
            rows.iter().map(|row| (row.intent_id.as_str(), row)).collect();

        for id in pending {
            let key = id.to_string();
            match stored.get(key.as_str()) {
                Some(row) if !row.gave_up => {
                    queue.attempts.insert(*id, row.attempts.saturating_add(1));
                    // A stored time in the past is due now; `take_due` treats it that way without a special case.
                    queue.due.insert(*id, row.next_at_ms.unwrap_or_else(|| now_ms + queue.policy.delay_ms(*id, 1)));
                }
                Some(row) => {
                    stale.push(row.intent_id.clone());
                    queue.attempts.insert(*id, 1);
                    queue.due.insert(*id, now_ms + queue.policy.delay_ms(*id, 1));
                }
                None => {
                    queue.attempts.insert(*id, 1);
                    queue.due.insert(*id, now_ms + queue.policy.delay_ms(*id, 1));
                }
            }
        }
        for row in rows {
            if !pending.iter().any(|id| id.to_string() == row.intent_id) {
                stale.push(row.intent_id.clone());
            }
        }
        (queue, stale)
    }

    /// Schedules anything new, and forgets anything that is no longer in flight.
    ///
    /// # Why the sweep is part of observing
    ///
    /// Because an intent can end for reasons this loop did not cause — the user cancelled it, the answer arrived on the
    /// listener's link, or the retention sweep dropped it. Keeping its entry would mean a due time for work that no longer
    /// exists, and the map would grow for the life of the process.
    ///
    /// # Returns
    ///
    /// The intents that had no entry, so the caller knows which rows it has to write.
    pub fn observe(&mut self, pending: impl IntoIterator<Item = IntentId>, now_ms: i64) -> Vec<IntentId> {
        let pending: HashSet<IntentId> = pending.into_iter().collect();
        self.attempts.retain(|id, _| pending.contains(id));
        self.due.retain(|id, _| pending.contains(id));
        self.gave_up.retain(|id| pending.contains(id));
        let mut added = Vec::new();
        for id in pending {
            if let std::collections::hash_map::Entry::Vacant(entry) = self.attempts.entry(id) {
                entry.insert(1);
                self.due.insert(id, now_ms + self.policy.delay_ms(id, 1));
                added.push(id);
            }
        }
        added
    }

    /// The ids whose wait is over, removed from the schedule.
    ///
    /// Removed rather than left: the caller is about to attempt them, and a due time that is still in the past would make the
    /// next `take_due` hand the same id out again.
    pub fn take_due(&mut self, now_ms: i64) -> Vec<IntentId> {
        let due: Vec<IntentId> =
            self.due.iter().filter_map(|(id, at)| (*at <= now_ms).then_some(*id)).collect();
        for id in &due {
            self.due.remove(id);
        }
        due
    }

    /// Schedules the next attempt, or gives up when the bound is reached.
    ///
    /// Returns whether another attempt was scheduled. Giving up keeps the entry and its count: the card says "no answer
    /// after N tries", and dropping the entry at the same moment would leave the page with nothing to say.
    pub fn record_failure(&mut self, id: IntentId, now_ms: i64) -> bool {
        let attempt = self.attempts.entry(id).or_insert(0);
        *attempt = attempt.saturating_add(1);
        if *attempt > self.policy.max_attempts {
            self.gave_up.insert(id);
            return false;
        }
        self.due.insert(id, now_ms + self.policy.delay_ms(id, *attempt));
        true
    }

    /// Removes an intent: it was answered, or it ended.
    pub fn forget(&mut self, id: IntentId) {
        self.attempts.remove(&id);
        self.due.remove(&id);
        self.gave_up.remove(&id);
    }

    /// What the interface is told about one intent's retries, when there is anything to tell.
    ///
    /// Nothing before the first retry has failed: an intent whose first attempt is still waiting is simply `Dispatching`,
    /// and "retrying (0/8)" would describe work that has not happened yet.
    #[must_use]
    pub fn status(&self, id: IntentId) -> Option<RetryStatus> {
        let next = *self.attempts.get(&id)?;
        let attempts = next.saturating_sub(1);
        let gave_up = self.gave_up.contains(&id);
        if attempts == 0 && !gave_up {
            return None;
        }
        Some(RetryStatus {
            attempts,
            max_attempts: self.policy.max_attempts,
            gave_up,
            next_at_ms: self.due.get(&id).copied(),
        })
    }

    /// The row that preserves this intent's schedule, when it has one.
    ///
    /// `attempts` is the count of retries **already made**, which is one less than the internal next-attempt number.
    #[must_use]
    pub fn row(&self, id: IntentId) -> Option<synra_store::IntentRetryRow> {
        let next = *self.attempts.get(&id)?;
        Some(synra_store::IntentRetryRow {
            intent_id: id.to_string(),
            attempts: next.saturating_sub(1),
            next_at_ms: self.due.get(&id).copied(),
            gave_up: self.gave_up.contains(&id),
        })
    }

    /// How long until the next attempt, or [`Duration::MAX`] when nothing is waiting.
    #[must_use]
    pub fn next_wait(&self, now_ms: i64) -> Duration {
        self.due
            .values()
            .map(|at| at.saturating_sub(now_ms).max(0))
            .filter_map(|ms| u64::try_from(ms).ok())
            .min()
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }
}

/// How one attempt ended, as the runner needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// The answer arrived and the host applied it.
    Answered,
    /// The intent is no longer in flight, so there is nothing to send. Its schedule goes without a retry.
    Ended,
    /// The send went out and nothing came back inside the wait.
    Unanswered,
    /// The send could not be made at all.
    Failed,
}

/// The host-specific halves of the retry loop.
///
/// # Why a trait and not four closures
///
/// Because the three pieces read the same host state, and a closure passed for each would either capture it three times
/// or need a struct anyway. A trait is that struct with the compiler checking which half is which.
pub trait RetryHost {
    /// The intents the host would send right now.
    fn pending(&mut self) -> Vec<IntentId>;

    /// One attempt at one intent.
    fn attempt(&mut self, id: IntentId) -> Attempt;

    /// A schedule changed: the row to write (or `None` to remove it) and what to tell the user.
    fn changed(
        &mut self,
        id: IntentId,
        row: Option<synra_store::IntentRetryRow>,
        status: Option<RetryStatus>,
    );
}

/// Runs the schedule until cancelled.
///
/// # What is shared, and what is not
///
/// The loop is the same in every host: take what is due, attempt it, forget the answered, back off the rest, see what
/// new work appeared, then sleep until the next due time. What differs is [`RetryHost`] — how to send, where to write,
/// what to show. Before this, the window and the daemon each wrote that loop; a change to the wait ceiling or the
/// give-up rule had to be made twice.
///
/// The clock and the sleep are arguments rather than calls, so a test drives a number forward and a cancellation
/// instead of waiting five minutes.
pub fn run_loop(
    queue: &mut RetryQueue,
    cancel: &Cancellation,
    host: &mut dyn RetryHost,
    now: &mut dyn FnMut() -> i64,
    sleep: &mut dyn FnMut(Duration),
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }

        for id in queue.take_due(now()) {
            match host.attempt(id) {
                Attempt::Answered | Attempt::Ended => queue.forget(id),
                Attempt::Unanswered | Attempt::Failed => {
                    // The return value is "another attempt was scheduled"; a host that cares reads `status.gave_up` in
                    // `changed`, which is the same fact in the shape it shows.
                    let _ = queue.record_failure(id, now());
                }
            }
            host.changed(id, queue.row(id), queue.status(id));
        }

        // New dispatches can appear while a send is in flight; the next wake has to see them, and their first schedule
        // has to be written down.
        for id in queue.observe(host.pending(), now()) {
            host.changed(id, queue.row(id), queue.status(id));
        }

        let wait = queue
            .next_wait(now())
            .min(Duration::from_secs(30))
            .max(Duration::from_millis(10));
        sleep(wait);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    const NOW: i64 = 1_000;

    /// A host that answers from a script and records what the runner told it.
    struct Fake {
        pending: Vec<IntentId>,
        outcomes: VecDeque<Attempt>,
        changes: Vec<(IntentId, Option<synra_store::IntentRetryRow>, Option<RetryStatus>)>,
        attempts: usize,
    }

    impl RetryHost for Fake {
        fn pending(&mut self) -> Vec<IntentId> {
            std::mem::take(&mut self.pending)
        }

        fn attempt(&mut self, _id: IntentId) -> Attempt {
            self.attempts += 1;
            self.outcomes.pop_front().unwrap_or(Attempt::Answered)
        }

        fn changed(
            &mut self,
            id: IntentId,
            row: Option<synra_store::IntentRetryRow>,
            status: Option<RetryStatus>,
        ) {
            self.changes.push((id, row, status));
        }
    }

    #[test]
    fn an_answered_dispatch_is_forgotten_and_the_change_is_reported() {
        let id = IntentId::new();
        let mut queue = RetryQueue::new(RetryPolicy::default());
        let _ = queue.observe([id], 0);
        let mut host =
            Fake { pending: Vec::new(), outcomes: VecDeque::from([Attempt::Answered]), changes: Vec::new(), attempts: 0 };
        let cancel = Cancellation::new();
        let mut now = || 100_000;
        let mut waits = Vec::new();
        let mut sleep = |wait| {
            waits.push(wait);
            cancel.cancel();
        };

        run_loop(&mut queue, &cancel, &mut host, &mut now, &mut sleep);

        assert_eq!(host.attempts, 1, "the due entry was attempted");
        assert_eq!(queue.status(id), None, "an answered intent is not retried");
        assert_eq!(host.changes.len(), 1, "one change: the schedule went away");
        assert!(host.changes[0].1.is_none(), "the row to write is the removal");
        assert_eq!(waits.len(), 1, "the runner slept once before the cancellation");
    }

    #[test]
    fn an_unanswered_dispatch_is_backed_off_and_the_bound_is_reported() {
        let id = IntentId::new();
        let policy =
            RetryPolicy { initial: Duration::from_millis(1), max: Duration::from_millis(2), max_attempts: 1 };
        let mut queue = RetryQueue::new(policy);
        let _ = queue.observe([id], 0);
        let mut host = Fake {
            pending: vec![id],
            outcomes: VecDeque::from([Attempt::Unanswered]),
            changes: Vec::new(),
            attempts: 0,
        };
        let cancel = Cancellation::new();
        let mut now = || 100_000;
        let mut sleep = |_| cancel.cancel();

        run_loop(&mut queue, &cancel, &mut host, &mut now, &mut sleep);

        assert_eq!(host.attempts, 1);
        assert_eq!(
            queue.status(id),
            Some(RetryStatus { attempts: 1, max_attempts: 1, gave_up: true, next_at_ms: None })
        );
        assert_eq!(
            host.changes.last().and_then(|(_, _, status)| *status),
            Some(RetryStatus { attempts: 1, max_attempts: 1, gave_up: true, next_at_ms: None }),
            "the host was told why the card changes"
        );
    }

    #[test]
    fn a_pending_dispatch_is_not_due_until_its_first_wait_has_passed() {
        // ★ The immediate pass has just run; retrying at zero would be a busy loop against a device that is asleep.
        let mut queue = RetryQueue::new(RetryPolicy::default());
        let id = IntentId::new();
        let _ = queue.observe([id], NOW);

        assert!(queue.take_due(NOW).is_empty(), "the first wait has not passed");
        assert_eq!(queue.take_due(NOW + 60_000), vec![id], "a minute is past any first wait of thirty seconds");
    }

    #[test]
    fn each_failed_retry_waits_at_least_as_long_as_the_one_before() {
        // The growth the policy promises. The jitter is added rather than symmetric, so "at least as long" is the real
        // property and a test can assert it without knowing the name-derived offset.
        let policy = RetryPolicy::default();
        let id = IntentId::new();
        let mut previous = Duration::ZERO;
        for attempt in 1..=5 {
            let wait = policy.delay(id, attempt);
            assert!(wait >= previous, "attempt {attempt} waited less: {previous:?} -> {wait:?}");
            assert!(wait <= policy.max, "attempt {attempt} passed the ceiling: {wait:?}");
            previous = wait;
        }
    }

    #[test]
    fn a_retry_that_keeps_failing_is_given_up_on_after_the_bound() {
        // ★ Giving up is about this process's effort, not the action's outcome: the intent stays dispatching, so a late
        // answer can still end it and the 24-hour expiry still collects it.
        let policy =
            RetryPolicy { initial: Duration::from_millis(1), max: Duration::from_millis(2), max_attempts: 3 };
        let mut queue = RetryQueue::new(policy);
        let id = IntentId::new();
        let _ = queue.observe([id], NOW);
        let later = NOW + 10_000;

        for retry in 1..=3 {
            let at = later + i64::from(retry) * 10_000;
            assert_eq!(queue.take_due(at), vec![id], "retry {retry} should be due");
            let more = queue.record_failure(id, at);
            assert_eq!(more, retry < 3, "after retry {retry} another was scheduled: {more}");
        }
        assert!(queue.take_due(later + 60_000).is_empty());
        assert!(queue.gave_up.contains(&id), "the entry is kept so the page can say why");
        assert_eq!(
            queue.status(id),
            Some(RetryStatus { attempts: 3, max_attempts: 3, gave_up: true, next_at_ms: None })
        );
    }

    #[test]
    fn the_status_is_silent_until_a_retry_has_actually_failed() {
        // ★ An intent whose first attempt is still waiting is `Dispatching`; "retrying (0/8)" would describe work that
        // has not happened.
        let mut queue = RetryQueue::new(RetryPolicy::default());
        let id = IntentId::new();
        let _ = queue.observe([id], NOW);
        assert_eq!(queue.status(id), None);

        let at = NOW + 60_000;
        let _ = queue.take_due(at);
        queue.record_failure(id, at);
        assert_eq!(
            queue.status(id),
            Some(RetryStatus {
                attempts: 1,
                max_attempts: 8,
                gave_up: false,
                next_at_ms: Some(at + RetryPolicy::default().delay_ms(id, 2)),
            })
        );

        queue.forget(id);
        assert_eq!(queue.status(id), None);
    }

    #[test]
    fn an_intent_that_ended_leaves_the_schedule() {
        // The board is the authority: a cancel, a late answer, or the retention sweep can end an intent while the loop is
        // sleeping, and a due time for work that no longer exists would keep the loop awake and the map growing.
        let mut queue = RetryQueue::new(RetryPolicy::default());
        let id = IntentId::new();
        let _ = queue.observe([id], NOW);
        let _ = queue.observe(std::iter::empty(), NOW + 1_000);

        assert!(queue.attempts.is_empty());
        assert!(queue.take_due(NOW + 600_000).is_empty());
    }

    #[test]
    fn an_answer_removes_the_schedule_without_a_retry() {
        let mut queue = RetryQueue::new(RetryPolicy::default());
        let id = IntentId::new();
        let _ = queue.observe([id], NOW);
        queue.forget(id);

        assert!(queue.take_due(NOW + 600_000).is_empty());
        assert_eq!(queue.next_wait(NOW), Duration::MAX);
    }

    #[test]
    fn a_restart_continues_the_schedule_and_forgets_what_cannot_be_used() {
        // ★ The point of writing the schedule down: a dispatch already retried three times does not begin again at the
        // first wait. A given-up row is deliberately *not* restored as given up — the interface said "until the next
        // start", and this is it — so it is returned as stale and gets a fresh first retry.
        let id = IntentId::new();
        let given_up = IntentId::new();
        let finished = IntentId::new();
        let rows = vec![
            synra_store::IntentRetryRow {
                intent_id: id.to_string(),
                attempts: 3,
                next_at_ms: Some(50_000),
                gave_up: false,
            },
            synra_store::IntentRetryRow {
                intent_id: given_up.to_string(),
                attempts: 8,
                next_at_ms: None,
                gave_up: true,
            },
            synra_store::IntentRetryRow {
                intent_id: finished.to_string(),
                attempts: 2,
                next_at_ms: Some(50_000),
                gave_up: false,
            },
        ];
        let pending: HashSet<IntentId> = [id, given_up].into_iter().collect();

        let (mut queue, stale) = RetryQueue::restore(RetryPolicy::default(), &rows, &pending, 10_000);

        assert_eq!(
            queue.status(id),
            Some(RetryStatus { attempts: 3, max_attempts: 8, gave_up: false, next_at_ms: Some(50_000) }),
            "the count came back"
        );
        assert!(
            !queue.take_due(49_999).contains(&id),
            "the stored wait is respected: the intent is not due before its stored time"
        );
        assert_eq!(queue.take_due(50_000), vec![id], "and then it is due");

        assert_eq!(queue.status(given_up), None, "a new process gets a fresh chance");
        assert!(stale.contains(&given_up.to_string()), "the given-up row was replaced");
        assert!(stale.contains(&finished.to_string()), "a schedule for work that ended is stale");
        assert_eq!(queue.attempts.get(&given_up), Some(&1), "the fresh first retry was scheduled");
    }
}
