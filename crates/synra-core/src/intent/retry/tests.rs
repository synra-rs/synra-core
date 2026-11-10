use std::collections::VecDeque;

use super::*;

const NOW: i64 = 1_000;

/// A host that answers from a script and records what the runner told it.
struct Fake {
    pending: Vec<IntentId>,
    outcomes: VecDeque<Attempt>,
    changes: Vec<(
        IntentId,
        Option<synra_store::IntentRetryRow>,
        Option<RetryStatus>,
    )>,
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
    let mut host = Fake {
        pending: Vec::new(),
        outcomes: VecDeque::from([Attempt::Answered]),
        changes: Vec::new(),
        attempts: 0,
    };
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
    assert!(
        host.changes[0].1.is_none(),
        "the row to write is the removal"
    );
    assert_eq!(
        waits.len(),
        1,
        "the runner slept once before the cancellation"
    );
}

#[test]
fn an_unanswered_dispatch_is_backed_off_and_the_bound_is_reported() {
    let id = IntentId::new();
    let policy = RetryPolicy {
        initial: Duration::from_millis(1),
        max: Duration::from_millis(2),
        max_attempts: 1,
    };
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
        Some(RetryStatus {
            attempts: 1,
            max_attempts: 1,
            gave_up: true,
            next_at_ms: None
        })
    );
    assert_eq!(
        host.changes.last().and_then(|(_, _, status)| *status),
        Some(RetryStatus {
            attempts: 1,
            max_attempts: 1,
            gave_up: true,
            next_at_ms: None
        }),
        "the host was told why the card changes"
    );
}

#[test]
fn a_pending_dispatch_is_not_due_until_its_first_wait_has_passed() {
    // ★ The immediate pass has just run; retrying at zero would be a busy loop against a device that is asleep.
    let mut queue = RetryQueue::new(RetryPolicy::default());
    let id = IntentId::new();
    let _ = queue.observe([id], NOW);

    assert!(
        queue.take_due(NOW).is_empty(),
        "the first wait has not passed"
    );
    assert_eq!(
        queue.take_due(NOW + 60_000),
        vec![id],
        "a minute is past any first wait of thirty seconds"
    );
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
        assert!(
            wait >= previous,
            "attempt {attempt} waited less: {previous:?} -> {wait:?}"
        );
        assert!(
            wait <= policy.max,
            "attempt {attempt} passed the ceiling: {wait:?}"
        );
        previous = wait;
    }
}

#[test]
fn a_retry_that_keeps_failing_is_given_up_on_after_the_bound() {
    // ★ Giving up is about this process's effort, not the action's outcome: the intent stays dispatching, so a late
    // answer can still end it and the 24-hour expiry still collects it.
    let policy = RetryPolicy {
        initial: Duration::from_millis(1),
        max: Duration::from_millis(2),
        max_attempts: 3,
    };
    let mut queue = RetryQueue::new(policy);
    let id = IntentId::new();
    let _ = queue.observe([id], NOW);
    let later = NOW + 10_000;

    for retry in 1..=3 {
        let at = later + i64::from(retry) * 10_000;
        assert_eq!(queue.take_due(at), vec![id], "retry {retry} should be due");
        let more = queue.record_failure(id, at);
        assert_eq!(
            more,
            retry < 3,
            "after retry {retry} another was scheduled: {more}"
        );
    }
    assert!(queue.take_due(later + 60_000).is_empty());
    assert!(
        queue.gave_up.contains(&id),
        "the entry is kept so the page can say why"
    );
    assert_eq!(
        queue.status(id),
        Some(RetryStatus {
            attempts: 3,
            max_attempts: 3,
            gave_up: true,
            next_at_ms: None
        })
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
        Some(RetryStatus {
            attempts: 3,
            max_attempts: 8,
            gave_up: false,
            next_at_ms: Some(50_000)
        }),
        "the count came back"
    );
    assert!(
        !queue.take_due(49_999).contains(&id),
        "the stored wait is respected: the intent is not due before its stored time"
    );
    assert_eq!(queue.take_due(50_000), vec![id], "and then it is due");

    assert_eq!(
        queue.status(given_up),
        None,
        "a new process gets a fresh chance"
    );
    assert!(
        stale.contains(&given_up.to_string()),
        "the given-up row was replaced"
    );
    assert!(
        stale.contains(&finished.to_string()),
        "a schedule for work that ended is stale"
    );
    assert_eq!(
        queue.attempts.get(&given_up),
        Some(&1),
        "the fresh first retry was scheduled"
    );
}
