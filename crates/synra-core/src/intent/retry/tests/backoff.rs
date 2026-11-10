use super::*;

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
