use super::*;

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
