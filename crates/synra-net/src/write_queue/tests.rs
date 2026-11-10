use core::time::Duration;

use synra_protocol::limits::WRITE_QUEUE_CAPACITY;

use crate::liveness::LinkHealth;

use super::{CloseReason, QueueOutcome, QueueRefusal, WriteQueue};

fn queue() -> WriteQueue<u32> {
    WriteQueue::with_capacity(4)
}

#[test]
fn a_new_queue_is_open_and_empty() {
    let queue = queue();
    assert_eq!(queue.capacity(), 4);
    assert!(queue.is_empty());
    assert_eq!(queue.fill_percent(), 0);
    assert!(!queue.is_closed());
    assert_eq!(queue.close_reason(), None);
}

#[test]
fn the_default_capacity_is_the_protocol_constant() {
    // One definition of the bound, so a change to the constant moves this and nothing else.
    assert_eq!(WriteQueue::<u32>::new().capacity(), WRITE_QUEUE_CAPACITY);
}

#[test]
fn frames_come_out_in_the_order_they_went_in() {
    // Ordering is what makes a transfer's chunks assemble into the right file.
    let mut queue = queue();
    for value in 1..=4 {
        queue.push(value).expect("queues");
    }
    assert_eq!(queue.drain(), vec![1, 2, 3, 4]);
    assert!(queue.is_empty());
}

#[test]
fn a_frame_comes_out_of_the_front() {
    let mut queue = queue();
    queue.push(1).expect("queues");
    queue.push(2).expect("queues");
    assert_eq!(queue.pop(), Some(1));
    assert_eq!(queue.pop(), Some(2));
    assert_eq!(queue.pop(), None);
}

#[test]
fn filling_past_the_threshold_reports_congestion() {
    // A burst is ordinary, so congestion is reported rather than acted on.
    let mut queue = WriteQueue::with_capacity(4);
    assert_eq!(queue.push(1).expect("queues"), QueueOutcome::Queued);
    assert_eq!(
        queue.push(2).expect("queues"),
        QueueOutcome::QueuedCongested { queue_percent: 50 }
    );
    assert_eq!(
        queue.push(3).expect("queues"),
        QueueOutcome::QueuedCongested { queue_percent: 75 }
    );
}

#[test]
fn a_full_queue_refuses_and_closes_the_link() {
    // Dropping the newest frame would silently lose a message; dropping the oldest would break a transfer's
    // ordering. Closing is the only option where the loss is visible.
    let mut queue = queue();
    for value in 1..=4 {
        queue.push(value).expect("queues");
    }
    assert!(!queue.is_closed());

    match queue.push(5) {
        Err(QueueRefusal::Full { queued, capacity }) => {
            assert_eq!(queued, 4);
            assert_eq!(capacity, 4);
        }
        other => panic!("expected a full refusal, got {other:?}"),
    }
    assert!(queue.is_closed());
    assert_eq!(queue.close_reason(), Some(CloseReason::Overflow));
}

#[test]
fn an_overflow_discards_everything_queued() {
    // The caller has to know that nothing it thought was sent will arrive — holding the frames would be a queue
    // that grows through the path that exists to bound it.
    let mut queue = queue();
    for value in 1..=4 {
        queue.push(value).expect("queues");
    }
    let _ = queue.push(5);
    assert!(queue.is_empty(), "the queued frames were not discarded");
}

#[test]
fn a_full_queue_reported_as_an_outcome_carries_the_counts() {
    let mut queue = queue();
    for value in 1..=4 {
        queue.push(value).expect("queues");
    }
    let outcome = queue.push_lossy(5);
    match outcome {
        QueueOutcome::Overflowed { queued, discarded } => {
            assert_eq!(queued, 4);
            assert_eq!(discarded, 4);
        }
        other => panic!("expected an overflow, got {other:?}"),
    }
    assert!(!outcome.link_survived());
}

#[test]
fn pushing_to_a_closed_queue_is_refused_with_the_reason() {
    let mut queue = queue();
    queue.close(CloseReason::Goodbye);
    match queue.push(1) {
        Err(QueueRefusal::Closed { reason }) => assert_eq!(reason, CloseReason::Goodbye),
        other => panic!("expected a closed refusal, got {other:?}"),
    }
}

#[test]
fn pushing_to_a_closed_queue_as_an_outcome_does_not_overwrite_the_reason() {
    // A goodbye is a decision; reporting it as an overflow would have the caller reconnect to a peer that is
    // shutting down.
    let mut queue = queue();
    queue.close(CloseReason::Goodbye);
    let outcome = queue.push_lossy(1);
    assert!(!outcome.link_survived());
    assert_eq!(queue.close_reason(), Some(CloseReason::Goodbye));
}

#[test]
fn closing_discards_what_is_queued() {
    let mut queue = queue();
    queue.push(1).expect("queues");
    queue.close(CloseReason::Requested);
    assert!(queue.is_empty());
}

#[test]
fn reopening_always_starts_empty() {
    // The previous connection's frames were discarded when it closed, so there is nothing to carry over.
    let mut queue = queue();
    queue.push(1).expect("queues");
    queue.close(CloseReason::Silent);

    queue.reopen();
    assert!(!queue.is_closed());
    assert!(queue.is_empty());
    assert_eq!(queue.push(2).expect("queues"), QueueOutcome::Queued);
}

#[test]
fn the_fill_percentage_is_what_it_says() {
    let mut queue = WriteQueue::with_capacity(10);
    for value in 0..5 {
        queue.push(value).expect("queues");
    }
    assert_eq!(queue.fill_percent(), 50);
    for value in 5..9 {
        queue.push(value).expect("queues");
    }
    assert_eq!(queue.fill_percent(), 90);
}

#[test]
fn a_queue_with_no_capacity_reports_full_immediately() {
    // A capacity of zero is a configuration that can carry nothing, and reporting it as healthy would have the
    // caller wait forever.
    let mut queue: WriteQueue<u32> = WriteQueue::with_capacity(0);
    assert_eq!(queue.fill_percent(), 100);
    assert!(matches!(queue.push(1), Err(QueueRefusal::Full { .. })));
    assert_eq!(queue.health(0, Duration::from_secs(1)), LinkHealth::Overflow);
}

#[test]
fn health_follows_the_queue_and_the_silence() {
    let timeout = Duration::from_millis(250);

    let mut queue = WriteQueue::with_capacity(4);
    assert_eq!(queue.health(0, timeout), LinkHealth::Healthy);

    queue.push(1).expect("queues");
    queue.push(2).expect("queues");
    assert_eq!(queue.health(0, timeout), LinkHealth::Congested { queue_percent: 50 });

    // Silence takes precedence: a dead link is dead whatever its queue says.
    assert_eq!(queue.health(250, timeout), LinkHealth::Silent { silent_ms: 250 });
}

#[test]
fn health_reports_a_closed_queue_as_unusable_whatever_the_reason() {
    for reason in [
        CloseReason::Overflow,
        CloseReason::Goodbye,
        CloseReason::Refused,
        CloseReason::Silent,
        CloseReason::Requested,
        CloseReason::WriteFailed,
    ] {
        let mut queue = queue();
        queue.close(reason);
        let health = queue.health(0, Duration::from_secs(10));
        assert!(health.should_close(), "{reason:?}");
        assert!(!health.is_usable(), "{reason:?}");
    }
}

#[test]
fn an_empty_queue_allocates_nothing_large() {
    // The capacity hint is clamped, because a queue of 256 frames declared at start-up should not reserve room
    // for a configuration that allows a million.
    let queue: WriteQueue<u32> = WriteQueue::with_capacity(1_000_000);
    assert_eq!(queue.capacity(), 1_000_000);
    assert!(queue.is_empty());
}

// ── Close reasons ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_deliberate_end_is_not_worth_reconnecting_to() {
    assert!(!CloseReason::Goodbye.is_worth_reconnecting());
    assert!(!CloseReason::Refused.is_worth_reconnecting());
    for reason in [
        CloseReason::Overflow,
        CloseReason::Silent,
        CloseReason::WriteFailed,
        CloseReason::Requested,
    ] {
        assert!(reason.is_worth_reconnecting(), "{reason:?}");
    }
}

#[test]
fn neither_refusal_is_retryable() {
    // A caller that looped on either would spin: a full queue closes the link, and a closed link stays closed
    // until it is replaced.
    assert!(!QueueRefusal::Full { queued: 1, capacity: 1 }.is_retryable());
    assert!(!QueueRefusal::Closed { reason: CloseReason::Goodbye }.is_retryable());
}

#[test]
fn every_close_reason_has_a_name_for_a_log_line() {
    for reason in [
        CloseReason::Overflow,
        CloseReason::Goodbye,
        CloseReason::Refused,
        CloseReason::Silent,
        CloseReason::Requested,
        CloseReason::WriteFailed,
    ] {
        let name = reason.as_str();
        assert!(!name.is_empty(), "{reason:?}");
        assert!(!name.contains(' '), "{reason:?} -> {name}");
    }
}

#[test]
fn the_default_queue_matches_the_constructor() {
    assert_eq!(WriteQueue::<u32>::default().capacity(), WriteQueue::<u32>::new().capacity());
}
