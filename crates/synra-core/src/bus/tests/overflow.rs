use super::super::SUBSCRIBER_QUEUE_CAPACITY;
use super::{Tick, bus};

#[test]
fn a_full_queue_drops_the_oldest_and_counts_it() {
    // ★ The newest event describes the world as it is now. A subscriber behind by a hundred events that receives the
    // hundred-and-first can be brought up to date by a snapshot; one that received the first hundred and not the
    // last is behind by an unknown amount and does not know it.
    let bus = bus();
    let id = bus.subscribe();
    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 3) {
        bus.emit(Tick(seq));
    }

    let delivery = bus.take(id).expect("id");
    assert!(delivery.must_refresh(), "{delivery:?}");
    assert_eq!(delivery.missed(), 3);
    let events = delivery.events();
    assert_eq!(events.len(), SUBSCRIBER_QUEUE_CAPACITY);
    // The oldest three are gone, and the newest is there.
    assert_eq!(events[0], Tick(4));
    assert_eq!(events[events.len() - 1], Tick(SUBSCRIBER_QUEUE_CAPACITY as u64 + 3));
}

#[test]
fn a_queue_that_never_overflows_never_asks_for_a_refresh() {
    // The ordinary case must not be the expensive one: a subscriber that reads after each notification never sees
    // `Behind`, and one that did would re-read a snapshot per event.
    let bus = bus();
    let id = bus.subscribe();
    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64) {
        bus.emit(Tick(seq));
    }
    let delivery = bus.take(id).expect("id");
    assert!(!delivery.must_refresh(), "{delivery:?}");
    assert_eq!(delivery.missed(), 0);
}

#[test]
fn the_overflow_is_reported_once_and_the_total_is_kept() {
    // ★ Telling a subscriber the same loss twice would make a diagnostic count one overflow as several, and a
    // caller that reacted to each would re-read a snapshot per read. The count stays because a diagnostic wants the
    // total rather than the per-read figure.
    let bus = bus();
    let id = bus.subscribe();
    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 1) {
        bus.emit(Tick(seq));
    }

    let first = bus.take(id).expect("id");
    assert_eq!(first.missed(), 1);
    // Nothing new was emitted, so the second read has nothing to hand over at all — and in particular is not reported
    // as `Behind` a second time, which is what would make one overflow look like several.
    assert!(bus.take(id).is_none(), "the loss was already reported");
    // The total survives, for a diagnostic.
    assert_eq!(bus.report(id).expect("id").dropped, 1);
}

#[test]
fn one_subscriber_overflowing_does_not_affect_another() {
    // ★ Each queue is its own. A slow window must not cost a diagnostic tool its events, and a shared buffer would
    // make the fastest reader's health depend on the slowest writer's.
    let bus = bus();
    let slow = bus.subscribe();
    let fast = bus.subscribe();

    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 * 2) {
        bus.emit(Tick(seq));
        // The fast subscriber reads every time, so it never fills.
        let _ = bus.take(fast);
    }

    let slow_delivery = bus.take(slow).expect("slow");
    assert!(slow_delivery.must_refresh());
    assert!(bus.report(slow).expect("slow").dropped > 0);

    let fast_report = bus.report(fast).expect("fast");
    assert_eq!(fast_report.dropped, 0);
    assert!(fast_report.is_healthy());
}

#[test]
fn a_report_says_what_happened_and_why_it_matters() {
    let bus = bus();
    let id = bus.subscribe();
    let healthy = bus.report(id).expect("id");
    assert!(healthy.is_healthy());
    assert!(healthy.explain().contains("none dropped"), "{}", healthy.explain());

    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 5) {
        bus.emit(Tick(seq));
    }
    let behind = bus.report(id).expect("id");
    assert!(!behind.is_healthy());
    assert_eq!(behind.dropped, 5);
    assert_eq!(behind.queued, SUBSCRIBER_QUEUE_CAPACITY);
    // The sentence says what to do, which is the whole point of reporting it.
    assert!(behind.explain().contains("re-read"), "{}", behind.explain());
}

#[test]
fn resetting_the_counters_keeps_the_queue() {
    // Clearing the counts and dropping the events would be two decisions in one call, and the caller that wanted
    // both can read and then reset.
    let bus = bus();
    let id = bus.subscribe();
    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 2) {
        bus.emit(Tick(seq));
    }
    assert!(bus.reset_counters(id));
    let report = bus.report(id).expect("id");
    assert_eq!(report.dropped, 0);
    assert_eq!(report.delivered, 0);
    assert!(report.is_healthy());
    // The queue is untouched.
    assert_eq!(report.queued, SUBSCRIBER_QUEUE_CAPACITY);
}

#[test]
fn every_subscribers_report_is_listed() {
    // A diagnostic bundle wants all of them, and a report that covered only the first would hide the subscriber
    // that is actually the problem.
    let bus = bus();
    let first = bus.subscribe();
    let second = bus.subscribe();
    bus.emit(Tick(1));

    let reports = bus.reports();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].0, first);
    assert_eq!(reports[1].0, second);
    assert!(reports.iter().all(|(_, report)| report.delivered == 1));
}

#[test]
fn a_subscriber_that_stops_reading_learns_how_much_it_missed() {
    // The same loop with the read removed, which is the case the queue is bounded for. The tracker is fed what the
    // subscriber actually received, and computes the hole the bus created.
    let bus = bus();
    let id = bus.subscribe();

    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 7) {
        bus.emit(Tick(seq));
    }

    let delivery = bus.take(id).expect("id");
    assert!(delivery.must_refresh());
    assert_eq!(delivery.missed(), 7);
    // What the subscriber sees begins after the hole, and the tracker's judgement about the first event is `Apply`
    // because it has no history — which is why the bus's own `missed` is what a fresh subscriber relies on.
    assert_eq!(delivery.events()[0], Tick(8));
}
