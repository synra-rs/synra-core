//! The event bus's tests.

use std::sync::Arc;

use synra_protocol::event::MAX_COUNTED_GAP;

use super::*;
/// An event, which the bus clones per subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tick(u64);

fn bus() -> EventBus<Tick> {
    EventBus::new()
}

// ── Sequence numbers ──────────────────────────────────────────────────────────────────────────

#[test]
fn the_first_event_is_numbered_one() {
    // ★ The client library's tracker treats a sequence at or below the last as a repeat, so a bus that started at
    // zero would make every subscriber see its first event as one it had already had. The numbering is part of the
    // wire contract, asserted rather than left to `0` being the natural default.
    let bus = bus();
    assert_eq!(bus.next_sequence(), 1);
    assert_eq!(bus.emit(Tick(1)), 1);
    assert_eq!(bus.emit(Tick(2)), 2);
}

#[test]
fn the_sequence_is_the_bus_is_not_the_subscribers() {
    // Two subscribers see the same numbers, because the numbers are a property of the stream. A bus per subscriber
    // would give each its own, and two interfaces comparing what they saw would disagree about which event came
    // first.
    let bus = bus();
    let first = bus.subscribe();
    let second = bus.subscribe();

    bus.emit(Tick(1));
    bus.emit(Tick(2));

    assert_eq!(bus.take(first).expect("first").events(), &[Tick(1), Tick(2)]);
    assert_eq!(bus.take(second).expect("second").events(), &[Tick(1), Tick(2)]);
}

#[test]
fn last_sequence_is_none_before_anything_is_emitted() {
    // `next - 1` would be zero, and zero is not a sequence number this bus hands out — a caller comparing it would
    // be comparing against a number that never appears.
    let bus = bus();
    assert_eq!(bus.last_sequence(), None);
    bus.emit(Tick(1));
    assert_eq!(bus.last_sequence(), Some(1));
}

// ── Subscribers ───────────────────────────────────────────────────────────────────────────────

#[test]
fn an_event_reaches_every_subscriber() {
    let bus = bus();
    let first = bus.subscribe();
    let second = bus.subscribe();
    assert_eq!(bus.subscriber_count(), 2);

    bus.emit(Tick(7));
    assert_eq!(bus.take(first).expect("first").events(), &[Tick(7)]);
    assert_eq!(bus.take(second).expect("second").events(), &[Tick(7)]);
}

#[test]
fn an_event_emitted_before_a_subscriber_existed_does_not_reach_it() {
    // A subscriber sees the stream from where it attached. A bus that replayed its history would give a diagnostic
    // tool the whole past unbounded, and a second window every event since the kernel started.
    let bus = bus();
    bus.emit(Tick(1));
    let late = bus.subscribe();
    bus.emit(Tick(2));
    assert_eq!(bus.take(late).expect("late").events(), &[Tick(2)]);
}

#[test]
fn taking_empties_the_queue() {
    // A `take` that left the events would hand the same event to a caller twice, which is what the sequence tracker
    // then refuses — so the mistake would be invisible except as a stalled queue.
    let bus = bus();
    let id = bus.subscribe();
    bus.emit(Tick(1));
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(1)]);
    // ★ And the second read answers `None` rather than an empty batch, which is what makes a drain terminate: a `while
    // let Some(..)` around a call that answered `Some(vec![])` would loop for ever rather than fail.
    assert!(bus.take(id).is_none(), "an empty queue is nothing to hand over");
}

#[test]
fn peeking_does_not_consume() {
    // For a caller that has to decide whether to read before reading. The events are still there afterwards.
    let bus = bus();
    let id = bus.subscribe();
    bus.emit(Tick(1));
    assert_eq!(bus.peek(id).expect("id").events(), &[Tick(1)]);
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(1)]);
}

#[test]
fn unsubscribing_removes_the_queue() {
    // ★ A subscriber that went away without unsubscribing is memory held for the life of the kernel, and a caller
    // that opened a window per device would leak one per window.
    let bus = bus();
    let id = bus.subscribe();
    bus.emit(Tick(1));

    assert!(bus.unsubscribe(id));
    assert_eq!(bus.subscriber_count(), 0);
    // And a second unsubscribe is `false` rather than an error: an interface torn down twice is ordinary.
    assert!(!bus.unsubscribe(id));
    assert!(bus.take(id).is_none());
    assert!(bus.report(id).is_none());
}

#[test]
fn an_unknown_subscriber_reads_nothing_rather_than_panicking() {
    // A stale identity is ordinary — a window closed while a timer was in flight — and a panic there would take the
    // kernel down for a UI mistake.
    let bus: EventBus<Tick> = bus();
    let ghost = SubscriberId(9_999);
    assert!(bus.take(ghost).is_none());
    assert!(bus.peek(ghost).is_none());
    assert!(bus.report(ghost).is_none());
    assert!(!bus.reset_counters(ghost));
}

#[test]
fn the_emitter_does_not_learn_whether_anyone_was_listening() {
    // ★ A kernel that blocked when an interface was slow would be one where a resizing window pauses device
    // discovery. The contract is `emit` and nothing else, and what it returns is the sequence number rather than a
    // subscriber count.
    let bus: EventBus<Tick> = bus();
    assert_eq!(bus.emit(Tick(1)), 1);
    assert_eq!(bus.emit(Tick(2)), 2);
}

// ── The bounded queue ─────────────────────────────────────────────────────────────────────────

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

// ── The sequence tracker ──────────────────────────────────────────────────────────────────────

#[test]
fn the_first_event_is_applied_whatever_its_number() {
    // A subscriber that attached mid-stream — a second window, a diagnostic tool — starts where it starts. Calling
    // its first event a gap would make it re-read a snapshot it has just taken.
    let mut tracker = SequenceTracker::new();
    assert_eq!(tracker.observe(1), Judgement::Apply);
    assert!(!tracker.is_stale());

    let mut late = SequenceTracker::new();
    assert_eq!(late.observe(5_000), Judgement::Apply);
    assert!(!late.is_stale());
}

#[test]
fn a_repeat_is_refused_quietly() {
    // ★ A channel delivers the same event twice around a reconnect. Applying it twice is what makes a device appear
    // once in a list and be fetched twice. And it is not a fault, so it does not set the stale flag: a caller that
    // treated a repeat as a gap would re-read a snapshot for every duplicate.
    let mut tracker = SequenceTracker::new();
    assert_eq!(tracker.observe(5), Judgement::Apply);
    assert_eq!(tracker.observe(5), Judgement::IgnoreRepeat);
    assert_eq!(tracker.observe(4), Judgement::IgnoreRepeat);
    assert!(!tracker.is_stale());
    assert_eq!(tracker.gaps(), 0);
}

#[test]
fn a_gap_is_reported_with_its_size() {
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    assert_eq!(tracker.observe(4), Judgement::RefreshSnapshot { missed: Some(2) });
    assert!(tracker.is_stale());
    assert_eq!(tracker.gaps(), 1);
}

#[test]
fn a_contiguous_event_after_a_gap_is_applied_and_the_picture_stays_known_stale() {
    // ★ The decision an earlier version got wrong: leaving the sequence where it was made every event after a gap
    // another gap, so the interface could not make progress without a round trip per event. Advancing says "I know
    // where I am; my picture is incomplete until the snapshot arrives" — and the flag is what says the second half.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    assert!(matches!(tracker.observe(3), Judgement::RefreshSnapshot { .. }));
    assert!(tracker.is_stale());

    assert_eq!(tracker.observe(4), Judgement::Apply);
    // Applied, and still known to be incomplete.
    assert!(tracker.is_stale());
    assert_eq!(tracker.gaps(), 1);
    assert_eq!(tracker.last_seen(), Some(4));
}

#[test]
fn a_snapshot_makes_the_picture_whole_again() {
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    tracker.observe(9);
    assert!(tracker.is_stale());
    tracker.snapshot_taken();
    assert!(!tracker.is_stale());
    // And the gap count survives, because it is a count of what happened rather than of what is still wrong.
    assert_eq!(tracker.gaps(), 1);
}

#[test]
fn a_gap_beyond_the_cap_is_reported_as_unknown_rather_than_capped() {
    // ★ Reporting `MAX_COUNTED_GAP` for a gap of four billion would be a number the caller believes. `None` says
    // "there was a gap and its size is not worth reporting", which is the same instruction — re-read — without a
    // false figure.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    let judgement = tracker.observe(u64::from(MAX_COUNTED_GAP) + 100);
    assert_eq!(judgement, Judgement::RefreshSnapshot { missed: None });
    assert!(tracker.is_stale());
}

#[test]
fn a_gap_exactly_at_the_cap_is_counted_and_one_beyond_it_is_not() {
    // ★ The boundary, asserted because an off-by-one there is a gap that reports itself as unknown when its size is
    // exactly the largest a consumer is told — or a capped figure where the true one would not have fitted.
    //
    // The count is the number of events *between* the two seen, which is the difference less one. That is the figure
    // a consumer can act on: seeing 1 and 1001 means events 2 through 1000 are missing, which is 999.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    assert_eq!(
        tracker.observe(u64::from(MAX_COUNTED_GAP) + 1),
        Judgement::RefreshSnapshot { missed: Some(MAX_COUNTED_GAP - 1) }
    );

    // One further and the gap is exactly the cap, which is still reported.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    assert_eq!(
        tracker.observe(u64::from(MAX_COUNTED_GAP) + 2),
        Judgement::RefreshSnapshot { missed: Some(MAX_COUNTED_GAP) }
    );

    // One beyond that and the size is not worth a number.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    assert_eq!(
        tracker.observe(u64::from(MAX_COUNTED_GAP) + 3),
        Judgement::RefreshSnapshot { missed: None }
    );
}

#[test]
fn a_gap_from_the_buses_first_event_is_counted() {
    // The first event is applied whatever its number, so the gap between it and the second is one less than the
    // difference — and getting that wrong is a report that is off by one for every subscriber that attaches late.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1_000);
    assert_eq!(tracker.observe(1_003), Judgement::RefreshSnapshot { missed: Some(2) });
}

#[test]
fn resetting_forgets_the_stream_and_the_gap_count() {
    // ★ The gap count goes too: it is a count of the gaps in *this* stream, and a reloaded interface that carried
    // the old total would report a number about a stream it is no longer reading.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    tracker.observe(50);
    assert!(tracker.is_stale());
    assert_eq!(tracker.gaps(), 1);

    tracker.reset();
    assert_eq!(tracker.last_seen(), None);
    assert_eq!(tracker.gaps(), 0);
    assert!(!tracker.is_stale());
    // And the next event is the first again rather than a gap.
    assert_eq!(tracker.observe(1), Judgement::Apply);
}

#[test]
fn the_tracker_and_the_bus_agree_about_what_a_subscriber_saw() {
    // ★ The integration the two halves exist for: the bus drops the oldest, the tracker notices the hole, and the
    // subscriber's instruction is to re-read. A test of either alone would miss a disagreement between the size the
    // bus dropped and the size the tracker computed.
    let bus = bus();
    let id = bus.subscribe();
    let mut tracker = SequenceTracker::new();

    let mut judgements = Vec::new();
    for seq in 1..=(SUBSCRIBER_QUEUE_CAPACITY as u64 + 7) {
        let emitted = bus.emit(Tick(seq));
        // The subscriber reads every time, so nothing overflows — and everything is applied.
        let delivery = bus.take(id).expect("id");
        assert!(!delivery.must_refresh());
        for _ in delivery.events() {
            judgements.push(tracker.observe(emitted));
        }
    }
    assert!(judgements.iter().all(|judgement| *judgement == Judgement::Apply));
    assert!(!tracker.is_stale());
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

#[test]
fn a_bus_with_no_subscribers_still_numbers_its_events() {
    // The numbering is the kernel's, not a subscriber's. A kernel that only counted when someone was listening
    // would restart its numbering when the last window closed, and an interface that reconnected would see numbers
    // it had already seen.
    let bus: EventBus<Tick> = bus();
    assert_eq!(bus.emit(Tick(1)), 1);
    assert_eq!(bus.emit(Tick(2)), 2);
    let id = bus.subscribe();
    bus.emit(Tick(3));
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(3)]);
    assert_eq!(bus.last_sequence(), Some(3));
}

#[test]
fn the_default_bus_is_empty_and_numbered_from_one() {
    let bus: EventBus<Tick> = EventBus::default();
    assert_eq!(bus.subscriber_count(), 0);
    assert_eq!(bus.next_sequence(), 1);
}

#[test]
fn the_bus_can_be_shared_between_threads() {
    // ★ Where the bus is used: one kernel task emits and several interfaces read, so the bus crosses threads by
    // construction. A compile-time assertion with a runtime witness — a bus that was not `Send + Sync` would not
    // compile here, and the failure would otherwise appear wherever it was first put behind an `Arc`.
    fn assert_shareable<T: Send + Sync>() {}
    assert_shareable::<EventBus<Tick>>();
    assert_shareable::<SubscriberId>();
    assert_shareable::<SubscriberReport>();

    // And it works from another thread, which is the property the assertion is a proxy for.
    let bus = Arc::new(bus());
    let id = bus.subscribe();
    let emitted = Arc::clone(&bus);
    let handle = std::thread::spawn(move || emitted.emit(Tick(42)));
    let seq = handle.join().expect("the thread finished");
    assert_eq!(seq, 1);
    assert_eq!(bus.take(id).expect("id").events(), &[Tick(42)]);
}

#[test]
fn a_subscriber_identity_is_readable_in_a_report() {
    // A diagnostic bundle names the subscriber it is complaining about, and an opaque tuple would give it a number
    // with no way to refer to it.
    let bus = bus();
    let id = bus.subscribe();
    assert_eq!(id.to_string(), format!("sub{}", id.get()));
    assert!(id.get() >= 1);
}
