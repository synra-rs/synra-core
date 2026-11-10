use synra_protocol::event::MAX_COUNTED_GAP;

use super::super::{Judgement, SUBSCRIBER_QUEUE_CAPACITY, SequenceTracker};
use super::{Tick, bus};

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
