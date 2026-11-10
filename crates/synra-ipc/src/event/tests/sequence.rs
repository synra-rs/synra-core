use super::super::{EventVerdict, KernelEvent, KernelEventEnvelope, SequenceReport, SequenceTracker};

#[test]
fn the_first_event_is_applied_rather_than_called_a_gap() {
    // The kernel's counter starts at one, so an interface that started mid-stream would otherwise report a gap
    // immediately and re-read the snapshot it had just taken.
    let mut tracker = SequenceTracker::new();
    assert_eq!(tracker.observe(1), EventVerdict::Apply);
    assert_eq!(tracker.last(), Some(1));
    assert_eq!(tracker.gaps(), 0);
}

#[test]
fn a_contiguous_event_is_applied() {
    let mut tracker = SequenceTracker::new();
    tracker.observe(7);
    assert_eq!(tracker.observe(8), EventVerdict::Apply);
    assert_eq!(tracker.observe(9), EventVerdict::Apply);
    assert_eq!(tracker.last(), Some(9));
    assert_eq!(tracker.gaps(), 0);
}

#[test]
fn a_gap_asks_for_a_snapshot_and_counts_what_was_missed() {
    // The gap cannot be repaired from the events themselves — the missing ones are gone — so the only correct
    // response is to re-read.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    match tracker.observe(4) {
        EventVerdict::RefreshSnapshot { missed } => assert_eq!(missed, Some(2)),
        other => panic!("expected a snapshot request, got {other:?}"),
    }
    assert_eq!(tracker.gaps(), 1);
}

#[test]
fn a_huge_gap_is_reported_without_a_count() {
    // A jump of thousands gives a number nobody reads, and the subtraction on a hostile value is one that could
    // overflow.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    match tracker.observe(u64::MAX) {
        EventVerdict::RefreshSnapshot { missed } => assert_eq!(missed, None),
        other => panic!("expected a snapshot request, got {other:?}"),
    }
}

#[test]
fn a_repeat_is_ignored() {
    // The channel can deliver the same event twice across a reload, and a `DeviceCardUpdated` applied twice is a
    // device fetched twice.
    let mut tracker = SequenceTracker::new();
    tracker.observe(5);
    assert_eq!(tracker.observe(5), EventVerdict::IgnoreRepeat);
    assert_eq!(tracker.observe(4), EventVerdict::IgnoreRepeat);
    assert_eq!(tracker.observe(1), EventVerdict::IgnoreRepeat);
}

#[test]
fn a_repeat_does_not_advance_the_sequence() {
    // Advancing on a repeat would make the next contiguous event look like a gap, which is a re-read triggered
    // by nothing.
    let mut tracker = SequenceTracker::new();
    tracker.observe(5);
    assert_eq!(tracker.observe(5), EventVerdict::IgnoreRepeat);
    assert_eq!(tracker.last(), Some(5));
    assert_eq!(tracker.observe(6), EventVerdict::Apply);
}

#[test]
fn a_gap_is_counted_once_rather_than_per_event() {
    // The interface is about to re-read, so treating the same gap as new until a snapshot arrives would ask for
    // one per event for as long as the gap lasted.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    tracker.observe(10);
    assert_eq!(tracker.gaps(), 1);

    // The events after the gap are contiguous with it, so they apply.
    assert_eq!(tracker.observe(11), EventVerdict::Apply);
    assert_eq!(tracker.gaps(), 1);
}

#[test]
fn resetting_forgets_the_sequence() {
    // The sequence is not persisted across a reload: the interface that comes back takes a snapshot, and a
    // remembered sequence would make the first event after the reload look like a gap.
    let mut tracker = SequenceTracker::new();
    tracker.observe(100);
    tracker.reset();
    assert_eq!(tracker.last(), None);
    assert_eq!(tracker.observe(1), EventVerdict::Apply);
}

#[test]
fn a_snapshot_makes_the_picture_trustworthy_again() {
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    tracker.observe(5);
    tracker.snapshot_taken();
    assert_eq!(tracker.report().gaps, 1);
    assert_eq!(tracker.report().last, Some(5));
}

#[test]
fn the_gap_count_saturates() {
    // A wrapping count would make an interface that had lost four billion events look like one that had lost
    // none.
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    for _ in 0..3 {
        tracker.observe(tracker.last().expect("seen") + 2);
    }
    assert_eq!(tracker.gaps(), 3);
    assert!(tracker.gaps() < u32::MAX);
}

#[test]
fn an_envelope_can_be_judged_by_its_sequence() {
    // The shape the interface actually uses: read the sequence, decide, then apply.
    let envelope = KernelEventEnvelope {
        seq: 9,
        at: 0,
        event: KernelEvent::LogLine {
            level: "info".to_owned(),
            line: "x".to_owned(),
        },
    };
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    assert!(matches!(
        tracker.observe(envelope.seq),
        EventVerdict::RefreshSnapshot { .. }
    ));
}

#[test]
fn a_report_carries_what_a_diagnostic_bundle_needs() {
    let mut tracker = SequenceTracker::new();
    tracker.observe(1);
    tracker.observe(3);
    let report = tracker.report();
    assert_eq!(report.last, Some(3));
    assert_eq!(report.gaps, 1);

    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("gaps"), "{json}");
    let back: SequenceReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}
