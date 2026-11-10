use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use super::{EventVerdict, SequenceTracker};

proptest! {
    // Keep using the saved regression seeds from before the suite moved.
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/event.txt"
        )))),
        ..ProptestConfig::default()
    })]

    /// Whatever sequence of numbers is observed, the last one recorded is never less than any applied one, and
    /// a repeat is never applied. The property is what stops a duplicated event from being applied twice, which
    /// is how a list gets a row it renders once and fetches twice.
    #[test]
    fn a_repeat_is_never_applied(sequences in proptest::collection::vec(0u64..50, 0..200)) {
        let mut tracker = SequenceTracker::new();
        let mut last_applied: Option<u64> = None;

        for seq in sequences {
            let verdict = tracker.observe(seq);
            match verdict {
                EventVerdict::Apply | EventVerdict::ApplyAndRefresh => {
                    if let Some(previous) = last_applied {
                        prop_assert!(seq > previous, "applied {} after {}", seq, previous);
                    }
                    last_applied = Some(seq);
                }
                EventVerdict::IgnoreRepeat => {
                    if let Some(previous) = last_applied {
                        prop_assert!(seq <= previous, "called {} a repeat after {}", seq, previous);
                    }
                }
                EventVerdict::RefreshSnapshot { .. } => {
                    if let Some(previous) = last_applied {
                        prop_assert!(seq > previous + 1, "called {} a gap after {}", seq, previous);
                    }
                    last_applied = Some(seq);
                }
            }
        }
    }

    /// The tracker never records a sequence lower than one it has already recorded. A tracker that went
    /// backwards would then treat every subsequent event as a repeat and the interface would stop updating.
    #[test]
    fn the_recorded_sequence_never_decreases(sequences in proptest::collection::vec(any::<u64>(), 0..100)) {
        let mut tracker = SequenceTracker::new();
        let mut previous = 0u64;
        for seq in sequences {
            let _ = tracker.observe(seq);
            if let Some(last) = tracker.last() {
                prop_assert!(last >= previous, "went from {} to {}", previous, last);
                previous = last;
            }
        }
    }

    /// A gap is reported once, and the next contiguous event after it applies. A tracker that kept reporting
    /// the same gap would ask for a snapshot per event for as long as the gap lasted.
    #[test]
    fn a_gap_is_not_reported_twice_for_the_same_jump(
        first in 1u64..100,
        jump in 1u64..1_000,
    ) {
        let mut tracker = SequenceTracker::new();
        prop_assert_eq!(tracker.observe(first), EventVerdict::Apply);

        let second = first.saturating_add(jump);
        // Bound first: a `matches!` with a `{ .. }` pattern cannot be a `prop_assert!` message, because proptest
        // builds the message with `format!` and the braces are read as a format argument.
        let verdict = tracker.observe(second);

        if jump == 1 {
            // Contiguous, so it applies and there is no gap to report twice.
            prop_assert_eq!(verdict, EventVerdict::Apply);
        }
        else {
            prop_assert!(matches!(verdict, EventVerdict::RefreshSnapshot { .. }), "{:?}", verdict);
            // The event after the gap is contiguous *with the gap*, so it applies rather than re-reporting.
            if let Some(next) = second.checked_add(1) {
                let after = tracker.observe(next);
                prop_assert_eq!(after, EventVerdict::Apply, "the gap was re-reported");
            }
        }
    }

    /// Observing is total, whatever the numbers. The sequence comes from another process, and an interface that
    /// panicked on a strange value would be one a kernel could stop with a single event.
    #[test]
    fn observing_is_total(sequences in proptest::collection::vec(any::<u64>(), 0..200)) {
        let mut tracker = SequenceTracker::new();
        for seq in sequences {
            let _ = tracker.observe(seq);
        }
        let _ = tracker.report();
        let _ = tracker.is_stale();
    }
}
