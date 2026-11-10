use std::collections::HashMap;

use proptest::prelude::*;

use super::{CrashReport, SAFE_MODE_THRESHOLD, StartupVerdict, startup_verdict};

fn arbitrary_report() -> impl Strategy<Value = CrashReport> {
    (
        0i64..1_000_000,
        proptest::option::of("[a-z]{1,8}\\.rs:[0-9]{1,4}:[0-9]{1,3}"),
        proptest::option::of("[a-zA-Z ]{1,30}"),
    )
        .prop_map(|(at_ms, location, message)| {
            CrashReport::new(at_ms, "1.0.0", location, message, None, None, None)
        })
}

proptest! {
    /// Safe mode is entered exactly when one location has crashed at least the threshold number of
    /// times, counting only recent crashes. Getting this wrong in either direction is bad in a
    /// different way: too eager disables plugins for unrelated bugs, too lax leaves a user unable to
    /// reach the settings screen.
    #[test]
    fn safe_mode_depends_only_on_repeated_recent_locations(
        reports in proptest::collection::vec(arbitrary_report(), 0..12),
        now in 1_000_000i64..2_000_000,
    ) {
        let verdict = startup_verdict(&reports, now);

        let recent: Vec<&CrashReport> = reports.iter().filter(|r| r.is_recent(now)).collect();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for report in &recent {
            if let Some(location) = report.location_key() {
                *counts.entry(location).or_insert(0) += 1;
            }
        }
        let worst = counts.values().copied().max().unwrap_or(0);

        match verdict {
            StartupVerdict::Clean => {
                prop_assert!(recent.is_empty());
            }
            StartupVerdict::Crashed { recent_count, .. } => {
                prop_assert!(!recent.is_empty());
                prop_assert_eq!(recent_count, recent.len());
                prop_assert!(worst < SAFE_MODE_THRESHOLD);
            }
            StartupVerdict::SafeMode { count, .. } => {
                prop_assert!(count >= SAFE_MODE_THRESHOLD);
                prop_assert!(worst >= SAFE_MODE_THRESHOLD);
            }
        }
    }

    /// Recency is monotonic in the timestamp: if a crash is recent, a later one is too. A window that
    /// behaved otherwise would offer a prompt for something older than something it ignored.
    #[test]
    fn recency_is_monotonic(
        base in 0i64..1_000_000,
        offset_a in 0i64..500_000,
        offset_b in 0i64..500_000,
    ) {
        let now = 2_000_000;
        let (earlier, later) = if offset_a <= offset_b {
            (base + offset_a, base + offset_b)
        }
        else {
            (base + offset_b, base + offset_a)
        };

        let earlier_report = CrashReport::new(earlier, "1", Some("a".into()), None, None, None, None);
        let later_report = CrashReport::new(later, "1", Some("a".into()), None, None, None, None);
        if earlier_report.is_recent(now) {
            prop_assert!(later_report.is_recent(now));
        }
    }

    /// A report survives a trip through the wire format with every field intact. The report is written by
    /// a dying process and read by the next start, so anything lost in between is lost for good.
    #[test]
    fn reports_round_trip(report in arbitrary_report()) {
        let json = serde_json::to_string(&report).expect("serialises");
        let back: CrashReport = serde_json::from_str(&json).expect("deserialises");
        prop_assert_eq!(back, report);
    }
}
