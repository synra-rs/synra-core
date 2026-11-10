use super::super::{CrashReport, SAFE_MODE_THRESHOLD, StartupVerdict, startup_verdict};
use super::report;

#[test]
fn no_reports_means_a_clean_start() {
    assert_eq!(startup_verdict(&[], 1_000), StartupVerdict::Clean);
    assert!(!StartupVerdict::Clean.needs_attention());
    assert!(StartupVerdict::Clean.allows_plugins());
    assert_eq!(StartupVerdict::Clean.explain(), "no recent crash");
}

#[test]
fn an_old_report_does_not_trigger_the_prompt() {
    // A prompt about something the user already dealt with is noise, and noise is what trains people to
    // dismiss prompts without reading them.
    let now = 1_700_000_000_000;
    let old = report(now - 86_400_000, Some("a.rs:1:1"));
    assert_eq!(startup_verdict(&[old], now), StartupVerdict::Clean);
}

#[test]
fn one_recent_crash_is_reported_without_safe_mode() {
    let now = 1_700_000_000_000;
    let verdict = startup_verdict(&[report(now - 1_000, Some("a.rs:1:1"))], now);

    // Matched by reference, so the verdict can still be asked about after its contents are inspected.
    match &verdict {
        StartupVerdict::Crashed { latest, recent_count } => {
            assert_eq!(*recent_count, 1);
            assert_eq!(latest.location_key(), Some("a.rs:1:1"));
        }
        other => panic!("expected a crash prompt, got {other:?}"),
    }
    assert!(verdict.allows_plugins(), "one crash is not a reason to disable plugins");
    assert!(verdict.needs_attention());
}

#[test]
fn the_same_place_crashing_three_times_enters_safe_mode() {
    // The scenario the whole mechanism exists for: a plugin that crashes on activation makes the
    // settings screen unreachable, and this is the only way back to it.
    let now = 1_700_000_000_000;
    let reports: Vec<CrashReport> = (0..SAFE_MODE_THRESHOLD)
        .map(|index| report(now - 1_000 - index as i64, Some("plugin.rs:99:1")))
        .collect();

    let verdict = startup_verdict(&reports, now);
    match &verdict {
        StartupVerdict::SafeMode { location, count, .. } => {
            assert_eq!(location, "plugin.rs:99:1");
            assert_eq!(*count, SAFE_MODE_THRESHOLD);
        }
        other => panic!("expected safe mode, got {other:?}"),
    }
    assert!(!verdict.allows_plugins(), "safe mode exists to start without plugins");
    assert!(verdict.explain().contains("without plugins"));
}

#[test]
fn unrelated_crashes_do_not_add_up_to_safe_mode() {
    // Three bugs in three places are three bugs. Counting them together would disable plugins for a user
    // who has no plugin problem at all.
    let now = 1_700_000_000_000;
    let reports = vec![
        report(now - 1_000, Some("a.rs:1:1")),
        report(now - 900, Some("b.rs:2:2")),
        report(now - 800, Some("c.rs:3:3")),
    ];

    match startup_verdict(&reports, now) {
        StartupVerdict::Crashed { recent_count, .. } => assert_eq!(recent_count, 3),
        other => panic!("expected a plain crash prompt, got {other:?}"),
    }
}

#[test]
fn a_report_without_a_location_cannot_contribute_to_safe_mode() {
    // An unknown location is not evidence that the same bug happened again, and treating it as such
    // would disable plugins on the strength of an unrelated series.
    let now = 1_700_000_000_000;
    let reports: Vec<CrashReport> = (0..5).map(|i| report(now - i as i64, None)).collect();

    match startup_verdict(&reports, now) {
        StartupVerdict::Crashed { recent_count, .. } => assert_eq!(recent_count, 5),
        other => panic!("expected a plain crash prompt, got {other:?}"),
    }
}

#[test]
fn only_recent_crashes_are_counted_toward_safe_mode() {
    // Two from yesterday plus one today is not three in a row: the plugin may have been fixed since.
    let now = 1_700_000_000_000;
    let reports = vec![
        report(now - 86_400_000, Some("plugin.rs:99:1")),
        report(now - 86_300_000, Some("plugin.rs:99:1")),
        report(now - 1_000, Some("plugin.rs:99:1")),
    ];

    match startup_verdict(&reports, now) {
        StartupVerdict::Crashed { recent_count, .. } => assert_eq!(recent_count, 1),
        other => panic!("expected a plain crash prompt, got {other:?}"),
    }
}

#[test]
fn the_latest_report_is_the_one_shown() {
    let now = 1_700_000_000_000;
    let reports = vec![
        report(now - 5_000, Some("old.rs:1:1")),
        report(now - 1_000, Some("new.rs:9:9")),
        report(now - 3_000, Some("middle.rs:5:5")),
    ];

    match startup_verdict(&reports, now) {
        StartupVerdict::Crashed { latest, .. } => {
            assert_eq!(latest.location_key(), Some("new.rs:9:9"));
        }
        other => panic!("expected a crash prompt, got {other:?}"),
    }
}

#[test]
fn the_location_that_crashed_most_decides_safe_mode() {
    // With two locations both over the threshold, the one that crashed more is the one named, because it
    // is the one to disable first.
    let now = 1_700_000_000_000;
    let reports = vec![
        report(now - 100, Some("a.rs:1:1")),
        report(now - 200, Some("a.rs:1:1")),
        report(now - 300, Some("a.rs:1:1")),
        report(now - 400, Some("b.rs:2:2")),
        report(now - 500, Some("b.rs:2:2")),
        report(now - 600, Some("b.rs:2:2")),
        report(now - 700, Some("b.rs:2:2")),
    ];

    match startup_verdict(&reports, now) {
        StartupVerdict::SafeMode { location, count, .. } => {
            assert_eq!(location, "b.rs:2:2");
            assert_eq!(count, 4);
        }
        other => panic!("expected safe mode, got {other:?}"),
    }
}

#[test]
fn a_verdict_explains_itself_for_every_case() {
    let now = 1_700_000_000_000;
    let crashed = startup_verdict(&[report(now - 1, Some("a.rs:1:1"))], now);
    assert!(crashed.explain().contains("1 time"));

    let reports: Vec<CrashReport> = (0..3).map(|i| report(now - i as i64, Some("a.rs:1:1"))).collect();
    let safe = startup_verdict(&reports, now);
    assert!(safe.explain().contains("a.rs:1:1"));
    assert!(safe.explain().contains('3'));
}
