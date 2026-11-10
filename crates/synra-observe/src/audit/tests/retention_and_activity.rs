use super::*;

#[test]
fn a_stale_sweep_selects_only_old_records() {
    let retention = Retention { days: 1 };
    let day_ms = 24 * 60 * 60 * 1_000;
    let chat = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(16);

    // One record two days old and one from an hour ago, with "now" at day two.
    let now = day_ms * 2;
    ring.record(entry(0, &chat, "device:list", AuditOutcome::Allowed));
    ring.record(entry(now - 3_600_000, &chat, "device:list", AuditOutcome::Allowed));

    let cutoff = retention.cutoff_ms(now);
    assert_eq!(cutoff, day_ms, "one day back from day two");

    let stale = ring.older_than(cutoff);
    assert_eq!(stale.len(), 1, "only the two-day-old record is stale");
    assert_eq!(stale[0].at_ms, 0);
    assert!(retention.is_stale(&stale[0], now));

    // And the recent one is not selected.
    let recent = ring.all();
    assert!(
        !retention.is_stale(&recent[1], now),
        "a record from an hour ago is inside a one-day window"
    );
}

#[test]
fn the_default_retention_matches_the_documented_window() {
    assert_eq!(Retention::default().days, DEFAULT_RETENTION_DAYS);
    assert_eq!(Retention::default().validate(), Ok(()));
}

#[test]
fn a_zero_retention_is_refused() {
    // It would delete every record as it was written, leaving the user with an audit page that never
    // shows anything and no way to tell that from "nothing happened".
    assert!(Retention { days: 0 }.validate().is_err());
}

#[test]
fn the_cutoff_moves_with_the_clock() {
    let retention = Retention { days: 1 };
    let day_ms = 24 * 60 * 60 * 1_000;
    assert_eq!(retention.cutoff_ms(day_ms * 10), day_ms * 9);
    // And a clock at zero does not underflow into a huge positive window.
    assert!(retention.cutoff_ms(0) <= 0);
}

#[test]
fn a_plugin_activity_summary_reports_newest_first() {
    let chat = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(16);
    for index in 0..5i64 {
        ring.record(entry(index * 1_000, &chat, "device:list", AuditOutcome::Allowed));
    }
    ring.record(entry(9_000, &chat, "network:fetch:evil.com", AuditOutcome::Denied));

    let activity = PluginActivity::of(&ring, &chat, 3);
    assert_eq!(activity.total, 6);
    assert_eq!(activity.recent.len(), 3);
    assert_eq!(activity.recent[0].at_ms, 9_000, "newest first");
    assert_eq!(activity.refusals.len(), 1);
    assert!(activity.summarise().contains("6 capabilities used"));
    assert!(activity.summarise().contains("1 refused"));
}

#[test]
fn an_activity_summary_for_an_idle_plugin_says_so() {
    let ring = AuditRing::with_capacity(4);
    let activity = PluginActivity::of(&ring, &plugin("@synra-plugin/chat"), 10);

    assert!(activity.is_empty());
    assert!(activity.recent.is_empty());
    assert_eq!(activity.summarise(), "has not used any capabilities");
}

#[test]
fn an_activity_summary_with_no_refusals_says_so() {
    let chat = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(4);
    ring.record(entry(1_000, &chat, "device:list", AuditOutcome::Allowed));

    let activity = PluginActivity::of(&ring, &chat, 10);
    assert!(activity.summarise().contains("none refused"));
}

#[test]
fn an_activity_summary_respects_its_limit() {
    let chat = plugin("@synra-plugin/chat");
    let mut ring = AuditRing::with_capacity(32);
    for index in 0..20i64 {
        ring.record(entry(index, &chat, "device:list", AuditOutcome::Allowed));
    }

    let activity = PluginActivity::of(&ring, &chat, 5);
    assert_eq!(activity.recent.len(), 5);
    assert_eq!(activity.total, 20, "the total is not limited");
}
