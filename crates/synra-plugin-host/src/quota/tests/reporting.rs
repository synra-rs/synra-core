use core::time::Duration;

use super::super::{Health, Quota, QuotaReport, RateKind, RateLimited};
use super::{budget, refusal_budget, refusal_quota};

#[test]
fn the_report_carries_what_the_settings_screen_needs() {
    let budget = refusal_budget();
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    assert!(budget.consume(RateKind::HostCalls, 1, 0).is_err());

    let report = budget.report();
    assert_eq!(report.health, "good");
    assert_eq!(report.admitted, 1);
    assert_eq!(report.refused, 1);
    assert!(!report.explanation.is_empty());
    assert_eq!(
        report
            .refusals_by_kind
            .iter()
            .find(|(kind, _)| kind == "host-calls")
            .map(|(_, count)| *count),
        Some(1)
    );
    assert_eq!(report.quota, refusal_quota());
}

#[test]
fn every_health_level_explains_itself_for_a_user() {
    // A user whose plugin has been degraded needs to know why it got slower.
    for health in [Health::Good, Health::Overreaching, Health::Degraded, Health::Faulted] {
        assert!(health.explain().len() > 15, "{health:?}");
        assert!(!health.as_str().is_empty(), "{health:?}");
    }
}

#[test]
fn the_ladder_is_ordered_from_best_to_worst() {
    // The ordering is what a caller uses to show a trend, and an out-of-order ladder would make a plugin look
    // like it was improving while it got worse.
    assert!(Health::Good < Health::Overreaching);
    assert!(Health::Overreaching < Health::Degraded);
    assert!(Health::Degraded < Health::Faulted);
    // And only the last one stops the plugin.
    assert!(Health::Good.is_running());
    assert!(Health::Overreaching.is_running());
    assert!(Health::Degraded.is_running());
    assert!(!Health::Faulted.is_running());
}

#[test]
fn only_ordinary_health_is_not_worth_mentioning() {
    assert!(!Health::Good.is_worth_telling_the_user());
    assert!(Health::Overreaching.is_worth_telling_the_user());
    assert!(Health::Degraded.is_worth_telling_the_user());
    assert!(Health::Faulted.is_worth_telling_the_user());
}

#[test]
fn a_report_survives_a_round_trip() {
    let budget = budget();
    let report = budget.report();
    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("refusalsByKind"), "{json}");
    let back: QuotaReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}

#[test]
fn a_quota_survives_a_round_trip() {
    // The quota reaches the interface, so its field names are part of what a user setting a custom quota sees.
    let quota = Quota::default();
    let json = serde_json::to_string(&quota).expect("serialises");
    assert!(json.contains("maxMemoryBytes"), "{json}");
    assert!(json.contains("callTimeoutMs"), "{json}");
    let back: Quota = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, quota);
}

#[test]
fn a_limited_refusal_reports_its_wait() {
    let refusal = RateLimited { kind: Some(RateKind::Events), retry_after_ms: 250, shortfall: 1_000 };
    assert_eq!(refusal.retry_after(), Duration::from_millis(250));
    assert!(refusal.to_string().contains("250"));
}
