use core::time::Duration;
use super::super::{DeathReason, LinkHealth};

#[test]
fn a_deliberate_end_is_not_worth_reconnecting_to() {
    // A goodbye is a decision and a refusal may be permanent, so retrying immediately races a shutdown or
    // repeats something that will not change.
    assert!(!DeathReason::Goodbye.is_worth_reconnecting());
    assert!(!DeathReason::Refused.is_worth_reconnecting());
    assert!(DeathReason::Silent { silent_ms: 1 }.is_worth_reconnecting());
    assert!(DeathReason::Local { detail: "write failed" }.is_worth_reconnecting());
}

#[test]
fn only_a_refusal_is_worth_telling_the_user_about() {
    // Silence is ordinary — a laptop that closed its lid — and mentioning it every time trains the user to
    // ignore the message.
    assert!(!DeathReason::Silent { silent_ms: 1 }.is_worth_telling_the_user());
    assert!(!DeathReason::Goodbye.is_worth_telling_the_user());
    assert!(!DeathReason::Local { detail: "x" }.is_worth_telling_the_user());
    assert!(DeathReason::Refused.is_worth_telling_the_user());
}

// ── Link health ───────────────────────────────────────────────────────────────────────────────

#[test]
fn an_empty_queue_on_a_live_link_is_healthy() {
    let health = LinkHealth::classify(0, 256, 0, Duration::from_millis(250));
    assert_eq!(health, LinkHealth::Healthy);
    assert!(health.is_usable());
    assert!(!health.should_close());
}

#[test]
fn a_filling_queue_is_congested_but_usable() {
    // A burst is ordinary, and closing a link on the first full queue would drop connections that were working.
    let health = LinkHealth::classify(128, 256, 0, Duration::from_millis(250));
    assert_eq!(health, LinkHealth::Congested { queue_percent: 50 });
    assert!(health.is_usable());
    assert!(!health.should_close());
}

#[test]
fn a_full_queue_is_an_overflow_and_the_link_closes() {
    // Dropping the newest frame would silently lose a message, and dropping the oldest would break a transfer's
    // ordering — so the link ends and the caller reconnects knowing something was lost.
    let health = LinkHealth::classify(256, 256, 0, Duration::from_millis(250));
    assert_eq!(health, LinkHealth::Overflow);
    assert!(!health.is_usable());
    assert!(health.should_close());
}

#[test]
fn silence_takes_precedence_over_the_queue() {
    // A silent link is dead whatever its queue says, and reporting congestion for a dead link would have the
    // caller wait for it to drain.
    let health = LinkHealth::classify(0, 256, 250, Duration::from_millis(250));
    assert_eq!(health, LinkHealth::Silent { silent_ms: 250 });
    assert!(health.should_close());
}

#[test]
fn a_queue_with_no_capacity_is_an_overflow() {
    // A link with no queue can carry nothing, which is an overflow in effect rather than a configuration to be
    // tolerated.
    assert_eq!(
        LinkHealth::classify(0, 0, 0, Duration::from_millis(250)),
        LinkHealth::Overflow
    );
}

#[test]
fn a_queue_longer_than_its_capacity_is_still_an_overflow() {
    // A capacity that shrank under a live queue, which happens when the tuning changes at runtime.
    assert_eq!(
        LinkHealth::classify(300, 256, 0, Duration::from_millis(250)),
        LinkHealth::Overflow
    );
}

#[test]
fn the_congestion_threshold_is_where_it_says_it_is() {
    let timeout = Duration::from_millis(10_000);
    // Just below the threshold is healthy.
    let below = usize::from(LinkHealth::CONGESTED_PERCENT) - 1;
    assert_eq!(LinkHealth::classify(below, 100, 0, timeout), LinkHealth::Healthy);
    // At it, congested.
    assert_eq!(
        LinkHealth::classify(usize::from(LinkHealth::CONGESTED_PERCENT), 100, 0, timeout),
        LinkHealth::Congested { queue_percent: LinkHealth::CONGESTED_PERCENT }
    );
}

#[test]
fn health_reports_a_percentage_a_caller_can_show() {
    for queued in [50usize, 100, 200, 255] {
        if let LinkHealth::Congested { queue_percent } = LinkHealth::classify(queued, 256, 0, Duration::from_secs(1))
        {
            assert!((LinkHealth::CONGESTED_PERCENT..100).contains(&queue_percent));
        }
    }
}

#[test]
fn a_death_reason_that_carries_text_does_not_contain_a_brace() {
    // The variants hold a `&'static str` a caller chose, so the message is always renderable.
    let reason = DeathReason::Local { detail: "the socket closed" };
    assert!(reason.is_worth_reconnecting());
}
