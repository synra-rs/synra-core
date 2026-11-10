use core::time::Duration;
use synra_protocol::limits::{HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT};
use super::super::{DeathReason, HeartbeatAction, Liveness};
use super::tracker;

#[test]
fn a_fresh_link_is_idle_until_its_first_interval() {
    // A link that just came up has just carried a handshake, so pinging immediately would be asking a question
    // that was just answered.
    let liveness = tracker(0);
    assert_eq!(liveness.poll(0), HeartbeatAction::Idle);
    assert_eq!(liveness.poll(50), HeartbeatAction::Idle);
    assert_eq!(liveness.poll(99), HeartbeatAction::Idle);
    assert_eq!(liveness.poll(100), HeartbeatAction::SendPing);
}

#[test]
fn pings_are_spaced_by_the_interval() {
    let mut liveness = tracker(0);
    assert_eq!(liveness.poll(100), HeartbeatAction::SendPing);
    liveness.record_ping(100);

    // A frame arrives and resets the silence clock. Without it the link would be within the timeout of death at
    // 299, which is the separate property the next test covers.
    liveness.record_inbound(150);
    assert_eq!(liveness.poll(150), HeartbeatAction::Idle);
    assert_eq!(liveness.poll(200), HeartbeatAction::SendPing);
    liveness.record_ping(200);
    liveness.record_inbound(250);
    assert_eq!(liveness.poll(299), HeartbeatAction::Idle);
    assert_eq!(liveness.poll(300), HeartbeatAction::SendPing);
    liveness.record_ping(300);

    // A pong does not change the *ping* schedule: the next ping is still an interval after the last one, so a
    // peer that answers promptly is not pinged more often for it.
    liveness.record_inbound(310);
    assert_eq!(liveness.poll(350), HeartbeatAction::Idle);
    assert_eq!(liveness.poll(400), HeartbeatAction::SendPing);
}

#[test]
fn a_clock_that_moves_backwards_does_not_pull_the_deadline_back() {
    // The caller's clock is monotonic, so a reading that moved backwards is a defect. Accepting it would make a
    // link that just received a frame more likely to be declared dead than one that did not.
    let mut liveness = tracker(0);
    liveness.record_inbound(500);
    assert_eq!(liveness.dead_at_ms(), 750);

    liveness.record_inbound(100);
    assert_eq!(liveness.dead_at_ms(), 750, "the deadline moved backwards");
    assert_eq!(liveness.last_inbound_ms(), 500);
}

#[test]
fn silence_past_the_timeout_declares_the_link_dead() {
    // A cable unplugged at the far end does not close the socket, so nothing else would notice.
    let liveness = tracker(0);
    assert_eq!(
        liveness.poll(250),
        HeartbeatAction::DeclareDead(DeathReason::Silent { silent_ms: 250 })
    );
    assert_eq!(
        liveness.poll(1_000),
        HeartbeatAction::DeclareDead(DeathReason::Silent { silent_ms: 1_000 })
    );
}

#[test]
fn any_inbound_frame_counts_as_life() {
    // Counting only pongs would declare a busy link dead whenever a large transfer delayed the reply behind
    // hundreds of data frames.
    let mut liveness = tracker(0);
    for at in [50u64, 100, 150, 200, 249] {
        liveness.record_inbound(at);
        // Still idle or pinging, never dead, because something arrived each time.
        assert!(
            !matches!(liveness.poll(at + 1), HeartbeatAction::DeclareDead(_)),
            "declared dead at {at} despite an inbound frame"
        );
    }
    // And the deadline moved with the last frame.
    assert_eq!(liveness.dead_at_ms(), 249 + 250);
}

#[test]
fn a_pong_and_an_ordinary_frame_have_the_same_effect() {
    let mut with_pong = tracker(0);
    let mut with_data = tracker(0);
    with_pong.record_pong(120);
    with_data.record_inbound(120);

    assert_eq!(with_pong.last_inbound_ms(), with_data.last_inbound_ms());
    assert_eq!(with_pong.dead_at_ms(), with_data.dead_at_ms());
    assert_eq!(with_pong.poll(200), with_data.poll(200));
}

#[test]
fn a_goodbye_is_reported_rather_than_the_silence() {
    // The peer is gone deliberately, so pretending otherwise would keep pinging something that is not listening.
    let mut liveness = tracker(0);
    liveness.record_goodbye();
    assert_eq!(liveness.poll(0), HeartbeatAction::DeclareDead(DeathReason::Goodbye));
    // And it takes precedence even before the timeout would have fired.
    assert_eq!(liveness.poll(10), HeartbeatAction::DeclareDead(DeathReason::Goodbye));
}

#[test]
fn a_refusal_is_reported_rather_than_the_silence() {
    let mut liveness = tracker(0);
    liveness.record_refusal();
    assert_eq!(liveness.poll(0), HeartbeatAction::DeclareDead(DeathReason::Refused));
}

#[test]
fn unanswered_pings_are_counted_and_reset_by_any_traffic() {
    // Diagnostic rather than decisive — the timeout is what declares death — but a link that needed three pings
    // before dying is worth seeing in a report.
    let mut liveness = tracker(0);
    assert_eq!(liveness.unanswered_pings(), 0);
    liveness.record_ping(100);
    liveness.record_ping(200);
    assert_eq!(liveness.unanswered_pings(), 2);

    liveness.record_inbound(210);
    assert_eq!(liveness.unanswered_pings(), 0);
}

#[test]
fn the_timeout_is_longer_than_the_interval() {
    // Equal values would declare a link dead on a single lost packet: the ping is sent, the pong is dropped, and
    // a working connection is torn down. The ratio is what tolerates the packet loss ordinary networks have.
    assert!(HEARTBEAT_TIMEOUT > HEARTBEAT_INTERVAL);
    let ratio = HEARTBEAT_TIMEOUT.as_millis() as f64 / HEARTBEAT_INTERVAL.as_millis() as f64;
    assert!(ratio >= 2.0, "the timeout is only {ratio}x the interval");

    // And the same holds for a tracker with overridden timing, because the caller set them.
    let liveness = tracker(0);
    assert!(liveness.timeout() > liveness.interval());
}

#[test]
fn the_remaining_time_counts_down_to_the_deadline() {
    let mut liveness = tracker(0);
    assert_eq!(liveness.remaining_ms(0), 250);
    assert_eq!(liveness.remaining_ms(100), 150);
    assert_eq!(liveness.remaining_ms(250), 0);
    // Past the deadline it is zero rather than negative, so a caller showing it does not show a negative wait.
    assert_eq!(liveness.remaining_ms(10_000), 0);

    liveness.record_inbound(100);
    assert_eq!(liveness.remaining_ms(100), 250);
}

#[test]
fn a_zero_interval_pings_every_poll_without_declaring_death() {
    // A configuration that disables the interval must not turn every poll into a death.
    let liveness = Liveness::new(0).with_timing(Duration::ZERO, Duration::from_millis(250));
    assert_eq!(liveness.poll(0), HeartbeatAction::SendPing);
    assert!(!matches!(liveness.poll(100), HeartbeatAction::DeclareDead(_)));
}

#[test]
fn a_zero_timeout_declares_death_immediately() {
    // The configuration is unusable, and the failure is visible rather than silent: pretending the link is alive
    // would be worse.
    let liveness = Liveness::new(0).with_timing(Duration::from_millis(100), Duration::ZERO);
    assert_eq!(
        liveness.poll(0),
        HeartbeatAction::DeclareDead(DeathReason::Silent { silent_ms: 0 })
    );
}

// ── Death reasons ─────────────────────────────────────────────────────────────────────────────
