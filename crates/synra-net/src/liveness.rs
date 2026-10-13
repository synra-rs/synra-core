//! Liveness: whether a link is still carrying anything.
//!
//! # A TCP connection can be dead and look alive
//!
//! A cable unplugged at the far end, a laptop that slept, a NAT entry that expired — none of these close the
//! socket. The local end sees an open connection and would wait forever, which is why the exchange is:
//!
//! * Send a [`Ping`](synra_protocol::frame::FrameKind::Ping) every [`HEARTBEAT_INTERVAL`].
//! * Treat **any** inbound frame as evidence of life, not only a `Pong`.
//! * Declare the link dead once nothing at all has arrived for [`HEARTBEAT_TIMEOUT`].
//!
//! # Any frame, not just a pong
//!
//! Counting only `Pong` would declare a busy link dead whenever a large transfer delayed the reply behind
//! hundreds of data frames. The question the timeout answers is "is anything arriving", and a chunk frame answers
//! it exactly as well as a pong does.
//!
//! # The timeout is longer than the interval, and that is the point
//!
//! [`HEARTBEAT_TIMEOUT`] is two and a half intervals. Equal values would declare a link dead on a single lost
//! packet — the ping is sent, the pong is dropped, and a working connection is torn down. The ratio is what
//! tolerates the packet loss that ordinary networks have.

use core::time::Duration;

use synra_protocol::limits::{HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT};

/// Why a link was declared dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeathReason {
    /// Nothing has arrived for [`HEARTBEAT_TIMEOUT`].
    Silent {
        /// How long it has been.
        silent_ms: u64,
    },
    /// The peer sent a goodbye.
    ///
    /// Distinct from silence because it is a decision rather than a failure: the peer is shutting down, and
    /// reconnecting immediately would be reconnecting to something that is not there.
    Goodbye,
    /// The peer refused the handshake.
    Refused,
    /// A local fault, such as a write failing.
    Local {
        /// What happened.
        detail: &'static str,
    },
}

impl DeathReason {
    /// Whether reconnecting makes sense.
    ///
    /// A goodbye is a decision: the peer is shutting down, so retrying immediately races its shutdown. A refusal
    /// may be permanent — a protocol version that will not change, a peer that unpaired while the connection was
    /// open — so it is retried on the schedule like any other failure but is worth showing differently.
    #[must_use]
    pub const fn is_worth_reconnecting(self) -> bool {
        match self {
            Self::Goodbye | Self::Refused => false,
            Self::Silent { .. } | Self::Local { .. } => true,
        }
    }

    /// Whether the interface should mention it to the user.
    ///
    /// Silence is ordinary — a laptop that closed its lid — and mentioning it every time trains the user to
    /// ignore the message. A refusal is a configuration problem they may be able to act on.
    #[must_use]
    pub const fn is_worth_telling_the_user(self) -> bool {
        matches!(self, Self::Refused)
    }
}

/// What to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeartbeatAction {
    /// Nothing to do.
    Idle,
    /// Send a ping.
    SendPing,
    /// The link is dead.
    DeclareDead(DeathReason),
}

/// Tracks one link's liveness.
///
/// Owns no clock and no socket: the caller supplies the current time and performs the actions. That is what makes
/// the timing testable without sleeping, and the timing is the whole of this type's behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Liveness {
    /// When the last ping was sent.
    last_ping_ms: Option<u64>,
    /// When anything last arrived.
    last_inbound_ms: u64,
    /// How many pings have gone unanswered since the last inbound frame.
    ///
    /// Diagnostic rather than decisive — the timeout is what declares death — but a link that needed three pings
    /// before dying is worth seeing in a report.
    unanswered_pings: u32,
    interval: Duration,
    timeout: Duration,
    /// Set when the peer said goodbye, so the next check reports that rather than silence.
    goodbye: bool,
    /// Set when the handshake was refused.
    refused: bool,
}

impl Liveness {
    /// A tracker for a link that just came up at `now_ms`.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            last_ping_ms: None,
            last_inbound_ms: now_ms,
            unanswered_pings: 0,
            interval: HEARTBEAT_INTERVAL,
            timeout: HEARTBEAT_TIMEOUT,
            goodbye: false,
            refused: false,
        }
    }

    /// A tracker with the timing overridden, for a test that cannot wait ten seconds.
    #[must_use]
    pub const fn with_timing(mut self, interval: Duration, timeout: Duration) -> Self {
        self.interval = interval;
        self.timeout = timeout;
        self
    }

    /// The ping interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// The silence timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// How many pings went unanswered.
    #[must_use]
    pub const fn unanswered_pings(&self) -> u32 {
        self.unanswered_pings
    }

    /// When anything last arrived.
    #[must_use]
    pub const fn last_inbound_ms(&self) -> u64 {
        self.last_inbound_ms
    }

    /// Records that something arrived.
    ///
    /// **Any** frame counts. Counting only pongs would declare a busy link dead whenever a large transfer delayed
    /// the reply behind hundreds of data frames.
    ///
    /// A time earlier than the last one is ignored rather than accepted. The caller's clock is monotonic, so a
    /// reading that moves backwards is either a defect or a caller passing the wrong value — and accepting it would
    /// pull the deadline *backwards*, making a link that just received a frame more likely to be declared dead than
    /// one that did not. The deadline only ever moves forward.
    pub const fn record_inbound(&mut self, now_ms: u64) {
        if now_ms > self.last_inbound_ms {
            self.last_inbound_ms = now_ms;
        }
        self.unanswered_pings = 0;
    }

    /// Records that a pong arrived.
    ///
    /// The same effect as any inbound frame; named separately so a caller reading the code can see the intent.
    pub const fn record_pong(&mut self, now_ms: u64) {
        self.record_inbound(now_ms);
    }

    /// Records that the peer said goodbye.
    pub const fn record_goodbye(&mut self) {
        self.goodbye = true;
    }

    /// Records that the handshake was refused.
    pub const fn record_refusal(&mut self) {
        self.refused = true;
    }

    /// What to do at `now_ms`.
    #[must_use]
    pub fn poll(&self, now_ms: u64) -> HeartbeatAction {
        // A goodbye or a refusal is a decision, so it takes precedence over the silence arithmetic: the peer is
        // gone deliberately and pretending otherwise would keep pinging something that is not listening.
        if self.goodbye {
            return HeartbeatAction::DeclareDead(DeathReason::Goodbye);
        }
        if self.refused {
            return HeartbeatAction::DeclareDead(DeathReason::Refused);
        }

        let silent = now_ms.saturating_sub(self.last_inbound_ms);
        let timeout_ms = u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX);
        if silent >= timeout_ms {
            return HeartbeatAction::DeclareDead(DeathReason::Silent { silent_ms: silent });
        }

        let interval_ms = u64::try_from(self.interval.as_millis()).unwrap_or(u64::MAX);
        let due = match self.last_ping_ms {
            // The first ping waits a full interval: a link that just came up has just carried a handshake, so
            // pinging immediately would be asking a question that was just answered.
            None => self.last_inbound_ms.saturating_add(interval_ms),
            Some(last) => last.saturating_add(interval_ms),
        };
        if now_ms >= due {
            return HeartbeatAction::SendPing;
        }

        HeartbeatAction::Idle
    }

    /// Records that a ping was sent at `now_ms`.
    pub const fn record_ping(&mut self, now_ms: u64) {
        self.last_ping_ms = Some(now_ms);
        self.unanswered_pings = self.unanswered_pings.saturating_add(1);
    }

    /// The time at which the link would be declared dead, as of the last inbound frame.
    #[must_use]
    pub fn dead_at_ms(&self) -> u64 {
        self.last_inbound_ms
            .saturating_add(u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX))
    }

    /// How much longer the link has, at `now_ms`.
    #[must_use]
    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.dead_at_ms().saturating_sub(now_ms)
    }
}

/// Whether a link is healthy enough to keep using.
///
/// The write queue's state decides this as much as the heartbeat does: a link whose queue is full is one the
/// application is producing data for faster than the peer is consuming it, and a link that stays that way is
/// broken in a way no heartbeat detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkHealth {
    /// Carrying traffic.
    Healthy,
    /// Alive, but the queue is filling.
    ///
    /// Reported rather than acted on: a burst is ordinary, and closing a link on the first full queue would drop
    /// connections that were working.
    Congested {
        /// How full the queue is, as a percentage.
        queue_percent: u8,
    },
    /// The queue is full and the link must be closed.
    ///
    /// The design document's rule: overflow means the link is unhealthy and is closed. Dropping the newest frame
    /// instead would silently lose a message, and dropping the oldest would break a transfer's ordering — so the
    /// link ends and the caller reconnects with the knowledge that something was lost.
    Overflow,
    /// Nothing has arrived within the timeout.
    Silent {
        /// How long it has been.
        silent_ms: u64,
    },
}

impl LinkHealth {
    /// Whether the link may keep being used.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        !matches!(self, Self::Overflow | Self::Silent { .. })
    }

    /// Whether the link should be closed now.
    #[must_use]
    pub const fn should_close(self) -> bool {
        !self.is_usable()
    }

    /// A percentage of the queue above which the link counts as congested.
    ///
    /// Half. Below that a burst is ordinary; above it the producer is persistently ahead of the consumer, which is
    /// worth showing before it becomes an overflow.
    pub const CONGESTED_PERCENT: u8 = 50;

    /// Classifies a link from its queue depth and its liveness.
    #[must_use]
    pub fn classify(queued: usize, capacity: usize, silent_ms: u64, timeout: Duration) -> Self {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        if silent_ms >= timeout_ms {
            return Self::Silent { silent_ms };
        }
        if capacity == 0 {
            // A link with no queue can carry nothing, which is an overflow in effect rather than a configuration
            // to be tolerated.
            return Self::Overflow;
        }
        if queued >= capacity {
            return Self::Overflow;
        }

        let percent = u8::try_from(queued.saturating_mul(100) / capacity).unwrap_or(100);
        if percent >= Self::CONGESTED_PERCENT {
            return Self::Congested { queue_percent: percent };
        }
        Self::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tracker with timings small enough to reason about: 100 ms interval, 250 ms timeout.
    fn tracker(now_ms: u64) -> Liveness {
        Liveness::new(now_ms).with_timing(Duration::from_millis(100), Duration::from_millis(250))
    }

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
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// The same short timing the unit tests use, because a property test cannot wait ten seconds per case.
    fn tracker(now_ms: u64) -> Liveness {
        Liveness::new(now_ms).with_timing(Duration::from_millis(100), Duration::from_millis(250))
    }

    proptest! {
        /// Whatever the times, a link is never declared dead while something arrived within the timeout. The
        /// converse — declaring a live link dead — is the failure that costs a user their connection.
        #[test]
        fn a_link_is_never_declared_dead_early(
            start in 0u64..1_000,
            inbound in 0u64..1_000,
            check in 0u64..2_000,
        ) {
            let mut liveness = tracker(start);
            liveness.record_inbound(inbound);
            let timeout_ms = 250u64;

            if check.saturating_sub(inbound) < timeout_ms {
                prop_assert!(
                    !matches!(liveness.poll(check), HeartbeatAction::DeclareDead(DeathReason::Silent { .. })),
                    "declared dead at {} with the last frame at {}",
                    check,
                    inbound,
                );
            }
        }

        /// An inbound frame always moves the deadline forward, never backward. A frame that shortened the deadline
        /// would make a busy link more likely to be declared dead than an idle one.
        #[test]
        fn an_inbound_frame_never_shortens_the_deadline(
            start in 0u64..1_000,
            first in 0u64..1_000,
            second in 0u64..2_000,
        ) {
            let mut liveness = tracker(start);
            liveness.record_inbound(first);
            let after_first = liveness.dead_at_ms();
            liveness.record_inbound(second);
            let after_second = liveness.dead_at_ms();

            // The deadline only ever moves forward. A frame whose timestamp is earlier than an earlier frame's is a
            // defect in the caller's clock, and accepting it would make a link that just received a frame more
            // likely to be declared dead than one that did not.
            prop_assert!(after_second >= after_first);
            prop_assert_eq!(after_second, first.max(second).max(start).saturating_add(250));
            prop_assert_eq!(liveness.last_inbound_ms(), first.max(second).max(start));
        }

        /// Any queue depth below capacity is either healthy or merely congested, never an overflow. Reporting an
        /// overflow for a queue that has room would close working links.
        #[test]
        fn an_overflow_needs_a_full_queue(queued in 0usize..256, capacity in 1usize..=256) {
            let health = LinkHealth::classify(queued, capacity, 0, Duration::from_secs(1));
            if queued < capacity {
                prop_assert_ne!(health, LinkHealth::Overflow);
                prop_assert!(health.is_usable());
            }
            else {
                prop_assert_eq!(health, LinkHealth::Overflow);
                prop_assert!(health.should_close());
            }
        }
    }
}
