use core::time::Duration;

use synra_protocol::limits::{HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT};

use super::{DeathReason, HeartbeatAction};

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
