//! Queue and timeout classification for a live link.

use core::time::Duration;

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


