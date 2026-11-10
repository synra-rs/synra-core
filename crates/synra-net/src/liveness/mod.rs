//! Liveness: whether a link is still carrying anything.
//!
//! # A TCP connection can be dead and look alive
//!
//! A cable unplugged at the far end, a laptop that slept, a NAT entry that expired — none of these close the
//! socket. The local end sees an open connection and would wait forever, which is why the exchange is:
//!
//! * Send a [`Ping`](synra_protocol::frame::FrameKind::Ping) every
//!   [`HEARTBEAT_INTERVAL`](synra_protocol::limits::HEARTBEAT_INTERVAL).
//! * Treat **any** inbound frame as evidence of life, not only a `Pong`.
//! * Declare the link dead once nothing at all has arrived for
//!   [`HEARTBEAT_TIMEOUT`](synra_protocol::limits::HEARTBEAT_TIMEOUT).
//!
//! # Any frame, not just a pong
//!
//! Counting only `Pong` would declare a busy link dead whenever a large transfer delayed the reply behind
//! hundreds of data frames. The question the timeout answers is "is anything arriving", and a chunk frame answers
//! it exactly as well as a pong does.
//!
//! # The timeout is longer than the interval, and that is the point
//!
//! The timeout is two and a half intervals. Equal values would declare a link dead on a single lost
//! packet — the ping is sent, the pong is dropped, and a working connection is torn down. The ratio is what
//! tolerates the packet loss that ordinary networks have.

mod health;
mod heartbeat;

pub use health::LinkHealth;
pub use heartbeat::Liveness;

/// Why a link was declared dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeathReason {
    /// Nothing has arrived for [`HEARTBEAT_TIMEOUT`](synra_protocol::limits::HEARTBEAT_TIMEOUT).
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

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

