//! Reconnection: when to try again, and how long to wait.
//!
//! # The schedule is a floor, not a timer
//!
//! [`synra_protocol::limits::RECONNECT_BACKOFF`] exists because a failed connection must not be retried in a tight
//! loop — that turns a peer that is merely asleep into a peer whose network is saturated. But a device that has
//! just *rediscovered* the peer it was waiting for should not sit out the remaining twenty seconds of a backoff it
//! no longer needs.
//!
//! So there are two kinds of event:
//!
//! * **Time passing** — the scheduled delay elapsed, so a retry is due.
//! * **Something changing** — the peer was rediscovered, the network changed, the application came to the
//!   foreground. Each of these is evidence the previous failure's cause may be gone, so the wait is cut short.
//!
//! # Why the jitter is not optional
//!
//! Every device that lost the same peer at the same moment — a router reboot — would otherwise retry at the same
//! instant, and the router would see the whole fleet arrive together. The jitter spreads them.
//!
//! **The jitter is derived, not random.** A caller supplies the seed, and the same seed always produces the same
//! delay. That is what makes the schedule testable: a test asserts the exact delays for a known seed rather than a
//! range, and a failure is reproducible from a log line.

use core::time::Duration;

mod schedule;

pub use schedule::Backoff;

/// What caused a retry to be considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryTrigger {
    /// The scheduled delay elapsed.
    Timer,
    /// The peer was seen again — a discovery reply, a mDNS announcement.
    Rediscovered,
    /// The set of available networks changed.
    NetworkChanged,
    /// The application came to the foreground.
    Foreground,
    /// A local change means the peer may now accept a connection, such as a plugin that has to be synchronised.
    LocalChange,
}

impl RetryTrigger {
    /// Whether this trigger justifies retrying before the schedule says so.
    ///
    /// Only [`Self::Timer`] waits. The others are all evidence that the condition which caused the failure may
    /// have changed, and making them wait would mean a device that was rediscovered sits idle through a backoff
    /// designed for a device that was not.
    #[must_use]
    pub const fn overrides_schedule(self) -> bool {
        !matches!(self, Self::Timer)
    }

    /// A name for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Rediscovered => "rediscovered",
            Self::NetworkChanged => "network-changed",
            Self::Foreground => "foreground",
            Self::LocalChange => "local-change",
        }
    }
}

/// Why a peer is not being retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackoffRefusal {
    /// The delay has not elapsed and nothing has changed.
    TooSoon {
        /// How long is left.
        remaining: Duration,
    },
    /// Retrying has been given up on.
    ///
    /// A peer that has failed this many times is not going to succeed on the next attempt, and continuing to try
    /// costs battery and log volume. The peer is still rediscoverable; it is this schedule that stops, not the
    /// possibility of ever connecting.
    GivenUp {
        /// How many attempts were made.
        attempts: u32,
    },
}

/// How many consecutive failures before the schedule stops.
///
/// A ceiling rather than unbounded: an application that has tried for an hour against a peer that is unplugged is
/// one that has spent an hour of battery and filled a log file. Rediscovery is what starts it again.
pub const MAX_ATTEMPTS: u32 = 12;

/// Why the schedule was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResetReason {
    /// A connection was established and the handshake completed.
    Connected,
    /// The user asked for it, such as a "reconnect now" button.
    UserRequest,
    /// The peer was unpaired, so there is nothing to reconnect to.
    Unpaired,
}

/// A retry that is waiting, for the interface to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRetry {
    /// The peer.
    pub peer: String,
    /// How many times it has failed.
    pub attempts: u32,
    /// How long until the next attempt, as of when it was computed.
    pub in_ms: u64,
}

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
