//! What a link's state is called, and how it may move.
//!
//! # Why the transition rule lives with the states
//!
//! Because a rule about states that sits anywhere else is a rule somebody will break: the two are read together, and
//! separating them means a change to one is made without seeing the other.
//!
//! # Why these are states and not flags
//!
//! `connected`, `agreed` and `draining` as three booleans admit states that cannot happen — draining and connected, agreed
//! and not connected. A state that cannot happen is one that is never tested, which means the day it happens nobody knows
//! what it should do.

/// How far a link has got.
///
/// # Why this is a state rather than a set of flags
///
/// `connected`, `agreed` and `draining` as three booleans admit five states that cannot happen — draining and
/// connected, agreed and not connected, all three at once. A state that cannot happen is one that is never tested,
/// which means the day it happens nobody knows what it should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LinkState {
    /// The socket is open and nothing has been exchanged.
    Connecting,
    /// Both ends have said hello and neither has agreed yet.
    Handshaking,
    /// Agreed, and carrying work.
    Ready,
    /// A goodbye has been sent or received, and the link is finishing what it was doing.
    ///
    /// Distinct from [`LinkState::Ready`] because a link that is draining must not take new work — the peer is going
    /// away, and a transfer started now is one neither side will finish.
    Draining,
    /// Over. The registry keeps the entry only until the caller removes it, so a diagnostic can say why it ended.
    Closed,
}

impl LinkState {
    /// The name, for a log line or a report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Handshaking => "handshaking",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }

    /// Whether the link can carry work.
    ///
    /// # Why only `Ready`
    ///
    /// A draining link is the tempting exception — the peer said goodbye and a small message might still fit — and it
    /// is the wrong one. A goodbye means the peer is closing, and a message accepted on a closing link is one that
    /// either fails or, worse, arrives after the peer has released its state.
    #[must_use]
    pub const fn accepts_work(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether frames may still be exchanged.
    ///
    /// A `Draining` link must: the goodbye and the in-flight replies are frames. A `Closed` one must not.
    #[must_use]
    pub const fn accepts_frames(self) -> bool {
        matches!(self, Self::Connecting | Self::Handshaking | Self::Ready | Self::Draining)
    }

    /// Whether the link is over.
    #[must_use]
    pub const fn is_over(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Why a session ended.
///
/// # Why this is recorded rather than inferred
///
/// A closed entry and a closed entry with a reason look the same from the outside, and the questions a user asks —
/// "why did it disconnect", "is it my network" — are answered by the reason. Recording it costs a small enum, and
/// inferring it after the fact is impossible: by then the socket, the peer's goodbye and the timeout are all gone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClosureReason {
    /// This side closed it, for a user-visible reason.
    Local {
        /// What the user asked for, or why the kernel did it.
        why: String,
    },
    /// The peer said goodbye.
    Peer {
        /// The peer's reason, if it gave one.
        why: Option<String>,
    },
    /// The peer stopped answering.
    ///
    /// The one reason a session is closed by this side that the user did not cause, so it is separated from
    /// [`ClosureReason::Local`]: a UI that showed both as "disconnected" would hide a network fault behind an ordinary
    /// one.
    HeartbeatMissed {
        /// How long the peer had been silent.
        silent_ms: u64,
    },
    /// The handshake failed.
    HandshakeFailed {
        /// What went wrong.
        why: String,
    },
    /// The link failed at the transport.
    TransportFailed {
        /// What the transport said.
        why: String,
    },
}

impl ClosureReason {
    /// A sentence for a log line or a report.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::Local { why } => format!("closed locally: {why}"),
            Self::Peer { why } => match why {
                Some(why) => format!("the peer closed it: {why}"),
                None => "the peer closed it".to_owned(),
            },
            Self::HeartbeatMissed { silent_ms } => {
                format!("the peer was silent for {silent_ms} ms, longer than the heartbeat timeout")
            }
            Self::HandshakeFailed { why } => format!("the handshake failed: {why}"),
            Self::TransportFailed { why } => format!("the transport failed: {why}"),
        }
    }

    /// Whether the user should be told the link is down, as opposed to told what they asked for.
    ///
    /// # Why this is a question
    ///
    /// A user who pressed "disconnect" does not need a notification saying the device disconnected — they were there
    /// when it happened. A peer that stopped answering does, because they did not cause it and may not have noticed.
    #[must_use]
    pub const fn is_unexpected(&self) -> bool {
        matches!(
            self,
            Self::HeartbeatMissed { .. }
                | Self::HandshakeFailed { .. }
                | Self::TransportFailed { .. }
        )
    }
}
