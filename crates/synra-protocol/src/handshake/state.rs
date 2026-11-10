//! Handshake decisions, replay protection and time budgets.

use crate::ids::DeviceId;
use crate::limits;
use crate::session::PlatformKind;

use super::{Agreed, Feature, negotiate};
use super::hello::{HelloAck, RefusalReason};

/// What the dialer does next, once a reply has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NextStep {
    /// The link is established and the pairing is current.
    Established(Agreed),
    /// Do not connect, and do not retry on its own.
    Refused(RefusalReason),
    /// Try again later.
    Retry {
        /// Why, for the log.
        reason: RefusalReason,
    },
}

/// Decides what to do with a checked reply.
///
/// The whole handshake decision in one function, so it is testable without a socket and exists in one
/// place rather than being spread through the connect loop.
#[must_use]
pub fn next_step(ack: &HelloAck, ours: &[Feature], required: &[Feature]) -> NextStep {
    if let Some(refusal) = ack.refusal {
        return match refusal.is_retryable() {
            true => NextStep::Retry { reason: refusal },
            false => NextStep::Refused(refusal),
        };
    }

    let agreed = negotiate(ours, &ack.features, required);
    if !agreed.is_usable() {
        // The peer accepted but cannot do something this side needs. Refusing here rather than
        // proceeding means the failure surfaces at connection time, where it can be explained,
        // instead of at the moment the missing capability was first required.
        return NextStep::Refused(RefusalReason::MissingRequiredFeature);
    }

    NextStep::Established(agreed)
}


/// Replay protection for handshakes.
///
/// A recorded `Hello` replayed at a peer would otherwise look like a fresh attempt from the same
/// device. The sequence numbers are per device, monotonic, and small enough to persist: all that
/// matters is that a value is never accepted twice.
#[derive(Debug, Default)]
pub struct SequenceGuard {
    seen: u64,
}

impl SequenceGuard {
    /// A guard that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { seen: 0 }
    }

    /// A guard resuming from a persisted value.
    #[must_use]
    pub const fn resume(seen: u64) -> Self {
        Self { seen }
    }

    /// The highest sequence accepted so far, for persisting.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.seen
    }

    /// Accepts a sequence number, or reports it as a replay.
    ///
    /// Strictly greater rather than greater-or-equal: a peer that restarted its counter — from a
    /// restored backup, say — has to re-pair, and treating a repeated value as fresh would let a
    /// recorded attempt through. The equal case is exactly what a replay produces.
    ///
    /// # Errors
    ///
    /// [`ReplayError`] when the value is not newer than one already seen.
    pub const fn accept(&mut self, sequence: u64) -> Result<(), ReplayError> {
        if sequence <= self.seen {
            return Err(ReplayError { sequence, seen: self.seen });
        }
        self.seen = sequence;
        Ok(())
    }
}

/// A handshake sequence number that was not newer than one already seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("handshake sequence {sequence} is not newer than {seen}, so this is a replay")]
pub struct ReplayError {
    /// The value offered.
    pub sequence: u64,
    /// The highest value already accepted.
    pub seen: u64,
}

/// How long a link may stay in each handshake phase.
///
/// A `Hello` that arrives and is never answered holds a connection slot and a file descriptor. With
/// no limit, an attacker exhausts either by connecting and going quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeBudget {
    /// How long to wait for a peer's `Hello` after accepting a connection.
    pub await_hello: core::time::Duration,
    /// How long the dialer waits for a `HelloAck`.
    pub await_ack: core::time::Duration,
    /// How long a link may sit paired-but-not-established.
    pub await_pairing: core::time::Duration,
}

impl Default for HandshakeBudget {
    fn default() -> Self {
        Self {
            await_hello: limits::HELLO_TIMEOUT,
            await_ack: limits::HELLO_TIMEOUT,
            // Long enough to find the phone and tap accept, short enough that a forgotten prompt
            // does not hold a slot all afternoon.
            await_pairing: core::time::Duration::from_secs(120),
        }
    }
}

impl HandshakeBudget {
    /// Checks the budget is usable.
    ///
    /// # Errors
    ///
    /// A description if any phase has no limit.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.await_hello.is_zero() || self.await_ack.is_zero() || self.await_pairing.is_zero() {
            return Err("every handshake phase needs a non-zero limit, or a quiet peer holds a slot");
        }
        Ok(())
    }
}

/// What a link has agreed to, once it is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkAgreement {
    /// The peer's device id.
    pub peer: DeviceId,
    /// The peer's name, as it announced itself.
    pub peer_display_name: String,
    /// Which platform it runs.
    pub peer_platform: PlatformKind,
    /// The features both sides can use.
    pub agreed: Agreed,
    /// Whether the pairing was already current.
    pub paired: bool,
}


