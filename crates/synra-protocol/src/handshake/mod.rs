//! Link establishment: what two devices say to each other before anything else.
//!
//! A `Hello` is the first frame on every connection, in both directions. It carries the protocol
//! version, what each side can do, and enough evidence for the receiving side to decide whether it
//! already trusts the caller.
//!
//! # The handshake exists to fail early
//!
//! Everything checked here is something that would otherwise fail later, after the user has already
//! asked for something:
//!
//! * **Protocol version** — a peer from a different major version would send frames this build
//!   cannot read. Refusing at `Hello` turns that into one clear message instead of a stream of
//!   unreadable frames.
//! * **Features** — a peer that cannot do `TransferResume` would strand a partially transferred
//!   file. The intersection is computed once, here, so no later code has to ask.
//!   rest of the kernel can assume every message on an established link came from a paired device.
//!
use serde::{Deserialize, Serialize};

/// The only protocol version this build speaks.
///
/// A single version with no compatibility layer. Two builds that disagree here do not talk; they
/// report it, and one of them is updated.
pub const PROTOCOL_VERSION: u16 = 1;

/// Identifies a protocol version this build cannot speak.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("peer speaks protocol {theirs}, this build speaks {ours}")]
pub struct VersionMismatch {
    /// The version this build speaks.
    pub ours: u16,
    /// The version the peer announced.
    pub theirs: u16,
}

/// A per-connection random value, so two connections are never confusable.
///
/// Sent by the dialer and echoed by the acceptor. Proves the reply belongs to *this* attempt rather
/// than to a delayed one, and gives every link a value that cannot be predicted from the last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionNonce(pub u128);

impl SessionNonce {
    /// A fresh nonce.
    #[must_use]
    pub fn random() -> Self {
        Self(uuid::Uuid::now_v7().as_u128())
    }

    /// Whether this is the all-zero value, which is never a valid nonce.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }
}

mod features;
mod hello;
mod state;

pub use features::{Agreed, Feature, negotiate};
pub use hello::{Hello, HelloAck, HelloError, RefusalReason};
pub use state::{HandshakeBudget, LinkAgreement, NextStep, ReplayError, SequenceGuard, next_step};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;
