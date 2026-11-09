//! A link that has finished its handshake, and what travels on it.
//!
//! # What this adds to the handshake
//!
//! [`crate::peer`] reaches agreement and hands back a socket. This turns that socket into a link: envelopes go out and
//! come in, and the link refuses the three things a raw socket would happily deliver.
//!
//! * **An envelope addressed to somebody else.** `synra-protocol`'s `Envelope` carries a `target`, and a peer that sends
//!   one for another device is either misconfigured or probing. The check is against this device's own identifier.
//! * **An envelope claiming to be from somebody else.** This is the one that matters: the link's peer *is* the sender,
//!   so an envelope whose `from` is a different device is a peer trying to speak for a device it is not. Without this,
//!   any paired device could send an intent that appears to come from a device the user trusts more.
//! * **A frame that is not an envelope.** A `Hello` after the handshake is a peer that has lost track of where it is,
//!   and a `Chunk` outside a transfer is one with no transfer to belong to. Both are reported rather than routed.
//!
//! # Why the receive half returns an owned envelope
//!
//! `Envelope::payload` is a `Box<RawValue>` — the protocol's own decision, so that a kernel can check a message's shape
//! without parsing it into a tree. Owning the envelope keeps that: a borrow of the frame buffer would tie the envelope's
//! lifetime to the next read, and the kernel's routing outlives one read.
//!
//! # What is not here
//!
//! Chunked transfer bodies. A `Chunk` frame belongs to a transfer that a session owns, and the pieces that own it — the
//! block bitmap, the digest check, the resumption — are the transfer layer's. This link carries envelopes and reports a
//! chunk as an unexpected frame, which is the honest answer while there is no transfer to hand it to.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

/// A byte stream backed by memory, for a link with no socket behind it.
///
/// Public because the end-to-end tests `04 §11` describes need to name it: a fixture inside `#[cfg(test)]` is one nobody
/// outside this crate can substitute.
pub mod memory;

use bytes::Bytes;
use synra_protocol::envelope::Envelope;
use synra_protocol::frame::{
    ChunkFrame, Frame, FrameBody, FrameDecoder, FrameEncoder, FrameError, FrameKind,
};
use synra_protocol::ids::DeviceId;

use crate::peer::{Flags, HandshakeError};

/// Why a link operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The captured authenticated authorization was revoked or does not match this link.
    #[error("the link is no longer authorized")]
    Unauthorized,
    /// Authorization could not be checked; the connection must not continue.
    #[error("the link authorization check failed: {why}")]
    AuthorizationUnavailable {
        /// The persistence failure, without credentials.
        why: String,
    },
    /// The stream failed.
    #[error("the link failed: {why}")]
    Transport {
        /// What the operating system said.
        why: String,
    },

    /// A read or a write waited longer than the link's timeout.
    ///
    /// ★ Both directions, and the second was missing for a long time.
    ///
    /// A read that times out means nothing arrived; a **write** that times out means the peer is alive and not taking bytes —
    /// its receive window is full. They are the same fact about the link from opposite ends, and neither is a broken
    /// connection. The write side reported every failure as [`Self::Transport`] until this variant covered it, so a caller
    /// could not tell a busy peer from a dead one.
    ///
    /// # Why this is not `Transport`
    ///
    /// Because "nothing has arrived yet" and "the connection is broken" are different facts with different answers, and
    /// flattening them into one is how a working transfer gets reported as a broken link. An end-to-end run showed exactly
    /// that: a 300 KB file arrived byte-for-byte while the sender reported `transport_not_open`, because a read had timed
    /// out while it was waiting for a confirmation that was still in flight.
    #[error("the link was quiet for longer than the timeout")]
    TimedOut,

    /// The peer closed the link.
    #[error("the peer closed the link")]
    Closed,

    /// A frame could not be encoded or decoded.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// A frame arrived that this link does not carry.
    #[error("expected an envelope and received a {found} frame")]
    Unexpected {
        /// What arrived.
        found: String,
    },

    /// An envelope could not be read or was refused.
    #[error("the envelope was refused: {why}")]
    Envelope {
        /// What the protocol's validator said.
        why: String,
    },
}

impl From<HandshakeError> for LinkError {
    fn from(error: HandshakeError) -> Self {
        // A handshake's transport failure and a link's are the same condition seen at different moments; collapsing them
        // keeps a caller from having to handle two spellings of "the connection broke".
        match error {
            HandshakeError::Transport { why } => Self::Transport { why },
            HandshakeError::Closed => Self::Closed,
            HandshakeError::Frame(inner) => Self::Frame(inner),
            other => Self::Envelope {
                why: other.to_string(),
            },
        }
    }
}

pub(crate) fn transport_error(error: &std::io::Error) -> LinkError {
    error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<LinkError>())
        .cloned()
        .unwrap_or_else(|| LinkError::Transport {
            why: error.to_string(),
        })
}

/// What arrived on a link.
///
/// # Why the envelope is boxed
///
/// Because an `Envelope` holds a `Box<RawValue>` payload and a `CompactString` event name, so it is far larger than a
/// block's four-byte header — and an enum sized for the larger variant makes every block, which is the common case during
/// a transfer, pay for the rare one.
#[derive(Debug)]
#[non_exhaustive]
pub enum Inbound {
    /// A control-plane message.
    Envelope(Box<Envelope>),
    /// A block of a file, which the transfer layer owns.
    Block {
        /// Which block, within the transfer the caller is tracking.
        chunk_id: u32,
        /// The bytes.
        data: Bytes,
    },
}

/// A byte stream a link can be built on.
///
/// ★ Why this trait exists, and what it is not.
///
/// `PeerLink` held a **concrete `TcpStream`**, so the only way to exercise a link was to open a socket — and the design's
/// end-to-end tests, which want two kernels linked in one process, had nothing to substitute. `synra-testkit` already has a
/// `MemoryTransport`, but it moves **decoded frames** while a link decodes **bytes**, so the two are type-incompatible: the
/// seam was missing, not the fixture. `04 §11` records exactly this, and this is the seam it asked for, at the byte layer
/// because that is the layer the link lives at.
///
/// # Why the methods return this crate's error rather than `std::io::Error`
///
/// Because a promise about another crate's error type is a promise about its version — `synra-error-guard` exists to refuse exactly
/// that, and it is right to: a consumer matching on `std::io::ErrorKind` from a `synra-core` signature has tied its build to
/// whatever `std` does next. Converting at the boundary costs one `map_err` per implementation and keeps the promise where
/// it belongs.
///
/// # Why `Read` and `Write` are supertraits
///
/// Because the framing is above this line: a link reads bytes into its own decoder and writes encoded frames, and inventing
/// separate `read_bytes`/`write_bytes` methods would be a second spelling of two traits that already exist and are already
/// implemented by everything a caller might bring.
pub trait LinkStream: Read + Write + Send + std::fmt::Debug {
    /// Rechecks authorization for these actual link identities before delivering or sending a frame.
    ///
    /// Memory fixtures and legacy transports have no authority to check. Authenticated transports
    /// must compare their captured credential generation even when a frame was already buffered.
    /// # Errors
    /// Refuses revoked identities and unavailable authorization storage.
    fn authorize(&self, _local: DeviceId, _peer: DeviceId) -> Result<(), LinkError> {
        Ok(())
    }

    /// Sets the deadline one `read` call runs under.
    ///
    /// # Errors
    ///
    /// [`LinkError::Transport`] when the stream refuses the deadline — which is a real case rather than a theoretical one:
    /// Windows rejects a zero timeout outright.
    fn set_read_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError>;

    /// Sets the deadline one `write` call runs under.
    ///
    /// # Errors
    ///
    /// As [`Self::set_read_deadline`].
    fn set_write_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError>;
}

impl LinkStream for TcpStream {
    fn set_read_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError> {
        self.set_read_timeout(Some(timeout))
            .map_err(|error| LinkError::Transport {
                why: error.to_string(),
            })
    }

    fn set_write_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError> {
        self.set_write_timeout(Some(timeout))
            .map_err(|error| LinkError::Transport {
                why: error.to_string(),
            })
    }
}

/// A socket whose handshake is done.
///
/// # Why this is not the session registry's entry
///
/// `synra_core::sessions` records what the *kernel* knows about a link — its state, its heartbeat deadline, its closure
/// reason — and this is the *wire*: one socket, one decoder, and the checks that belong to this specific connection. A
/// session that lost its socket is still a session with a reason to report; a link without a socket is nothing.
#[derive(Debug)]
pub struct PeerLink {
    /// The bytes, behind the seam above.
    ///
    /// Boxed rather than generic so `PeerLink` stays one type: a generic link would put the choice of stream into every
    /// signature that mentions a link — the session registry, the listener, the daemon's transport — and none of them cares.
    stream: Box<dyn LinkStream>,
    decoder: FrameDecoder,
    /// This device, so an envelope's target can be checked.
    local: DeviceId,
    /// The peer, so an envelope's `from` can be checked.
    peer: DeviceId,
    /// What was agreed, for a caller that has to know whether a feature is available.
    agreed: synra_protocol::handshake::Agreed,
    /// Flags a read runs under.
    flags: Flags,
    /// A per-call read timeout, for a caller whose own deadline is sooner than the link's.
    read_timeout_override: Option<std::time::Duration>,
    /// A write deadline a caller asked for, in place of the negotiated one.
    ///
    /// ★ The asymmetry this fixes: a **read** timeout had an override and a write timeout did not exist at all. A caller that
    /// wanted its own write deadline had no way to say so, and the link's own deadline is the negotiated session timeout —
    /// thirty seconds — which for a transfer's first block is a long time to hold a thread that could be told sooner.
    write_timeout_override: Option<std::time::Duration>,
    /// Envelopes sent, for a report.
    sent: u64,
    /// Envelopes received and accepted, for a report.
    received: u64,
    /// Where the byte counters go, when the host has a recorder.
    ///
    /// ★ Payload bytes, not wire bytes: the frame header is the transport's accounting, and what a reader of
    /// `bytes_sent_total` is asking is "how much did this device move". A link with no recorder is a link, not a broken
    /// one — the same rule `Host::with_metrics` and the plugin host follow.
    metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
}

mod peer;
mod receive;
mod send;

#[cfg(test)]
mod tests;
