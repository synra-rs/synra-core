//! The byte-level layer: length-prefixed frames, and a decoder that refuses to resynchronise.
//!
//! ```text
//! ┌──────────────────┬──────────┬──────────┬─────────────────────────┐
//! │ u32 BE length    │ u8 kind  │ u8 flags │ body (length - 2 bytes) │
//! └──────────────────┴──────────┴──────────┴─────────────────────────┘
//!      4 bytes          1 byte     1 byte
//! ```
//!
//! The length field counts the kind and flags bytes as well as the body, so a body-less frame
//! declares `2`. `FRAME_HEADER_LEN` is 6: four bytes of length, one of kind, one of flags.
//!
//! # The one rule everything else follows from
//!
//! **Any structural problem closes the link.** Not skipped, not worked around, not resynchronised.
//!
//! It is tempting to make a decoder forgiving — skip a bad frame and carry on, so one corrupt
//! datagram does not cost a reconnection. That is the wrong trade. A frame's length is a *claim*;
//! once a claim is wrong, every subsequent boundary is wrong too. A forgiving decoder keeps
//! producing "frames" from the middle of other frames, and the connection appears alive while
//! carrying nonsense. The cost of refusing is a few seconds of reconnection; the cost of skipping is
//! a link that is permanently broken, with symptoms that look like a bug anywhere but here.
//!
//! So the decoder has one entrance and one failure mode. After an error it is
//! [`FrameDecoder::is_poisoned`], and [`FrameDecoder::next_frame`] refuses to continue — the caller
//! cannot carry on by accident.
//!
//! # Zero copy
//!
//! [`FrameDecoder`] keeps the last received [`Bytes`] and slices frames straight out of it, so the
//! common case — a read containing whole frames — copies nothing. Only a frame split across reads is
//! copied, into a small scratch buffer, because it has to live somewhere until the rest arrives.
//! Every body it produces is a shared slice, so forwarding a message is a reference-count bump
//! rather than a memcpy.

use core::fmt;

use bytes::Bytes;

use crate::limits::{FRAME_HEADER_LEN, MAX_CHUNK_LEN, MAX_FRAME_LEN};

/// What a frame carries.
///
/// An unknown kind is a protocol violation rather than something to ignore: the kinds are a closed
/// set, and a byte outside it means the stream is not what the peer believes it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum FrameKind {
    /// A JSON envelope.
    Envelope = 0x01,
    /// A binary chunk of a transfer.
    Chunk = 0x02,
    /// A heartbeat. Empty body.
    Ping = 0x03,
    /// A heartbeat reply. Empty body.
    Pong = 0x04,
    /// Link establishment.
    Hello = 0x05,
    /// Link establishment accepted.
    HelloAck = 0x06,
    /// Deliberate shutdown, with a reason code.
    Bye = 0x07,
}

impl FrameKind {
    /// The byte written on the wire.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decodes a kind byte.
    ///
    /// # Errors
    ///
    /// [`FrameError::UnknownKind`] for any byte outside the defined set.
    pub const fn from_u8(value: u8) -> Result<Self, FrameError> {
        match value {
            0x01 => Ok(Self::Envelope),
            0x02 => Ok(Self::Chunk),
            0x03 => Ok(Self::Ping),
            0x04 => Ok(Self::Pong),
            0x05 => Ok(Self::Hello),
            0x06 => Ok(Self::HelloAck),
            0x07 => Ok(Self::Bye),
            other => Err(FrameError::UnknownKind { kind: other }),
        }
    }

    /// Whether a frame of this kind must have an empty body.
    #[must_use]
    pub const fn requires_empty_body(self) -> bool {
        matches!(self, Self::Ping | Self::Pong)
    }
}

impl fmt::Display for FrameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Envelope => "envelope",
            Self::Chunk => "chunk",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Hello => "hello",
            Self::HelloAck => "hello-ack",
            Self::Bye => "bye",
        })
    }
}

/// A binary chunk of a transfer step.
///
/// `data` is a shared slice, so cloning a chunk is O(1) and forwarding one costs no copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkFrame {
    /// Sequence number within the transfer session.
    pub chunk_id: u32,
    /// The bytes. Never longer than [`MAX_CHUNK_LEN`].
    pub data: Bytes,
}

/// What a frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameBody {
    /// No body: heartbeats.
    Empty,
    /// A JSON envelope, as raw bytes.
    ///
    /// Left unparsed: the frame layer's job is boundaries, and parsing here would make every caller
    /// pay for it even when the message is only being routed onward.
    Envelope(Bytes),
    /// A transfer chunk.
    Chunk(ChunkFrame),
    /// A handshake body.
    Hello(Bytes),
    /// A handshake reply body.
    HelloAck(Bytes),
    /// A shutdown reason: one code byte, then optional UTF-8 text.
    Bye {
        /// Reason code. `0` means "no particular reason".
        code: u8,
        /// Optional human-readable text.
        reason: Bytes,
    },
}

impl FrameBody {
    /// Encoded length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Envelope(b) | Self::Hello(b) | Self::HelloAck(b) => b.len(),
            Self::Chunk(c) => 4 + c.data.len(),
            Self::Bye { code: _, reason } => 1 + reason.len(),
        }
    }

    /// Whether the body is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// What the frame carries.
    pub kind: FrameKind,
    /// Reserved for future use. Always zero today; a non-zero value is accepted and preserved so a
    /// flag can be introduced without breaking older receivers.
    pub flags: u8,
    /// The body.
    pub body: FrameBody,
}

impl Frame {
    /// A frame with no body.
    #[must_use]
    pub const fn empty(kind: FrameKind) -> Self {
        Self { kind, flags: 0, body: FrameBody::Empty }
    }

    /// Total encoded length, header included.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        FRAME_HEADER_LEN + self.body.len()
    }
}

/// Why a frame could not be decoded.
///
/// Every variant means "close the link". There is deliberately no variant meaning "skip this one and
/// continue": see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The declared length cannot hold the header.
    #[error("frame length {len} is below the minimum {min}")]
    Truncated {
        /// The declared length.
        len: u32,
        /// The smallest legal declared length.
        min: u32,
    },

    /// The declared length exceeds the ceiling.
    #[error("frame length {len} exceeds the ceiling {max}")]
    TooLarge {
        /// The declared length.
        len: u32,
        /// The ceiling in force.
        max: u32,
    },

    /// The kind byte is not one this version defines.
    #[error("unknown frame kind 0x{kind:02x}")]
    UnknownKind {
        /// The offending byte.
        kind: u8,
    },

    /// A chunk's payload exceeds the ceiling.
    #[error("chunk data {len} exceeds the ceiling {max}")]
    ChunkTooLarge {
        /// Observed length.
        len: usize,
        /// The ceiling.
        max: usize,
    },

    /// A chunk body is shorter than the four-byte chunk id.
    #[error("chunk body is {actual} bytes, needs at least {expected}")]
    ChunkBodyTooShort {
        /// Minimum required.
        expected: usize,
        /// Observed.
        actual: usize,
    },

    /// A control frame carried a body where none is defined.
    #[error("{kind} must have an empty body, got {len} bytes")]
    UnexpectedBody {
        /// The frame kind.
        kind: FrameKind,
        /// Observed body length.
        len: usize,
    },

    /// A frame that requires a body had none.
    #[error("{kind} requires a body")]
    MissingBody {
        /// The frame kind.
        kind: FrameKind,
    },

    /// Encoding was asked to produce a frame larger than the ceiling.
    #[error("frame of {len} bytes exceeds the ceiling {max}")]
    EncodeTooLarge {
        /// The size requested.
        len: usize,
        /// The ceiling.
        max: u32,
    },

    /// The body does not match the kind it was given with.
    #[error("body {body} does not match frame kind {kind}")]
    BodyKindMismatch {
        /// The frame kind.
        kind: FrameKind,
        /// A description of the body that was supplied.
        body: &'static str,
    },

    /// The decoder was used after it had already failed.
    ///
    /// Not a protocol problem: it is the decoder protecting the caller from itself, because
    /// continuing after a structural error is exactly the mistake this module exists to prevent.
    #[error("decoder is poisoned after an earlier failure; close the link")]
    Poisoned,
}

mod decoder;
mod encoder;
mod validation;

pub use decoder::FrameDecoder;
pub use encoder::FrameEncoder;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod proptests;
#[cfg(test)]
#[allow(clippy::panic)]
mod tests;

