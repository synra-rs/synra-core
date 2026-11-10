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

use bytes::{Bytes, BytesMut};

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
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn encode(frame: &Frame) -> Bytes {
        FrameEncoder::encode_to_vec(frame).expect("encodes")
    }

    /// Feeds one complete frame and returns what came out.
    fn decode_one(bytes: Bytes) -> Result<Option<Frame>, FrameError> {
        let mut decoder = FrameDecoder::new();
        decoder.push(&bytes)?;
        decoder.next_frame()
    }

    #[test]
    fn every_kind_round_trips_through_a_byte() {
        for kind in [
            FrameKind::Envelope,
            FrameKind::Chunk,
            FrameKind::Ping,
            FrameKind::Pong,
            FrameKind::Hello,
            FrameKind::HelloAck,
            FrameKind::Bye,
        ] {
            assert_eq!(FrameKind::from_u8(kind.as_u8()), Ok(kind), "{kind}");
        }
    }

    #[rstest]
    #[case(0x00)]
    #[case(0x08)]
    #[case(0xFF)]
    fn unknown_kind_bytes_are_rejected(#[case] byte: u8) {
        assert!(matches!(
            FrameKind::from_u8(byte),
            Err(FrameError::UnknownKind { kind }) if kind == byte
        ));
    }

    #[test]
    fn ping_encodes_to_exactly_the_header() {
        let bytes = encode(&Frame::empty(FrameKind::Ping));
        assert_eq!(bytes.len(), FRAME_HEADER_LEN);
        // The length field counts the kind and flags bytes too, so a body-less frame declares 2.
        assert_eq!(&bytes[..4], &[0, 0, 0, 2]);
        assert_eq!(bytes[4], FrameKind::Ping.as_u8());
    }

    #[test]
    fn envelope_round_trips() {
        let payload = Bytes::from_static(br#"{"event":"device.ping"}"#);
        let bytes = encode(&Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(payload.clone()),
        });

        let frame = decode_one(bytes).expect("decodes").expect("one frame");
        assert_eq!(frame.kind, FrameKind::Envelope);
        assert_eq!(frame.body, FrameBody::Envelope(payload));
    }

    #[test]
    fn chunk_round_trips_with_its_id() {
        let bytes = encode(&Frame {
            kind: FrameKind::Chunk,
            flags: 0,
            body: FrameBody::Chunk(ChunkFrame {
                chunk_id: 0xDEAD_BEEF,
                data: Bytes::from_static(b"hello"),
            }),
        });

        let frame = decode_one(bytes).expect("decodes").expect("one frame");
        match frame.body {
            FrameBody::Chunk(chunk) => {
                assert_eq!(chunk.chunk_id, 0xDEAD_BEEF);
                assert_eq!(&chunk.data[..], b"hello");
            }
            other => panic!("expected a chunk, got {other:?}"),
        }
    }

    #[test]
    fn a_whole_frame_is_sliced_not_copied() {
        // The fast path. A read containing a whole frame must be sliced, so the decoded payload
        // points into the buffer the caller handed over — which is what makes forwarding a message a
        // refcount bump rather than a memcpy.
        static PAYLOAD: [u8; 64] = [7u8; 64];
        let frame_bytes = encode(&Frame {
            kind: FrameKind::Chunk,
            flags: 0,
            body: FrameBody::Chunk(ChunkFrame { chunk_id: 1, data: Bytes::from_static(&PAYLOAD) }),
        });
        let input = Bytes::from(frame_bytes.to_vec());
        let base = input.as_ptr() as usize;

        let mut decoder = FrameDecoder::new();
        decoder.push(&input).expect("push");
        let frame = decoder.next_frame().expect("decodes").expect("one frame");

        match frame.body {
            FrameBody::Chunk(chunk) => {
                assert_eq!(
                    chunk.data.as_ptr() as usize - base,
                    FRAME_HEADER_LEN + 4,
                    "the payload must be a slice of the caller's buffer",
                );
                assert_eq!(&chunk.data[..], &PAYLOAD[..]);
            }
            other => panic!("expected a chunk, got {other:?}"),
        }
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        // The slow path: the pieces have to be copied somewhere, and the result must still be
        // correct. Nothing may be lost or reordered.
        let bytes = encode(&Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}")),
        });

        for split in 1..bytes.len() {
            let mut decoder = FrameDecoder::new();
            decoder.push_slice(&bytes[..split]).expect("push head");
            assert_eq!(
                decoder.next_frame().expect("head is valid or incomplete"),
                None,
                "split at {split}"
            );

            decoder.push_slice(&bytes[split..]).expect("push tail");
            let frame = decoder.next_frame().expect("decodes").expect("one frame");
            assert_eq!(
                frame.body,
                FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}")),
                "split at {split}"
            );
        }
    }

    #[test]
    fn three_way_split_reassembles() {
        // More than two pieces, so the scratch buffer has to survive more than one append.
        let bytes = encode(&Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"hello")),
        });
        let (a, rest) = bytes.split_at(3);
        let (b, c) = rest.split_at(2);

        let mut decoder = FrameDecoder::new();
        for piece in [a, b, c] {
            decoder.push_slice(piece).expect("push");
        }
        let frame = decoder.next_frame().expect("decodes").expect("one frame");
        assert_eq!(frame.body, FrameBody::Envelope(Bytes::from_static(b"hello")));
    }

    #[test]
    fn length_below_the_minimum_is_rejected() {
        for len in 0u32..2 {
            let mut decoder = FrameDecoder::new();
            let mut header = Vec::from(len.to_be_bytes());
            header.extend_from_slice(&[FrameKind::Ping.as_u8(), 0]);
            decoder.push_slice(&header).expect("push");
            assert!(matches!(
                decoder.next_frame(),
                Err(FrameError::Truncated { len: got, min: 2 }) if got == len
            ));
            assert!(decoder.is_poisoned());
        }
    }

    #[test]
    fn length_above_the_ceiling_is_rejected_rather_than_buffered() {
        let mut decoder = FrameDecoder::with_max_frame(1024);
        // Header only: the body never arrives, and must never be waited for.
        let mut header = Vec::from(2048u32.to_be_bytes());
        header.extend_from_slice(&[FrameKind::Envelope.as_u8(), 0]);
        decoder.push_slice(&header).expect("push");

        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::TooLarge { len: 2048, max: 1024 })
        ));
        assert!(decoder.is_poisoned());
    }

    #[test]
    fn a_ceiling_breach_inside_scratch_is_also_rejected() {
        // Same property, reached through the partial-frame path: a split read must not let an
        // over-large claim through. Enough bytes are supplied for a header but not for the body, so
        // the decoder is holding a partial frame when it reads the length.
        let mut decoder = FrameDecoder::with_max_frame(64);
        let declared = 1000u32;
        let mut first = Vec::from(declared.to_be_bytes());
        first.extend_from_slice(&[FrameKind::Envelope.as_u8(), 0, b'{']);
        decoder.push_slice(&first).expect("push");

        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::TooLarge { len: 1000, max: 64 })
        ));
        assert!(decoder.is_poisoned());
    }

    #[test]
    fn incomplete_frame_returns_none_and_does_not_poison() {
        // A real frame, split so that only the header and part of the body have arrived.
        let whole = encode(&Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}")),
        });

        let mut decoder = FrameDecoder::new();
        decoder.push_slice(&whole[..8]).expect("push head");
        assert_eq!(decoder.next_frame(), Ok(None));
        assert!(!decoder.is_poisoned());

        // And it becomes decodable once the rest arrives — with no byte lost in between.
        decoder.push_slice(&whole[8..]).expect("push rest");
        let frame = decoder.next_frame().expect("decodes").expect("one frame");
        assert_eq!(
            frame.body,
            FrameBody::Envelope(Bytes::from_static(b"{\"a\":1}"))
        );
    }

    #[test]
    fn unknown_kind_poisons_the_decoder() {
        let mut decoder = FrameDecoder::new();
        decoder.push_slice(&[0, 0, 0, 2, 0xFF, 0x00]).expect("push");
        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::UnknownKind { kind: 0xFF })
        ));
        assert!(decoder.is_poisoned());
    }

    #[test]
    fn a_body_on_a_control_frame_is_rejected() {
        let mut decoder = FrameDecoder::new();
        // Declared 5 = kind + flags + 3 body bytes.
        decoder
            .push_slice(&[0, 0, 0, 5, FrameKind::Ping.as_u8(), 0, b'x', b'y', b'z'])
            .expect("push");
        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::UnexpectedBody { kind: FrameKind::Ping, len: 3 })
        ));
    }

    #[test]
    fn a_chunk_shorter_than_its_id_is_rejected() {
        let mut decoder = FrameDecoder::new();
        // Declared 5 = kind + flags + 3 body bytes, but a chunk needs four for the id.
        decoder
            .push_slice(&[0, 0, 0, 5, FrameKind::Chunk.as_u8(), 0, 1, 2, 3])
            .expect("push");
        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::ChunkBodyTooShort { expected: 4, actual: 3 })
        ));
    }

    #[test]
    fn an_oversized_chunk_is_rejected() {
        // A chunk's data ceiling is below the frame ceiling, so it is only reachable when the frame
        // ceiling is wide enough for the id and the data. A narrower `max_frame` would trip the
        // frame check first and the chunk check would never be exercised.
        let max_frame = u32::try_from(FRAME_HEADER_LEN + 4 + MAX_CHUNK_LEN + 1).expect("fits in u32");
        let mut decoder = FrameDecoder::with_max_frame(max_frame);

        let body_len = 4 + MAX_CHUNK_LEN + 1;
        let declared = u32::try_from(2 + body_len).expect("fits in u32");
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + body_len);
        bytes.extend_from_slice(&declared.to_be_bytes());
        bytes.push(FrameKind::Chunk.as_u8());
        bytes.push(0);
        bytes.extend(std::iter::repeat_n(0u8, body_len));

        decoder.push_slice(&bytes).expect("push");
        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::ChunkTooLarge { len, max })
                if len == MAX_CHUNK_LEN + 1 && max == MAX_CHUNK_LEN
        ));
    }

    #[test]
    fn empty_bye_body_is_a_missing_body_not_a_panic() {
        let mut decoder = FrameDecoder::new();
        decoder
            .push_slice(&[0, 0, 0, 2, FrameKind::Bye.as_u8(), 0])
            .expect("push");
        assert!(matches!(
            decoder.next_frame(),
            Err(FrameError::MissingBody { kind: FrameKind::Bye })
        ));
        assert!(decoder.is_poisoned());
    }

    #[test]
    fn poisoned_decoder_refuses_further_use() {
        // This is the whole point of the module: after a structural error there is no way to
        // continue by accident.
        let mut decoder = FrameDecoder::new();
        decoder
            .push_slice(&[0, 0, 0, 1, FrameKind::Ping.as_u8(), 0])
            .expect("push");
        assert!(decoder.next_frame().is_err());
        assert!(decoder.is_poisoned());

        assert_eq!(decoder.next_frame(), Err(FrameError::Poisoned));
        assert_eq!(decoder.push(&Bytes::new()), Err(FrameError::Poisoned));
        assert_eq!(decoder.push_slice(b"x"), Err(FrameError::Poisoned));
    }

    #[test]
    fn multiple_frames_in_one_batch_decode_in_order() {
        let mut batch = BytesMut::new();
        FrameEncoder::encode(&Frame::empty(FrameKind::Ping), &mut batch).expect("encode ping");
        FrameEncoder::encode(
            &Frame {
                kind: FrameKind::Envelope,
                flags: 0,
                body: FrameBody::Envelope(Bytes::from_static(b"{}")),
            },
            &mut batch,
        )
        .expect("encode envelope");

        let mut decoder = FrameDecoder::new();
        decoder.push(&batch.freeze()).expect("push");

        let first = decoder.next_frame().expect("first").expect("present");
        assert_eq!(first.kind, FrameKind::Ping);
        let second = decoder.next_frame().expect("second").expect("present");
        assert_eq!(second.kind, FrameKind::Envelope);
        assert_eq!(decoder.next_frame().expect("no more"), None);
    }

    #[test]
    fn recycle_keeps_the_decoder_usable() {
        let mut decoder = FrameDecoder::new();
        decoder
            .push(&encode(&Frame {
                kind: FrameKind::Envelope,
                flags: 0,
                body: FrameBody::Envelope(Bytes::from_static(b"{}")),
            }))
            .expect("push");
        let _ = decoder.next_frame().expect("decodes");
        assert_eq!(decoder.buffered(), 0);

        decoder.recycle();
        assert!(!decoder.is_poisoned());
        assert_eq!(decoder.next_frame().expect("empty"), None);

        decoder
            .push(&encode(&Frame::empty(FrameKind::Pong)))
            .expect("push");
        let frame = decoder.next_frame().expect("decodes").expect("present");
        assert_eq!(frame.kind, FrameKind::Pong);
    }

    #[test]
    fn release_marks_the_decoder_unusable() {
        // A decoder from a dead link must not be reused: leftover bytes would be read as the new
        // stream's first frame.
        let mut decoder = FrameDecoder::new();
        decoder.push_slice(b"leftover").expect("push");
        decoder.release();
        assert!(decoder.is_poisoned());
        assert_eq!(decoder.next_frame(), Err(FrameError::Poisoned));
        assert_eq!(decoder.buffered(), 0);
    }

    #[rstest]
    #[case(Frame { kind: FrameKind::Ping, flags: 0, body: FrameBody::Envelope(Bytes::from_static(b"{}")) }, "envelope")]
    #[case(Frame { kind: FrameKind::Envelope, flags: 0, body: FrameBody::Empty }, "empty")]
    #[case(Frame { kind: FrameKind::Chunk, flags: 0, body: FrameBody::Empty }, "empty")]
    #[case(Frame { kind: FrameKind::Bye, flags: 0, body: FrameBody::Empty }, "empty")]
    #[case(Frame { kind: FrameKind::Hello, flags: 0, body: FrameBody::Chunk(ChunkFrame { chunk_id: 1, data: Bytes::new() }) }, "chunk")]
    fn mismatched_body_shapes_cannot_be_encoded(#[case] frame: Frame, #[case] body: &str) {
        // Rejecting at encode time means a caller cannot put an unparseable frame on the wire.
        let mut out = BytesMut::new();
        match FrameEncoder::encode(&frame, &mut out) {
            Err(FrameError::BodyKindMismatch { kind, body: actual }) => {
                assert_eq!(kind, frame.kind);
                assert_eq!(actual, body);
            }
            Err(FrameError::MissingBody { kind }) => assert_eq!(kind, frame.kind),
            other => panic!("expected a shape error, got {other:?}"),
        }
        assert!(out.is_empty(), "a failed encode must leave the buffer untouched");
    }

    #[test]
    fn encode_refuses_an_oversized_envelope() {
        let frame = Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from(vec![b'{'; MAX_FRAME_LEN as usize])),
        };
        let mut out = BytesMut::new();
        assert!(matches!(
            FrameEncoder::encode(&frame, &mut out),
            Err(FrameError::EncodeTooLarge { .. })
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn flags_are_preserved_for_future_use() {
        let bytes = encode(&Frame { kind: FrameKind::Ping, flags: 0xAB, body: FrameBody::Empty });
        let frame = decode_one(bytes).expect("decodes").expect("one frame");
        assert_eq!(frame.flags, 0xAB);
    }

    #[test]
    fn encoded_len_matches_what_was_written() {
        let frame = Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"{}")),
        };
        assert_eq!(encode(&frame).len(), frame.encoded_len());
    }

    #[test]
    fn a_chunk_with_empty_data_is_legal() {
        // Zero-length data is unusual but not a violation: a session may legitimately send an empty
        // final chunk.
        let bytes = encode(&Frame {
            kind: FrameKind::Chunk,
            flags: 0,
            body: FrameBody::Chunk(ChunkFrame { chunk_id: 9, data: Bytes::new() }),
        });
        let frame = decode_one(bytes).expect("decodes").expect("one frame");
        assert_eq!(frame.body, FrameBody::Chunk(ChunkFrame { chunk_id: 9, data: Bytes::new() }));
    }

    #[test]
    fn two_bodies_from_one_read_share_its_allocation() {
        let mut batch = BytesMut::new();
        for (id, data) in [(1u32, &b"aa"[..]), (2, b"bbbb")] {
            FrameEncoder::encode(
                &Frame {
                    kind: FrameKind::Chunk,
                    flags: 0,
                    body: FrameBody::Chunk(ChunkFrame {
                        chunk_id: id,
                        data: Bytes::copy_from_slice(data),
                    }),
                },
                &mut batch,
            )
            .expect("encode");
        }
        let input = batch.freeze();
        let base = input.as_ptr() as usize;

        let mut decoder = FrameDecoder::new();
        decoder.push(&input).expect("push");

        let first = decoder.next_frame().expect("first").expect("present");
        let second = decoder.next_frame().expect("second").expect("present");
        let (FrameBody::Chunk(a), FrameBody::Chunk(b)) = (&first.body, &second.body) else {
            panic!("expected two chunks");
        };

        let a_start = a.data.as_ptr() as usize - base;
        let b_start = b.data.as_ptr() as usize - base;
        assert!(b_start > a_start, "the second chunk must follow the first");
        // Both are windows onto the same allocation.
        assert!(b_start + b.data.len() <= input.len());
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_kind() -> impl Strategy<Value = FrameKind> {
        prop_oneof![
            Just(FrameKind::Envelope),
            Just(FrameKind::Chunk),
            Just(FrameKind::Ping),
            Just(FrameKind::Pong),
            Just(FrameKind::Hello),
            Just(FrameKind::HelloAck),
            Just(FrameKind::Bye),
        ]
    }

    /// A frame that is legal to encode, so the round-trip property is meaningful.
    fn arbitrary_frame() -> impl Strategy<Value = Frame> {
        (arbitrary_kind(), any::<u8>()).prop_flat_map(|(kind, flags)| {
            let body: BoxedStrategy<FrameBody> = match kind {
                FrameKind::Ping | FrameKind::Pong => Just(FrameBody::Empty).boxed(),
                FrameKind::Envelope => proptest::collection::vec(any::<u8>(), 1..256)
                    .prop_map(|v| FrameBody::Envelope(Bytes::from(v)))
                    .boxed(),
                FrameKind::Hello => proptest::collection::vec(any::<u8>(), 1..64)
                    .prop_map(|v| FrameBody::Hello(Bytes::from(v)))
                    .boxed(),
                FrameKind::HelloAck => proptest::collection::vec(any::<u8>(), 1..64)
                    .prop_map(|v| FrameBody::HelloAck(Bytes::from(v)))
                    .boxed(),
                FrameKind::Chunk => (any::<u32>(), proptest::collection::vec(any::<u8>(), 0..128))
                    .prop_map(|(chunk_id, data)| {
                        FrameBody::Chunk(ChunkFrame { chunk_id, data: Bytes::from(data) })
                    })
                    .boxed(),
                FrameKind::Bye => (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..32))
                    .prop_map(|(code, reason)| FrameBody::Bye { code, reason: Bytes::from(reason) })
                    .boxed(),
            };
            body.prop_map(move |body| Frame { kind, flags, body })
        })
    }

    proptest! {
        /// Encoding then decoding returns the frame unchanged.
        #[test]
        fn frame_round_trips(frame in arbitrary_frame()) {
            let bytes = FrameEncoder::encode_to_vec(&frame).expect("a generated frame encodes");
            let mut decoder = FrameDecoder::new();
            decoder.push(&bytes).expect("push");
            let decoded = decoder.next_frame().expect("decodes").expect("one frame");
            prop_assert_eq!(decoded, frame);
        }

        /// The property the whole module exists for: arbitrary input either produces a frame, asks
        /// for more bytes, or reports an error. It never panics and never reads out of bounds.
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut decoder = FrameDecoder::new();
            decoder.push_slice(&bytes).expect("first push succeeds");

            // Bounded by the input length, so a pathological length field cannot loop forever.
            for _ in 0..=bytes.len() {
                match decoder.next_frame() {
                    Ok(Some(frame)) => {
                        // Touching the body proves the slice is in range.
                        let _ = frame.body.len();
                    }
                    Ok(None) => break,
                    Err(_) => {
                        // The only allowed outcome besides success.
                        prop_assert!(decoder.is_poisoned());
                        break;
                    }
                }
            }
        }

        /// Feeding bytes in arbitrary chunks produces the same frames as feeding them at once. This
        /// is what makes a decoder safe to use over a socket, where a frame arrives in as many
        /// pieces as the network chooses.
        #[test]
        fn chunked_delivery_matches_bulk_delivery(
            frames in proptest::collection::vec(arbitrary_frame(), 1..6),
            cuts in proptest::collection::vec(0usize..64, 0..8),
        ) {
            let mut encoded = BytesMut::new();
            for frame in &frames {
                FrameEncoder::encode(frame, &mut encoded).expect("encodes");
            }
            let bulk = encoded.freeze();

            let mut decoder = FrameDecoder::new();
            let mut collected = Vec::new();
            let mut offset = 0usize;
            for cut in cuts {
                let end = (offset + cut).min(bulk.len());
                decoder.push(&bulk.slice(offset..end)).expect("push");
                offset = end;
                while let Some(frame) = decoder.next_frame().expect("valid stream") {
                    collected.push(frame);
                }
            }
            decoder.push(&bulk.slice(offset..)).expect("push tail");
            while let Some(frame) = decoder.next_frame().expect("valid stream") {
                collected.push(frame);
            }

            prop_assert_eq!(collected, frames);
        }
    }
}

