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

use bytes::{Buf, BufMut, Bytes, BytesMut};

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

/// Encodes frames.
///
/// Stateless, and separate from [`FrameDecoder`] so the two directions cannot accidentally share
/// mutable state.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameEncoder;

impl FrameEncoder {
    /// The smallest legal declared length: kind plus flags, with an empty body.
    pub const MIN_DECLARED: u32 = 2;

    /// Appends `frame` to `out`.
    ///
    /// Nothing is written when an error is returned, so a failed encode can never leave half a frame
    /// in the buffer.
    ///
    /// # Errors
    ///
    /// [`FrameError::EncodeTooLarge`] if the encoded frame would exceed [`MAX_FRAME_LEN`], or a
    /// body-shape error if the body does not match the kind.
    pub fn encode(frame: &Frame, out: &mut BytesMut) -> Result<(), FrameError> {
        let total = validate_for_encode(frame)?;

        // `total <= MAX_FRAME_LEN` (1 MiB), so the cast is lossless.
        #[allow(clippy::cast_possible_truncation)]
        let declared = (total - 4) as u32;

        // `put_*` on a `BytesMut` grows as needed and cannot panic.
        out.put_u32(declared);
        out.put_u8(frame.kind.as_u8());
        out.put_u8(frame.flags);

        match &frame.body {
            FrameBody::Empty => {}
            FrameBody::Envelope(b) | FrameBody::Hello(b) | FrameBody::HelloAck(b) => {
                out.put_slice(b);
            }
            FrameBody::Chunk(chunk) => {
                out.put_u32(chunk.chunk_id);
                out.put_slice(&chunk.data);
            }
            FrameBody::Bye { code, reason } => {
                out.put_u8(*code);
                out.put_slice(reason);
            }
        }

        Ok(())
    }

    /// Encodes into a fresh buffer.
    ///
    /// # Errors
    ///
    /// As [`Self::encode`].
    pub fn encode_to_vec(frame: &Frame) -> Result<Bytes, FrameError> {
        let mut out = BytesMut::with_capacity(frame.encoded_len());
        Self::encode(frame, &mut out)?;
        Ok(out.freeze())
    }
}

/// Names a body variant, for error messages.
const fn body_name(body: &FrameBody) -> &'static str {
    match body {
        FrameBody::Empty => "empty",
        FrameBody::Envelope(_) => "envelope",
        FrameBody::Chunk(_) => "chunk",
        FrameBody::Hello(_) => "hello",
        FrameBody::HelloAck(_) => "hello-ack",
        FrameBody::Bye { .. } => "bye",
    }
}

/// Checks a frame can be encoded, and returns its total encoded length.
fn validate_for_encode(frame: &Frame) -> Result<usize, FrameError> {
    // Kind and body must agree. Sending a mismatch would put a frame on the wire that the peer
    // rejects, which is worse than failing locally where the caller can see it.
    let consistent = matches!(
        (frame.kind, &frame.body),
        (FrameKind::Ping | FrameKind::Pong, FrameBody::Empty)
            | (FrameKind::Envelope, FrameBody::Envelope(_))
            | (FrameKind::Chunk, FrameBody::Chunk(_))
            | (FrameKind::Hello, FrameBody::Hello(_))
            | (FrameKind::HelloAck, FrameBody::HelloAck(_))
            | (FrameKind::Bye, FrameBody::Bye { .. })
    );
    if !consistent {
        return Err(FrameError::BodyKindMismatch {
            kind: frame.kind,
            body: body_name(&frame.body),
        });
    }

    if frame.kind.requires_empty_body() {
        return Ok(FRAME_HEADER_LEN);
    }

    if frame.body.is_empty() {
        return Err(FrameError::MissingBody { kind: frame.kind });
    }

    if let FrameBody::Chunk(chunk) = &frame.body
        && chunk.data.len() > MAX_CHUNK_LEN
    {
        return Err(FrameError::ChunkTooLarge { len: chunk.data.len(), max: MAX_CHUNK_LEN });
    }

    let total = FRAME_HEADER_LEN
        .checked_add(frame.body.len())
        .ok_or(FrameError::EncodeTooLarge { len: usize::MAX, max: MAX_FRAME_LEN })?;

    if total > MAX_FRAME_LEN as usize {
        return Err(FrameError::EncodeTooLarge { len: total, max: MAX_FRAME_LEN });
    }

    Ok(total)
}

/// Validates the length field on its own, before any body bytes are waited for.
///
/// Separated from the rest of the header handling because it is the security-relevant check: it runs
/// on the strength of the header alone, so a hostile or corrupt length can never make the buffer
/// grow.
const fn validate_declared(declared: u32, max_frame: u32) -> Result<(), FrameError> {
    if declared < FrameEncoder::MIN_DECLARED {
        return Err(FrameError::Truncated { len: declared, min: FrameEncoder::MIN_DECLARED });
    }
    if declared > max_frame {
        return Err(FrameError::TooLarge { len: declared, max: max_frame });
    }
    Ok(())
}

/// Rejects frames whose body does not fit their kind.
const fn validate_shape(kind: FrameKind, body_len: usize) -> Result<(), FrameError> {
    if kind.requires_empty_body() {
        return if body_len == 0 {
            Ok(())
        } else {
            Err(FrameError::UnexpectedBody { kind, len: body_len })
        };
    }

    match kind {
        FrameKind::Chunk => {
            // Four bytes of chunk id, then data. Empty data is legal.
            if body_len < 4 {
                return Err(FrameError::ChunkBodyTooShort { expected: 4, actual: body_len });
            }
            let data_len = body_len - 4;
            if data_len > MAX_CHUNK_LEN {
                return Err(FrameError::ChunkTooLarge { len: data_len, max: MAX_CHUNK_LEN });
            }
            Ok(())
        }
        // A `Bye` needs at least the reason code.
        FrameKind::Envelope | FrameKind::Hello | FrameKind::HelloAck | FrameKind::Bye
            if body_len == 0 =>
        {
            Err(FrameError::MissingBody { kind })
        }
        _ => Ok(()),
    }
}

/// Splits a validated body into its typed form.
fn build_body(kind: FrameKind, body: Bytes) -> Result<FrameBody, FrameError> {
    Ok(match kind {
        FrameKind::Ping | FrameKind::Pong => FrameBody::Empty,
        FrameKind::Envelope => FrameBody::Envelope(body),
        FrameKind::Hello => FrameBody::Hello(body),
        FrameKind::HelloAck => FrameBody::HelloAck(body),
        FrameKind::Chunk => {
            // `validate_shape` guarantees at least four bytes, so `slice` cannot panic.
            let mut id_reader = body.slice(..4);
            let chunk_id = id_reader.get_u32();
            FrameBody::Chunk(ChunkFrame { chunk_id, data: body.slice(4..) })
        }
        FrameKind::Bye => {
            // `validate_shape` guarantees at least one byte.
            let Some(code) = body.first().copied() else {
                return Err(FrameError::MissingBody { kind: FrameKind::Bye });
            };
            FrameBody::Bye { code, reason: body.slice(1..) }
        }
    })
}

/// A validated frame header.
#[derive(Debug, Clone, Copy)]
struct Header {
    declared: u32,
    kind_byte: u8,
    flags: u8,
}

impl Header {
    /// Body length implied by the declared length.
    ///
    /// `validate_declared` has already established `declared >= 2`, so this cannot underflow.
    const fn body_len(self) -> usize {
        (self.declared - 2) as usize
    }
}

/// Reads a header without indexing, returning `None` if six bytes are not present.
fn read_header(bytes: &Bytes) -> Option<Header> {
    let [l0, l1, l2, l3, kind_byte, flags] = bytes.first_chunk::<FRAME_HEADER_LEN>()?;
    Some(Header {
        declared: u32::from_be_bytes([*l0, *l1, *l2, *l3]),
        kind_byte: *kind_byte,
        flags: *flags,
    })
}

/// Turns a whole-frame region into a typed frame.
fn build_frame(region: &Bytes, header: Header) -> Result<Frame, FrameError> {
    let kind = FrameKind::from_u8(header.kind_byte)?;
    validate_shape(kind, header.body_len())?;

    // Skip the header. `slice` is O(1), so the body is still the same allocation.
    let body = build_body(kind, region.slice(FRAME_HEADER_LEN..))?;

    Ok(Frame { kind, flags: header.flags, body })
}

/// Incremental decoder.
///
/// Feed it bytes with [`Self::push`], read frames with [`Self::next_frame`], drop the last read with
/// [`Self::recycle`]. Every error is a link-closing condition; after one the decoder is poisoned.
///
/// # Buffer behaviour
///
/// A read that contains whole frames is sliced, not copied. A frame split across reads is copied
/// into `scratch`, which is reused: [`Self::recycle`] resets its length without freeing or zeroing
/// the allocation.
#[derive(Debug)]
pub struct FrameDecoder {
    /// The most recent read, kept so whole frames can be sliced out of it.
    head: Option<Bytes>,
    /// Holds a frame that is waiting for the rest of its bytes.
    scratch: BytesMut,
    /// Set on the first error. Once set, every operation returns [`FrameError::Poisoned`].
    poisoned: bool,
    /// Largest frame this decoder accepts, so a test or a host can lower it.
    max_frame: u32,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// A decoder with the standard ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            head: None,
            scratch: BytesMut::with_capacity(8 * 1024),
            poisoned: false,
            max_frame: MAX_FRAME_LEN,
        }
    }

    /// A decoder with a lowered ceiling, for tests and for hosts that want a smaller limit.
    #[must_use]
    pub fn with_max_frame(max_frame: u32) -> Self {
        Self { max_frame, ..Self::new() }
    }

    /// Whether an earlier operation failed.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Bytes buffered but not yet consumed.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.scratch.len() + self.head.as_ref().map_or(0, Bytes::len)
    }

    /// Appends received bytes.
    ///
    /// Takes `&Bytes` rather than `&[u8]` so a caller can hand over a socket read without a
    /// conversion. When the read contains whole frames — the common case — they are sliced straight
    /// out of it, so the fast path copies nothing at all. Only a frame split across reads is copied,
    /// into the scratch buffer, because it has to be held somewhere until the rest arrives.
    ///
    /// # Errors
    ///
    /// [`FrameError::Poisoned`] if the decoder has already failed.
    pub fn push(&mut self, input: &Bytes) -> Result<(), FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }

        // Carry-over wins.
        //
        // While anything is left over from an earlier read, new bytes must join *it* rather than
        // replace it: the stream is ordered, so a partial frame has to be completed before a later
        // frame can be looked at. Assigning `head` instead would silently drop the partial frame's
        // first bytes, which shows up later as a length read from the middle of a message.
        if self.head.as_ref().is_some_and(|head| !head.is_empty()) || !self.scratch.is_empty() {
            self.absorb_into_scratch(input);
        }
        else {
            self.head = Some(input.clone());
        }
        Ok(())
    }

    /// Moves whatever remains in `head` into `scratch`, then appends `input`.
    fn absorb_into_scratch(&mut self, input: &Bytes) {
        if let Some(rest) = self.head.take()
            && !rest.is_empty()
        {
            self.scratch.extend_from_slice(&rest);
        }
        self.scratch.extend_from_slice(input);
    }

    /// Appends bytes from a slice, for tests and callers without a [`Bytes`].
    ///
    /// # Errors
    ///
    /// As [`Self::push`].
    pub fn push_slice(&mut self, input: &[u8]) -> Result<(), FrameError> {
        self.push(&Bytes::copy_from_slice(input))
    }

    /// Returns the next complete frame, or `None` if more bytes are needed.
    ///
    /// On `Err` the decoder is poisoned and the caller must close the link.
    ///
    /// # Errors
    ///
    /// Any [`FrameError`] variant.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }

        // The scratch buffer holds a frame that arrived in pieces, plus anything queued behind it.
        // It is drained before the head is touched, because the stream is ordered.
        if !self.scratch.is_empty() {
            return self.advance_scratch();
        }

        let Some(head) = self.head.clone() else {
            return Ok(None);
        };

        if head.len() < FRAME_HEADER_LEN {
            // Too short for a header. Move it to scratch, because a `Bytes` cannot be extended.
            self.scratch.extend_from_slice(&head);
            self.head = None;
            return Ok(None);
        }

        let Some(header) = read_header(&head) else {
            return Ok(None);
        };

        // The declared length is validated before waiting for the body, so a peer cannot make us
        // buffer an arbitrarily large frame: a claim above the ceiling is refused the moment the
        // header arrives, rather than after the memory has been committed.
        if let Err(error) = validate_declared(header.declared, self.max_frame) {
            return Err(self.poison(error));
        }

        let total = FRAME_HEADER_LEN + header.body_len();
        if head.len() < total {
            // Valid header, incomplete body. Keep what arrived and wait.
            self.scratch.extend_from_slice(&head);
            self.head = None;
            return Ok(None);
        }

        // The fast path: a whole frame is present, so it is sliced rather than copied.
        self.head = Some(head.slice(total..));
        match build_frame(&head.slice(..total), header) {
            Ok(frame) => Ok(Some(frame)),
            Err(error) => Err(self.poison(error)),
        }
    }

    /// Consumes one frame from the scratch buffer, if a whole one is present.
    fn advance_scratch(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.scratch.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        // A `Bytes` view for header reading, so the borrow does not conflict with the later
        // `split_to`. `clone().freeze()` is O(1): it shares the allocation.
        let view = self.scratch.clone().freeze();
        let Some(header) = read_header(&view) else {
            return Ok(None);
        };

        if let Err(error) = validate_declared(header.declared, self.max_frame) {
            return Err(self.poison(error));
        }

        let total = FRAME_HEADER_LEN + header.body_len();
        if self.scratch.len() < total {
            return Ok(None);
        }

        // `split_to` advances an offset; `freeze` makes the result a shared slice, so the frame body
        // borrows the scratch allocation rather than a copy of it.
        let frame_region = self.scratch.split_to(total).freeze();

        // Once the scratch buffer is drained, stop using it entirely and go back to slicing the
        // head. Following this rule in `push` as well is what keeps the two in step: a drained
        // scratch means "the next read may go straight to head".
        if self.scratch.is_empty() {
            self.scratch = BytesMut::with_capacity(8 * 1024);
        }

        match build_frame(&frame_region, header) {
            Ok(frame) => Ok(Some(frame)),
            Err(error) => Err(self.poison(error)),
        }
    }

    /// Marks the decoder unusable and returns the error unchanged.
    fn poison(&mut self, error: FrameError) -> FrameError {
        self.poisoned = true;
        self.head = None;
        error
    }

    /// Drops the reference to the last read and clears the scratch length.
    ///
    /// Keeps the scratch allocation so the next partial frame reuses it, and does not zero it: the
    /// bytes are about to be overwritten.
    pub fn recycle(&mut self) {
        self.scratch.clear();
        self.head = None;
    }

    /// Frees both buffers and marks the decoder unusable, for a link being torn down.
    ///
    /// Poisoning on release is deliberate: a decoder belonging to a dead link must not be handed to
    /// a new one, because leftover bytes from the old stream would be read as the new stream's first
    /// frame.
    pub fn release(&mut self) {
        self.scratch = BytesMut::new();
        self.head = None;
        self.poisoned = true;
    }
}

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
