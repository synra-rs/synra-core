//! Stateless frame encoding and shape validation.

use bytes::{BufMut, Bytes, BytesMut};

use super::{Frame, FrameBody, FrameError, FrameKind, MAX_CHUNK_LEN, MAX_FRAME_LEN, FRAME_HEADER_LEN};

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




