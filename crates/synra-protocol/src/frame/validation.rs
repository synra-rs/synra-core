//! Shared validation for frame headers and bodies.

use bytes::{Buf, Bytes};

use super::{ChunkFrame, FrameBody, FrameEncoder, FrameError, FrameKind, MAX_CHUNK_LEN};

/// Validates the length field on its own, before any body bytes are waited for.
///
/// Separated from the rest of the header handling because it is the security-relevant check: it runs
/// on the strength of the header alone, so a hostile or corrupt length can never make the buffer
/// grow.
pub(super) const fn validate_declared(declared: u32, max_frame: u32) -> Result<(), FrameError> {
    if declared < FrameEncoder::MIN_DECLARED {
        return Err(FrameError::Truncated { len: declared, min: FrameEncoder::MIN_DECLARED });
    }
    if declared > max_frame {
        return Err(FrameError::TooLarge { len: declared, max: max_frame });
    }
    Ok(())
}

/// Rejects frames whose body does not fit their kind.
pub(super) const fn validate_shape(kind: FrameKind, body_len: usize) -> Result<(), FrameError> {
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
pub(super) fn build_body(kind: FrameKind, body: Bytes) -> Result<FrameBody, FrameError> {
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




