//! The frames the exchange is made of: reading one, writing one, and the JSON a handshake message travels as.

use bytes::Bytes;
use synra_protocol::frame::{Frame, FrameBody, FrameDecoder, FrameEncoder, FrameKind};
use synra_protocol::handshake::{Hello, HelloAck};

use super::config::Flags;
use super::errors::HandshakeError;
use crate::link::LinkStream;

/// Reads one frame into a buffer, or reports why it could not.
///
/// # Why a chunked read rather than `read_exact`
///
/// A frame's length is in its header, so the body length is only known after the header arrives. A `read_exact` of the
/// whole frame would need the length first, and a decoder that peeked at four bytes would be one that has to handle a
/// partial header anyway. So the loop reads what is there and lets the decoder decide when it has a whole frame —
/// which is the same shape a socket always requires.
pub(super) fn read_frame(
    stream: &mut impl LinkStream,
    decoder: &mut FrameDecoder,
    flags: Flags,
) -> Result<Frame, HandshakeError> {
    if let Some(timeout) = flags.timeout {
        stream
            .set_read_deadline(timeout)
            .map_err(|error| link_error(&error))?;
    }

    let mut buffer = [0u8; 8 * 1024];
    loop {
        if let Some(frame) = decoder.next_frame()? {
            return Ok(frame);
        }
        let read = match stream.read(&mut buffer) {
            Ok(0) => return Err(HandshakeError::Closed),
            Ok(read) => read,
            // ★ A peer that went away is one condition, and the platform decides how many ways it spells it. Classifying
            // only the clean end-of-file made this report a transport fault for an ordinary hang-up on Windows.
            Err(error) if peer_went_away(&error) => return Err(HandshakeError::Closed),
            Err(error) => return Err(transport(&error)),
        };
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| transport_message("a read reported more bytes than the buffer"))?;
        // ★ The result is propagated, and dropping it was the first version: a poisoned decoder then reported "no frame
        // yet" for ever, so a peer that sent a malformed frame produced a read loop that never ended rather than a
        // refused connection. `?` is what turns it into the refusal it is.
        decoder.push_slice(chunk)?;
    }
}

/// Writes one frame.
pub(super) fn write_frame(
    stream: &mut impl LinkStream,
    frame: &Frame,
) -> Result<(), HandshakeError> {
    let bytes = FrameEncoder::encode_to_vec(frame)?;
    stream
        .write_all(&bytes)
        .and_then(|()| stream.flush())
        .map_err(|error| transport(&error))
}

pub(super) fn link_error(error: &crate::link::LinkError) -> HandshakeError {
    match error {
        crate::link::LinkError::Unauthorized
        | crate::link::LinkError::AuthorizationUnavailable { .. } => {
            HandshakeError::Authorization {
                why: error.to_string(),
            }
        }
        _ => HandshakeError::Transport {
            why: error.to_string(),
        },
    }
}

/// A `Hello` frame carrying its JSON.
///
/// # Why the body is `Hello` and not `Envelope`
///
/// The protocol pairs each frame kind with its own body variant, and a mismatch is refused by the encoder with
/// `BodyKindMismatch` — which is what the first version of this did. The two are distinct on purpose: a frame's kind is
/// checked without parsing its body, so a peer that had to read the JSON to know it was a hello would be one that
/// allocated for every frame it intended to route.
pub(super) fn hello_frame(hello: &Hello) -> Result<Frame, HandshakeError> {
    let bytes = encode_json(hello)?;
    Ok(Frame {
        kind: FrameKind::Hello,
        flags: 0,
        body: FrameBody::Hello(Bytes::from(bytes)),
    })
}

/// A `HelloAck` frame carrying its JSON.
pub(super) fn hello_ack_frame(ack: &HelloAck) -> Result<Frame, HandshakeError> {
    let bytes = encode_json(ack)?;
    Ok(Frame {
        kind: FrameKind::HelloAck,
        flags: 0,
        body: FrameBody::HelloAck(Bytes::from(bytes)),
    })
}

/// Serialises a handshake message.
fn encode_json(value: &impl serde::Serialize) -> Result<Vec<u8>, HandshakeError> {
    serde_json::to_vec(value).map_err(|error| HandshakeError::Payload {
        message: "handshake",
        why: error.to_string(),
    })
}

/// The JSON in a handshake frame, whichever of the two bodies it is.
///
/// # Why this accepts both variants
///
/// The dialer reads a `HelloAck` and the acceptor reads a `Hello`, and each is a different body variant. One reader for
/// both keeps the exchange in one place; a reader per direction would be two places the JSON is parsed, and the second
/// is where a field added to one message and not the other goes unnoticed.
pub(super) fn json_payload<T: for<'de> serde::Deserialize<'de>>(
    frame: &Frame,
    message: &'static str,
) -> Result<T, HandshakeError> {
    let bytes = match &frame.body {
        FrameBody::Hello(bytes) | FrameBody::HelloAck(bytes) => bytes,
        other => {
            return Err(HandshakeError::Unexpected {
                expected: message,
                found: format!("{other:?}"),
            });
        }
    };
    serde_json::from_slice(bytes).map_err(|error| HandshakeError::Payload {
        message,
        why: error.to_string(),
    })
}

/// Checks the frame is the kind the exchange expects.
pub(super) fn expect(
    frame: &Frame,
    kind: FrameKind,
    expected: &'static str,
) -> Result<(), HandshakeError> {
    if frame.kind == kind {
        return Ok(());
    }
    Err(HandshakeError::Unexpected {
        expected,
        found: frame.kind.to_string(),
    })
}
/// Whether an error means the peer went away rather than that something is wrong.
///
/// # Why the error *kind* is not enough
///
/// Windows reports an abortive close as `WSAECONNABORTED` (10053) and a reset as `WSAECONNRESET` (10054), and the two do
/// not map to the same [`std::io::ErrorKind`] — which is what the first version of this matched on, so one of them came
/// through as a transport fault. A hang-up is one condition; how many codes a platform spells it with is the platform's
/// business, so the codes are named here and the kinds are checked as well for the platforms where they carry it.
pub(crate) fn peer_went_away(error: &std::io::Error) -> bool {
    // 10053 and 10054 are Winsock's, and the codes are stable. Named rather than imported, because naming them makes the
    // reason visible — and a reader who does not know them can look them up.
    const WSAECONNABORTED: i32 = 10053;
    const WSAECONNRESET: i32 = 10054;

    if error
        .raw_os_error()
        .is_some_and(|code| code == WSAECONNABORTED || code == WSAECONNRESET)
    {
        return true;
    }
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// An operating-system error, as a transport failure.
pub(super) fn transport(error: &std::io::Error) -> HandshakeError {
    if let Some(cause) = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<crate::link::LinkError>())
    {
        return link_error(cause);
    }
    transport_message(&error.to_string())
}

/// A message, as a transport failure.
fn transport_message(why: &str) -> HandshakeError {
    HandshakeError::Transport {
        why: why.to_owned(),
    }
}
