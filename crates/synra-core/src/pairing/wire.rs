//! How one pairing message travels over a socket.
//!
//! # Why a shared frame rather than JSON on the socket
//!
//! A socket is a byte stream, not a message stream: two writes can arrive as one read, and one write can arrive in
//! pieces. A reader that assumed one read equals one message would corrupt the moment a message straddled a packet
//! boundary — which happens on the very first real network, never in a test. So every message is a four-byte big-endian
//! length followed by exactly that many bytes, the same shape `pairing::confirmation` already uses on this ALPN.
//!
//! # Why a size limit is part of the format rather than a check later
//!
//! The length prefix is written by whoever connected, including a device that has not been approved yet — the whole point
//! of first pairing. Reading `length` bytes into a buffer before checking it lets that device ask this one to allocate
//! whatever it likes. The limit therefore belongs here, where the number is read, so no caller can forget it.

use std::io::{Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The largest pairing message accepted, matching the consent record's ceiling.
///
/// A pairing message carries a device profile and a request id — under a kilobyte in practice. The limit is four orders of
/// magnitude above that, which is room for a name in any script without being room to exhaust memory.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// What can go wrong on a pairing socket.
#[derive(Debug)]
pub enum WireError {
    /// The peer closed the connection, or the operating system reported a failure.
    Io,
    /// The frame was empty, over the limit, or its body was not the message expected.
    Malformed,
    /// Both sides agreed, but the durable grant that makes the agreement matter was refused.
    ///
    /// # Why this is not folded into `Io`
    ///
    /// The connection worked. What failed is the record that turns a conversation into permission, and a caller that saw
    /// `Io` would go looking at networks for a fault that lives in the trust journal — or, worse, would report a pairing
    /// as complete while the two devices still refuse each other.
    Trust,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Io => "the pairing connection failed",
            Self::Malformed => "the pairing message was not understood",
            Self::Trust => "the pairing agreement could not be recorded",
        })
    }
}

impl std::error::Error for WireError {}

/// Writes one message as a length-prefixed frame.
///
/// # Errors
///
/// [`WireError::Malformed`] when the encoded body exceeds [`MAX_MESSAGE_BYTES`], [`WireError::Io`] otherwise.
pub fn write<T: Serialize>(stream: &mut impl Write, message: &T) -> Result<(), WireError> {
    let bytes = serde_json::to_vec(message).map_err(|_| WireError::Malformed)?;
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::Malformed);
    }
    let size = u32::try_from(bytes.len()).map_err(|_| WireError::Malformed)?;
    stream.write_all(&size.to_be_bytes()).map_err(|_| WireError::Io)?;
    stream.write_all(&bytes).map_err(|_| WireError::Io)?;
    stream.flush().map_err(|_| WireError::Io)
}

/// Reads one length-prefixed frame and decodes it.
///
/// # Errors
///
/// [`WireError::Malformed`] when the size is zero, over the limit, or the body is not this message, [`WireError::Io`]
/// otherwise — including a peer that closes before finishing a frame.
pub fn read<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T, WireError> {
    let mut header = [0; 4];
    // `read_exact`, not `read`: a partial header is not an empty message, it is a connection that failed mid-frame.
    stream.read_exact(&mut header).map_err(|_| WireError::Io)?;
    let size = usize::try_from(u32::from_be_bytes(header)).map_err(|_| WireError::Malformed)?;
    if size == 0 || size > MAX_MESSAGE_BYTES {
        return Err(WireError::Malformed);
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).map_err(|_| WireError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| WireError::Malformed)
}