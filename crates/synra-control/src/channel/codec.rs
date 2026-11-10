//! Length-prefixed JSON encoding and incremental decoding.

use serde::{Deserialize, Serialize};

use super::{ChannelError, HEADER_LEN, MAX_MESSAGE_LEN, PROTOCOL_VERSION};

/// Frames messages for a stream, and reads them back.
///
/// # Why a decoder rather than a `read_exact` helper
///
/// A socket delivers bytes, not messages: a read may return half a frame, three frames, or two and a half. A helper
/// that read exactly a header and then exactly a body would work against a file and fail against a socket under load —
/// and it would fail intermittently, which is the shape of bug that survives review. So the decoder buffers, and
/// [`Decoder::next_message`] returns `None` when there is not yet a whole one.
#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
    /// Set on the first failure. Once set, every operation reports it.
    ///
    /// # Why a decoder poisons itself
    ///
    /// A framing error leaves the stream in an unknown position: the bytes that follow a length that was wrong are not
    /// where the next header is. Continuing would read a body as a header, and the failure would present as nonsense
    /// several messages later rather than as the one bad frame that caused it.
    poisoned: Option<ChannelError>,
}

impl Decoder {
    /// A decoder with nothing buffered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.poisoned.is_none() {
            self.buffer.extend_from_slice(bytes);
        }
    }

    /// How many bytes are buffered.
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the decoder has refused a frame and will refuse everything after it.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    /// Reads the next whole message, if there is one.
    ///
    /// # The order of the checks
    ///
    /// The length is checked against the ceiling **before** the body is waited for, so a client that claims a
    /// four-gigabyte message is refused immediately rather than after the kernel has waited for bytes that will never
    /// come.
    ///
    /// # Errors
    ///
    /// [`ChannelError::TooLong`] for a length beyond the ceiling, and [`ChannelError::Malformed`] for a body that is
    /// not the expected JSON. Both poison the decoder.
    pub fn next_message<T: for<'de> Deserialize<'de>>(
        &mut self,
    ) -> Result<Option<T>, ChannelError> {
        if let Some(error) = &self.poisoned {
            return Err(error.clone());
        }

        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }

        // `get` rather than a slice: the workspace denies `indexing_slicing` because a slice may panic, and the length
        // was checked one statement earlier — a check the compiler cannot see through, which is exactly why the rule is
        // "no slicing" rather than "slice only when you are sure".
        let Some(header) = self
            .buffer
            .get(..HEADER_LEN)
            .and_then(|bytes| bytes.try_into().ok())
        else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(header) as usize;

        if len > MAX_MESSAGE_LEN {
            let error = ChannelError::TooLong {
                len,
                max: MAX_MESSAGE_LEN,
            };
            self.poisoned = Some(error.clone());
            return Err(error);
        }

        if self.buffer.len() < HEADER_LEN + len {
            return Ok(None);
        }

        let Some(body) = self
            .buffer
            .get(HEADER_LEN..HEADER_LEN + len)
            .map(<[u8]>::to_vec)
        else {
            return Ok(None);
        };
        self.buffer.drain(..HEADER_LEN + len);

        match serde_json::from_slice(&body) {
            Ok(message) => Ok(Some(message)),
            Err(error) => {
                let failure = ChannelError::Malformed {
                    why: error.to_string(),
                };
                self.poisoned = Some(failure.clone());
                Err(failure)
            }
        }
    }
}

/// Frames a message for a stream.
///
/// # Errors
///
/// [`ChannelError::Malformed`] when the message cannot be serialised, and [`ChannelError::TooLong`] when it does not
/// fit. The length is checked **after** serialising, because that is the only point at which it is known — and a
/// client that checked beforehand would be checking a guess.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, ChannelError> {
    let body = serde_json::to_vec(message).map_err(|error| ChannelError::Malformed {
        why: error.to_string(),
    })?;
    if body.len() > MAX_MESSAGE_LEN {
        return Err(ChannelError::TooLong {
            len: body.len(),
            max: MAX_MESSAGE_LEN,
        });
    }

    let len = u32::try_from(body.len()).map_err(|_| ChannelError::TooLong {
        len: body.len(),
        max: MAX_MESSAGE_LEN,
    })?;

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Whether a client and this kernel can talk.
///
/// # Errors
///
/// [`ChannelError::VersionMismatch`], which names both versions. A client and a kernel are separate binaries that may
/// be upgraded separately, so this is an ordinary condition rather than a programming error.
pub const fn check_version(client: u16) -> Result<(), ChannelError> {
    if client == PROTOCOL_VERSION {
        return Ok(());
    }
    Err(ChannelError::VersionMismatch {
        client,
        kernel: PROTOCOL_VERSION,
    })
}


