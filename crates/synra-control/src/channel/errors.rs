//! Channel framing errors.

/// Why a message could not be framed or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelError {
    /// A message is longer than [`MAX_MESSAGE_LEN`].
    #[error("a message of {len} bytes exceeds the limit of {max}")]
    TooLong {
        /// How long it claimed to be.
        len: usize,
        /// The ceiling.
        max: usize,
    },

    /// A message's body was not valid JSON for its type.
    #[error("a message could not be read: {why}")]
    Malformed {
        /// What the parser said.
        why: String,
    },

    /// The client speaks a protocol version this kernel does not.
    #[error("the client speaks protocol {client}, this kernel speaks {kernel}")]
    VersionMismatch {
        /// What the client sent.
        client: u16,
        /// What this build speaks.
        kernel: u16,
    },
}


