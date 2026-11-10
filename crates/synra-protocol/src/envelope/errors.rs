//! Errors raised while constructing or reading an envelope.

use crate::ids::{DeviceId, RequestId};

/// Everything that can go wrong while constructing or parsing an envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The payload exceeds [`MAX_PAYLOAD_LEN`].
    #[error("payload of {len} bytes exceeds the ceiling {max}")]
    PayloadTooLarge {
        /// Observed size.
        len: usize,
        /// The ceiling.
        max: usize,
    },

    /// The payload nests more deeply than [`MAX_PAYLOAD_DEPTH`].
    #[error("payload nests deeper than {max} levels")]
    TooDeep {
        /// The ceiling.
        max: u32,
    },

    /// A field was missing.
    #[error("missing required field: {field}")]
    MissingField {
        /// Field name as it appears on the wire.
        field: &'static str,
    },

    /// A field had the wrong JSON type, or the document was not an object.
    #[error("cannot read envelope: {detail}")]
    FieldType {
        /// What was wrong.
        detail: String,
    },

    /// The bytes are not valid UTF-8, so they cannot be JSON.
    #[error("envelope bytes are not valid UTF-8")]
    NotUtf8,

    /// The payload is not valid JSON.
    #[error("payload is not valid JSON")]
    MalformedPayload,

    /// `target` is not this device.
    #[error("target {target} is not this device ({local})")]
    NotForUs {
        /// The address the message was sent to.
        target: DeviceId,
        /// This device.
        local: DeviceId,
    },

    /// A field that must not be nil was.
    #[error("field {field} must not be nil")]
    NilField {
        /// Field name as it appears on the wire.
        field: &'static str,
    },

    /// The message this replies to is not one we sent.
    #[error("replyTo {reply_to} does not match a request we made")]
    UnknownReply {
        /// The id that did not match.
        reply_to: RequestId,
    },
}


