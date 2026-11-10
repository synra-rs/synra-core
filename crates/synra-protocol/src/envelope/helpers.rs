//! Envelope validation, wire parsing and stable error mapping.

use core::fmt;

use bytes::Bytes;
use serde::Serialize;
use serde_json::value::RawValue;

use crate::error::{ErrorCode, SynraError};
use crate::ids::DeviceId;
use crate::limits::{MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_LEN};

use super::{Envelope, EnvelopeError};

/// How long ago `sent_at_ms` was, from the point of view of a receiver whose clock reads `now_ms`.
///
/// A sender whose clock runs fast produces a negative difference, and the answer is zero rather than
/// a negative duration or a wrapped one. Reading "from the future" as "nothing has elapsed yet" is
/// the safe direction: a message with a skewed timestamp then lives for at most its TTL measured
/// from when it arrives, instead of living forever because the arithmetic wrapped.
///
/// The difference is saturated, so a clock set decades away cannot overflow the subtraction.
pub(super) fn elapsed_ms(sent_at_ms: i64, now_ms: i64) -> i64 {
    now_ms.saturating_sub(sent_at_ms).max(0)
}

impl fmt::Display for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}→{} ({})",
            self.event, self.from, self.target, self.request_id
        )
    }
}

impl PartialEq for Envelope {
    /// Compares two envelopes by what they say, not by how they were spelled.
    fn eq(&self, other: &Self) -> bool {
        self.request_id == other.request_id
            && self.event == other.event
            && self.target == other.target
            && self.from == other.from
            && self.reply_to == other.reply_to
            && self.trace_id == other.trace_id
            && self.sent_at_ms == other.sent_at_ms
            && self.ttl_ms == other.ttl_ms
            && raw_json_eq(self.payload.as_deref(), other.payload.as_deref())
    }
}

impl Eq for Envelope {}

/// Compares two optional raw JSON payloads by value rather than by spelling.
///
/// Hand-written because `RawValue` has no `PartialEq`: it stores text, so a derived comparison would
/// compare bytes. Two peers can encode the same JSON with different key order or whitespace, and a
/// round-trip assertion should call those equal.
///
/// Parsing is the price. Acceptable because this is used by tests and by diagnostic comparisons, not
/// on the hot path: routing never compares payloads.
///
/// Shared with the session types, which carry raw JSON in the same way and would otherwise each need
/// their own copy of this reasoning.
pub(crate) fn raw_json_eq(mine: Option<&RawValue>, theirs: Option<&RawValue>) -> bool {
    match (mine, theirs) {
        (None, None) => true,
        (Some(mine), Some(theirs)) => {
            match (
                serde_json::from_str::<serde_json::Value>(mine.get()),
                serde_json::from_str::<serde_json::Value>(theirs.get()),
            ) {
                (Ok(mine), Ok(theirs)) => mine == theirs,
                // Unparseable payloads cannot be compared structurally, so fall back to the text.
                // Still better than reporting equality for different bytes.
                _ => mine.get() == theirs.get(),
            }
        }
        _ => false,
    }
}

/// Serialises a payload, enforcing the size and depth ceilings.
pub(super) fn encode_payload<P>(payload: Option<&P>) -> Result<Option<Box<RawValue>>, EnvelopeError>
where
    P: ?Sized + Serialize,
{
    let Some(payload) = payload else {
        return Ok(None);
    };

    let text = serde_json::to_string(payload).map_err(|error| EnvelopeError::FieldType {
        detail: format!("payload cannot be serialised: {error}"),
    })?;

    if text.len() > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::PayloadTooLarge { len: text.len(), max: MAX_PAYLOAD_LEN });
    }
    check_depth(&text)?;

    let raw = RawValue::from_string(text).map_err(|_| EnvelopeError::MalformedPayload)?;
    Ok(Some(raw))
}

/// Counts nesting depth, so a pathological payload cannot make a consumer recurse without bound.
///
/// A byte scan rather than a parse: brackets and braces are structural in JSON, and scanning is
/// linear where parsing is not. Strings are tracked so a `{` inside one is not counted.
pub(super) fn check_depth(json: &str) -> Result<(), EnvelopeError> {
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escaped = false;

    for byte in json.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            }
            else if byte == b'\\' {
                escaped = true;
            }
            else if byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_PAYLOAD_DEPTH {
                    return Err(EnvelopeError::TooDeep { max: MAX_PAYLOAD_DEPTH });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    Ok(())
}

/// Turns an envelope problem into the error a peer should receive.
///
/// Kept here so every caller reports the same failure the same way. An envelope that is not for us
/// is a protocol violation rather than a user-facing problem: the local user did nothing wrong.
#[must_use]
pub fn envelope_error_to_synra(error: &EnvelopeError) -> SynraError {
    match error {
        EnvelopeError::NotForUs { .. }
        | EnvelopeError::UnknownReply { .. }
        | EnvelopeError::NotUtf8
        | EnvelopeError::MalformedPayload => {
            SynraError::new(ErrorCode::ProtocolViolation, error.to_string())
        }
        EnvelopeError::PayloadTooLarge { .. } => {
            SynraError::new(ErrorCode::PayloadTooLarge, error.to_string())
        }
        EnvelopeError::MissingField { .. }
        | EnvelopeError::FieldType { .. }
        | EnvelopeError::NilField { .. }
        | EnvelopeError::TooDeep { .. } => {
            SynraError::new(ErrorCode::InvalidArgument, error.to_string())
        }
    }
}

/// Parses an envelope from bytes, for a caller holding a frame body.
///
/// # Errors
///
/// [`EnvelopeError::NotUtf8`] if the bytes are not text, plus as [`Envelope::inbound`].
pub fn parse_envelope(bytes: &Bytes, local: DeviceId) -> Result<Envelope, EnvelopeError> {
    let text = core::str::from_utf8(bytes).map_err(|_| EnvelopeError::NotUtf8)?;
    let raw = RawValue::from_string(text.to_owned()).map_err(|_| EnvelopeError::MalformedPayload)?;
    Envelope::inbound(&raw, local)
}


