//! The message layer: who sent what to whom.
//!
//! An envelope is the fixed set of fields that wraps every message. It is the contract between two
//! peers, so it changes only by the protocol's own evolution rules: a field may be added, an event
//! name may be added, and a field's *meaning* may not change without raising the protocol number.
//!
//! # Nine fields, and no more
//!
//! `requestId`, `event`, `target`, `from`, `replyTo`, `traceId`, `payload`, `sentAtMs`, `ttlMs`.
//! Adding a tenth means changing both this crate and the design document. That strictness is the
//! point: the field list is short enough to hold in your head, which is what makes it possible to
//! reason about what a peer can and cannot say.
//!
//! [`Envelope`] rejects unknown fields outright. A peer that sends an extra field is violating the
//! protocol, and accepting it would mean two implementations quietly disagreeing about what a valid
//! message is.
//!
//! # Payloads are moved, not read
//!
//! [`Envelope::payload`] is a [`RawValue`], not a `serde_json::Value`. The kernel's job is to check
//! the envelope, route it, and hand it on — it rarely needs to understand the payload, and building
//! a `Value` tree for every message would allocate per field, per frame. `RawValue` keeps the bytes
//! as they arrived: syntax is validated once, and only the party that actually reads a field pays
//! for parsing it.
//!
//! # There is one way to build an envelope
//!
//! [`Envelope::outbound`], [`Envelope::reply_to`] and [`Envelope::inbound`] are the only
//! constructors. A caller cannot set `traceId`, `from` or `target` itself — those are the fields a
//! call site would get wrong, and getting one wrong produces a message that cannot be correlated
//! with anything.

use core::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::{ErrorCode, SynraError};
use crate::event::EventName;
use crate::ids::{DeviceId, RequestId, TraceId};
use crate::limits::{MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_LEN};

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

/// The fixed set of fields every message carries.
///
/// Field names are camelCase on the wire, matching the rest of the protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    /// Identifies this send, so an acknowledgement and a reply can be correlated with it.
    ///
    /// A retry reuses the id. That is what makes redelivery idempotent rather than a second
    /// execution.
    pub request_id: RequestId,

    /// What the message is about.
    pub event: EventName,

    /// The device this was addressed to.
    pub target: DeviceId,

    /// The device that sent it. A receiver must check it matches the link's peer.
    pub from: DeviceId,

    /// The request this answers, if it is an answer.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reply_to: Option<RequestId>,

    /// Shared by every step of one user action.
    pub trace_id: TraceId,

    /// The message body, as raw JSON.
    ///
    /// Not parsed unless a consumer asks: see the module docs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload: Option<Box<RawValue>>,

    /// Sender's clock, in milliseconds. For logs and ordering only.
    ///
    /// Never used for timeout decisions: two devices' clocks disagree, and one of them may be wrong
    /// by hours. Timeouts are measured with a local monotonic clock, and a TTL is compared as a
    /// duration rather than as an absolute time.
    pub sent_at_ms: i64,

    /// How long the message stays interesting, in milliseconds. Past this, a receiver may drop it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttl_ms: Option<u32>,
}

/// The fields a caller must supply to send a message.
///
/// A parameter struct rather than positional arguments: `from` and `target` are both `DeviceId`, so
/// a swapped pair would compile and produce a message addressed to nobody.
#[derive(Debug, Clone)]
pub struct OutboundSpec {
    /// What the message is about.
    pub event: EventName,
    /// Who it is for.
    pub target: DeviceId,
    /// Who is sending it.
    pub from: DeviceId,
    /// Shared trace for this user action.
    pub trace_id: TraceId,
    /// Sender's clock, in milliseconds.
    pub sent_at_ms: i64,
    /// Optional lifetime, in milliseconds.
    pub ttl_ms: Option<u32>,
}

impl Envelope {
/// Builds an outgoing message.
    ///
    /// The payload is serialised once, straight into its wire form. Passing `&impl Serialize` rather
    /// than a `serde_json::Value` avoids building a tree only to flatten it again.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::PayloadTooLarge`] if the serialised payload exceeds the ceiling,
    /// [`EnvelopeError::TooDeep`] if it nests too far, or [`EnvelopeError::FieldType`] if it cannot
    /// be serialised at all.
    pub fn outbound<P>(spec: OutboundSpec, payload: Option<&P>) -> Result<Self, EnvelopeError>
    where
        P: ?Sized + Serialize,
    {
        Ok(Self {
            request_id: RequestId::new(),
            event: spec.event,
            target: spec.target,
            from: spec.from,
            reply_to: None,
            trace_id: spec.trace_id,
            payload: encode_payload(payload)?,
            sent_at_ms: spec.sent_at_ms,
            ttl_ms: spec.ttl_ms,
        })
    }

    /// Builds a reply to `request`.
    ///
    /// Inherits the trace so both halves of an exchange land under one id, and sets `replyTo` so the
    /// originator can match it. The addressing is inverted here rather than left to the caller:
    /// getting `from` and `target` the wrong way round in a reply produces a message nobody can
    /// route.
    ///
    /// # Errors
    ///
    /// As [`Self::outbound`].
    pub fn reply_to<P>(
        request: &Self,
        event: EventName,
        local: DeviceId,
        sent_at_ms: i64,
        payload: Option<&P>,
    ) -> Result<Self, EnvelopeError>
    where
        P: ?Sized + Serialize,
    {
        Self::reply_parts(ReplyContext::of(request, local), event, sent_at_ms, payload)
    }

    /// Builds a reply from the facts a reply needs, when the request itself is no longer at hand.
    ///
    /// ★ **Why this exists beside [`Envelope::reply_to`].** The side that answers is often not the side that read the
    /// request: in the daemon the bytes were consumed by a transfer that has already landed, and what survives is a
    /// [`ReplyContext`]. Requiring the whole envelope would make every reader keep one — payload included.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError`] when the payload cannot be encoded, as in [`Envelope::reply_to`].
    pub fn reply_parts<P>(
        context: ReplyContext,
        event: EventName,
        sent_at_ms: i64,
        payload: Option<&P>,
    ) -> Result<Self, EnvelopeError>
    where
        P: ?Sized + Serialize,
    {
        Ok(Self {
            request_id: RequestId::new(),
            event,
            target: context.target,
            from: context.from,
            reply_to: Some(context.request_id),
            trace_id: context.trace_id,
            payload: encode_payload(payload)?,
            sent_at_ms,
            // The reply is only interesting for as long as the question was.
            ttl_ms: context.ttl_ms,
        })
    }

    /// Parses an incoming message and checks it is addressed to us.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::NotForUs`] if `target` is a different device, plus every well-formedness
    /// error. A message for somebody else has arrived at the wrong place, which means routing tables
    /// disagree; refusing it is more useful than accepting and ignoring it.
    pub fn inbound(raw: &RawValue, local: DeviceId) -> Result<Self, EnvelopeError> {
        let envelope = Self::inbound_any(raw)?;
        envelope.validate(local)?;
        Ok(envelope)
    }

    /// Parses without checking the target, for a relay that forwards to another device.
    ///
    /// # Errors
    ///
    /// Every well-formedness error except [`EnvelopeError::NotForUs`].
    pub fn inbound_any(raw: &RawValue) -> Result<Self, EnvelopeError> {
        serde_json::from_str(raw.get()).map_err(|error| EnvelopeError::FieldType {
            detail: error.to_string(),
        })
    }

    /// Checks the invariants that do not depend on routing state.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::NotForUs`], [`EnvelopeError::NilField`] or
    /// [`EnvelopeError::PayloadTooLarge`].
    pub fn validate(&self, local: DeviceId) -> Result<(), EnvelopeError> {
        if self.target != local {
            return Err(EnvelopeError::NotForUs { target: self.target, local });
        }
        if self.from.is_nil() {
            return Err(EnvelopeError::NilField { field: "from" });
        }
        if self.trace_id.is_zero() {
            return Err(EnvelopeError::NilField { field: "traceId" });
        }
        if let Some(payload) = &self.payload {
            let len = payload.get().len();
            if len > MAX_PAYLOAD_LEN {
                return Err(EnvelopeError::PayloadTooLarge { len, max: MAX_PAYLOAD_LEN });
            }
            check_depth(payload.get())?;
        }
        Ok(())
    }

    /// Checks a reply names a request we actually made.
    ///
    /// Kept separate from [`Self::validate`] because it needs the set of outstanding requests, which
    /// belongs to the session layer rather than to the envelope.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::UnknownReply`] if `replyTo` is set and the predicate rejects it.
    pub fn check_reply_to(
        &self,
        mut is_outstanding: impl FnMut(&RequestId) -> bool,
    ) -> Result<(), EnvelopeError> {
        if let Some(reply_to) = self.reply_to
            && !is_outstanding(&reply_to)
        {
            return Err(EnvelopeError::UnknownReply { reply_to });
        }
        Ok(())
    }

    /// The payload as text, for handing to a consumer that parses it itself.
    ///
    /// The interface layer passes this across the IPC boundary verbatim rather than re-serialising a
    /// parsed tree, so the browser parses it exactly once.
    #[must_use]
    pub fn payload_str(&self) -> Option<&str> {
        self.payload.as_ref().map(|payload| payload.get())
    }

    /// Whether a message still needs to be delivered.
    ///
    /// `now_ms` comes from the receiver's clock, not the sender's: a TTL is a *duration*, and
    /// durations are safe to compare across devices in a way that timestamps are not.
    #[must_use]
    pub fn is_expired(&self, now_ms: i64) -> bool {
        let Some(ttl) = self.ttl_ms else {
            return false;
        };
        elapsed_ms(self.sent_at_ms, now_ms) > i64::from(ttl)
    }
}

/// How long ago `sent_at_ms` was, from the point of view of a receiver whose clock reads `now_ms`.
///
/// A sender whose clock runs fast produces a negative difference, and the answer is zero rather than
/// a negative duration or a wrapped one. Reading "from the future" as "nothing has elapsed yet" is
/// the safe direction: a message with a skewed timestamp then lives for at most its TTL measured
/// from when it arrives, instead of living forever because the arithmetic wrapped.
///
/// The difference is saturated, so a clock set decades away cannot overflow the subtraction.
fn elapsed_ms(sent_at_ms: i64, now_ms: i64) -> i64 {
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
fn encode_payload<P>(payload: Option<&P>) -> Result<Option<Box<RawValue>>, EnvelopeError>
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
fn check_depth(json: &str) -> Result<(), EnvelopeError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::events;
    use serde_json::json;

    fn device() -> DeviceId {
        DeviceId::new()
    }

    fn spec(event: &str, from: DeviceId, target: DeviceId) -> OutboundSpec {
        OutboundSpec {
            event: EventName::parse(event).expect("valid event"),
            target,
            from,
            trace_id: TraceId::new(),
            sent_at_ms: 1_000,
            ttl_ms: None,
        }
    }

    /// Serialises and re-parses, which is what every assertion about the wire actually tests.
    fn round_trip(envelope: &Envelope, local: DeviceId) -> Result<Envelope, EnvelopeError> {
        let text = serde_json::to_string(envelope).expect("serialises");
        Envelope::inbound(&RawValue::from_string(text).expect("valid"), local)
    }

    #[test]
    fn outbound_sets_every_addressing_field() {
        let (from, target) = (device(), device());
        let envelope =
            Envelope::outbound(spec("device.ping", from, target), None::<&()>).expect("builds");

        assert_eq!(envelope.from, from);
        assert_eq!(envelope.target, target);
        assert!(envelope.reply_to.is_none());
        assert!(!envelope.trace_id.is_zero());
        assert!(envelope.payload.is_none());
    }

    #[test]
    fn a_reply_inverts_the_addressing_and_inherits_the_trace() {
        let (a, b) = (device(), device());
        let request = Envelope::outbound(spec("device.pairing.request", a, b), None::<&()>)
            .expect("builds");

        let reply = Envelope::reply_to(
            &request,
            EventName::parse("device.pairing.response").expect("valid"),
            b,
            2_000,
            None::<&()>,
        )
        .expect("builds");

        assert_eq!(reply.from, b, "a reply comes from the device that received the request");
        assert_eq!(reply.target, a, "and goes back to the device that asked");
        assert_eq!(reply.reply_to, Some(request.request_id));
        assert_eq!(reply.trace_id, request.trace_id, "both halves share one trace");
        // A reply is its own request, so it needs its own id.
        assert_ne!(reply.request_id, request.request_id);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let local = device();
        let text = format!(
            r#"{{"requestId":"{}","event":"device.ping","target":"{local}","from":"{}","traceId":"{}","sentAtMs":1,"extraField":1}}"#,
            RequestId::new(),
            device(),
            TraceId::new().to_hex(),
        );
        let raw = RawValue::from_string(text).expect("valid json");
        // Accepting an extra field would let two implementations disagree about what a valid message
        // is, and the disagreement would surface as a mysterious failure much later.
        assert!(Envelope::inbound(&raw, local).is_err());
    }

    #[test]
    fn a_message_for_another_device_is_refused() {
        let (a, b, c) = (device(), device(), device());
        let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
        let raw = RawValue::from_string(serde_json::to_string(&envelope).expect("serialises"))
            .expect("valid");

        assert!(matches!(
            Envelope::inbound(&raw, c),
            Err(EnvelopeError::NotForUs { .. })
        ));
        // But a relay can still read it, which is what makes forwarding possible at all.
        assert_eq!(Envelope::inbound_any(&raw).expect("parses").target, b);
    }

    #[test]
    fn wire_field_names_are_camel_case() {
        let (a, b) = (device(), device());
        let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
        let json = serde_json::to_string(&envelope).expect("serialises");

        for name in ["requestId", "traceId", "sentAtMs"] {
            assert!(json.contains(&format!("\"{name}\"")), "{name} missing from {json}");
        }
        for absent in ["request_id", "trace_id", "sent_at_ms"] {
            assert!(!json.contains(absent), "{absent} leaked into {json}");
        }
        // Optional fields are absent rather than null, so a reader never has to handle both.
        for absent in ["replyTo", "ttlMs", "payload"] {
            assert!(!json.contains(absent), "{absent} should be omitted, not null: {json}");
        }
    }

    #[test]
    fn a_payload_survives_as_its_original_text() {
        let (a, b) = (device(), device());
        let payload = json!({ "body": "hi", "n": 3 });
        let envelope =
            Envelope::outbound(spec("device.ping", a, b), Some(&payload)).expect("builds");

        let text = envelope.payload_str().expect("has a payload");
        // Not a re-serialised tree: the consumer parses exactly once.
        assert!(text.contains("\"body\":\"hi\""), "{text}");

        let parsed = round_trip(&envelope, b).expect("round trips");
        assert_eq!(parsed.payload_str(), Some(text));
    }

    #[test]
    fn an_oversized_payload_is_refused_at_construction() {
        let (a, b) = (device(), device());
        let big = "x".repeat(MAX_PAYLOAD_LEN + 1);
        assert!(matches!(
            Envelope::outbound(spec("device.ping", a, b), Some(&big)),
            Err(EnvelopeError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn a_deeply_nested_payload_is_refused() {
        let (a, b) = (device(), device());

        // One level deeper than allowed, as *real* nesting. Building it by wrapping a string would
        // produce one JSON string with brackets inside it, which is one level deep — the check would
        // never fire and the test would pass for the wrong reason.
        let mut nested = serde_json::Value::Null;
        for _ in 0..=MAX_PAYLOAD_DEPTH {
            nested = serde_json::Value::Array(vec![nested]);
        }

        assert!(matches!(
            Envelope::outbound(spec("device.ping", a, b), Some(&nested)),
            Err(EnvelopeError::TooDeep { .. })
        ));

        // Exactly at the ceiling is accepted, so the limit is inclusive and not off by one.
        let mut allowed = serde_json::Value::Null;
        for _ in 0..MAX_PAYLOAD_DEPTH {
            allowed = serde_json::Value::Array(vec![allowed]);
        }
        assert!(Envelope::outbound(spec("device.ping", a, b), Some(&allowed)).is_ok());
    }

    #[test]
    fn depth_counting_ignores_brackets_inside_strings() {
        // A payload whose *text* looks deeply nested but whose structure is flat. Counting bytes
        // without tracking strings would reject it.
        let (a, b) = (device(), device());
        let payload = json!({ "note": "{{{{[[[[ nested " });
        assert!(Envelope::outbound(spec("device.ping", a, b), Some(&payload)).is_ok());
    }

    #[test]
    fn escaping_inside_strings_does_not_confuse_depth_counting() {
        let (a, b) = (device(), device());
        let payload = json!({ "quote": "he said \"{\" loudly" });
        assert!(Envelope::outbound(spec("device.ping", a, b), Some(&payload)).is_ok());
    }

    #[test]
    fn a_nil_trace_is_refused() {
        let (a, b) = (device(), device());
        let envelope = Envelope {
            request_id: RequestId::new(),
            event: EventName::parse("device.ping").expect("valid"),
            target: b,
            from: a,
            reply_to: None,
            trace_id: TraceId(0),
            payload: None,
            sent_at_ms: 0,
            ttl_ms: None,
        };
        assert!(matches!(
            envelope.validate(b),
            Err(EnvelopeError::NilField { field: "traceId" })
        ));
    }

    #[test]
    fn ttl_is_measured_as_a_duration() {
        let (a, b) = (device(), device());
        let mut outbound = spec("device.ping", a, b);
        outbound.sent_at_ms = 1_000;
        outbound.ttl_ms = Some(500);
        let envelope = Envelope::outbound(outbound, None::<&()>).expect("builds");

        assert!(!envelope.is_expired(1_000), "not yet");
        assert!(!envelope.is_expired(1_500), "exactly at the deadline still counts");
        assert!(envelope.is_expired(1_501), "past it");

        // No ttl means it never expires.
        let endless = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
        assert!(!endless.is_expired(i64::MAX));
    }

    #[test]
    fn a_sender_clock_in_the_future_does_not_expire_a_message_immediately() {
        let (a, b) = (device(), device());
        let mut outbound = spec("device.ping", a, b);
        outbound.sent_at_ms = i64::MAX;
        outbound.ttl_ms = Some(1);
        let envelope = Envelope::outbound(outbound, None::<&()>).expect("builds");

        // A clock that runs fast must not make every message look already-expired, which would
        // silently break the device. The difference is clamped to zero, so the TTL is measured from
        // arrival instead — the message lives for its full second and no longer.
        assert!(!envelope.is_expired(0), "a future timestamp means nothing has elapsed yet");
        assert!(!envelope.is_expired(i64::MAX - 1), "still within its TTL");
        // And it does expire, rather than being kept alive by arithmetic that wrapped.
        assert!(envelope.sent_at_ms == i64::MAX && envelope.ttl_ms == Some(1));
    }

    #[test]
    fn reply_matching_is_the_callers_business() {
        let (a, b) = (device(), device());
        let request = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
        let reply = Envelope::reply_to(
            &request,
            EventName::parse("device.pong").expect("valid"),
            b,
            2_000,
            None::<&()>,
        )
        .expect("builds");

        let outstanding = request.request_id;
        assert!(reply.check_reply_to(|id| *id == outstanding).is_ok());
        // A reply naming a request we never made is a protocol violation, caught here rather than
        // silently accepted as an unsolicited message.
        assert!(matches!(
            reply.check_reply_to(|_| false),
            Err(EnvelopeError::UnknownReply { .. })
        ));
    }

    #[test]
    fn a_message_without_a_reply_to_always_passes_reply_matching() {
        let (a, b) = (device(), device());
        let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
        assert!(envelope.check_reply_to(|_| false).is_ok());
    }

    #[test]
    fn built_in_events_are_accepted_and_nonsense_is_not() {
        let (a, b) = (device(), device());
        assert!(Envelope::outbound(spec(events::PAIR_REQUEST, a, b), None::<&()>).is_ok());

        // `spec` asserts the name parses, so the negative cases check the parser directly.
        assert!(
            EventName::parse("nonsense").is_err(),
            "a bare word is in no known namespace",
        );
        assert!(
            EventName::parse("other.thing").is_err(),
            "an unknown namespace is not an event name",
        );

        // But a *valid* name this version does not define parses. That is deliberate: a newer peer
        // may send an event we have never heard of, and the inbound dispatcher records and ignores
        // it rather than closing the link. Parsing is a grammar check, not a catalogue lookup.
        assert!(EventName::parse("device.something-new").is_ok());
        assert!(EventName::parse("file.transfer.chunk").is_ok());
    }

    #[test]
    fn envelope_errors_map_to_stable_codes() {
        let too_large = EnvelopeError::PayloadTooLarge { len: 1, max: 0 };
        assert_eq!(envelope_error_to_synra(&too_large).code, ErrorCode::PayloadTooLarge);

        let wrong_device = EnvelopeError::NotForUs { target: device(), local: device() };
        assert_eq!(envelope_error_to_synra(&wrong_device).code, ErrorCode::ProtocolViolation);

        let missing = EnvelopeError::MissingField { field: "event" };
        assert_eq!(envelope_error_to_synra(&missing).code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn parse_from_bytes_matches_parse_from_text() {
        let (a, b) = (device(), device());
        let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
        let bytes = Bytes::from(serde_json::to_vec(&envelope).expect("serialises"));

        assert_eq!(parse_envelope(&bytes, b).expect("parses"), envelope);
    }

    #[test]
    fn invalid_utf8_is_refused() {
        let bytes = Bytes::from_static(&[0xFF, 0xFE, 0x00]);
        assert!(matches!(
            parse_envelope(&bytes, device()),
            Err(EnvelopeError::NotUtf8)
        ));
    }

    #[test]
    fn an_envelope_renders_readably_for_logs() {
        let (a, b) = (device(), device());
        let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
        let text = envelope.to_string();
        assert!(text.contains("device.ping"));
        assert!(text.contains(&a.to_string()));
        assert!(text.contains(&b.to_string()));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_event() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("device.ping"),
            Just("device.bye"),
            Just("_synra.device.changed"),
            Just("_plugin.@acme/chat.text"),
            Just("_plugin.@acme/chat.typing"),
        ]
    }

    proptest! {
        /// Anything that can be built can be written and read back unchanged. If this fails, two
        /// peers built from the same code disagree about a message.
        #[test]
        fn envelopes_round_trip(
            event in arbitrary_event(),
            payload in proptest::option::of("[a-z0-9 \"]{0,64}"),
        ) {
            let (a, b) = (DeviceId::new(), DeviceId::new());
            let spec = OutboundSpec {
                event: EventName::parse(event).expect("the generated names are valid"),
                target: b,
                from: a,
                trace_id: TraceId::new(),
                sent_at_ms: 1,
                ttl_ms: Some(5_000),
            };
            let envelope = Envelope::outbound(spec, payload.as_ref()).expect("builds");
            let text = serde_json::to_string(&envelope).expect("serialises");
            let parsed = Envelope::inbound(&RawValue::from_string(text).expect("valid"), b)
                .expect("round trips");
            prop_assert_eq!(parsed, envelope);
        }

        /// A payload that is too large is refused at construction rather than at the socket, so a
        /// caller learns about the mistake where it was made.
        #[test]
        fn oversized_payloads_are_refused(len in (MAX_PAYLOAD_LEN + 1)..(MAX_PAYLOAD_LEN + 512)) {
            let payload = "x".repeat(len);
            let spec = OutboundSpec {
                event: EventName::parse("device.ping").expect("valid"),
                target: DeviceId::new(),
                from: DeviceId::new(),
                trace_id: TraceId::new(),
                sent_at_ms: 1,
                ttl_ms: None,
            };
            let result = Envelope::outbound(spec, Some(&payload));
            // Checked without a pattern, because `prop_assert!` builds a message with `format!` and a
            // `{ .. }` pattern would be read as a format placeholder.
            prop_assert!(result.is_err(), "a payload of {} bytes should be refused", len);
            prop_assert!(result.unwrap_err().to_string().contains("exceeds the ceiling"));
        }
    }
}

/// What a reply needs to know, when the request's own bytes are no longer at hand.
///
/// ★ **Why this is a value rather than the request envelope.**
///
/// The side that answers is often not the side that read the request: in the daemon's case the bytes were consumed by a
/// transfer that has already landed, and what survives is these four facts. A constructor that demanded the original
/// envelope would make every reader keep one — including a payload it has no use for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyContext {
    /// The request this answers.
    pub request_id: RequestId,
    /// Who the answer is for.
    pub target: DeviceId,
    /// Who it is from.
    pub from: DeviceId,
    /// The trace the question belonged to.
    pub trace_id: TraceId,
    /// How long the question was interesting for.
    pub ttl_ms: Option<u32>,
}

impl ReplyContext {
    /// The facts a reply needs, taken from the request and this device's own identity.
    ///
    /// ★ `local` is a parameter rather than a field read off the request, and that is the whole reason this is a
    /// function: **who is answering** is never in the question. A version of this that took only the request would set
    /// `from` to the *asker* — a reply addressed from the device it is addressed to.
    #[must_use]
    pub const fn of(request: &Envelope, local: DeviceId) -> Self {
        Self {
            request_id: request.request_id,
            target: request.from,
            from: local,
            trace_id: request.trace_id,
            ttl_ms: request.ttl_ms,
        }
    }
}
