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

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::event::EventName;
use crate::ids::{DeviceId, RequestId, TraceId};
use crate::limits::MAX_PAYLOAD_LEN;

mod errors;
mod helpers;
mod reply;

pub use errors::EnvelopeError;
pub use helpers::{envelope_error_to_synra, parse_envelope};
pub use reply::ReplyContext;
pub(crate) use helpers::raw_json_eq;

use helpers::{check_depth, elapsed_ms, encode_payload};

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

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;


