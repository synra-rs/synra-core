//! The control plane: which messages a transfer exchanges, and how each is put on the wire.
//!
//! # Why the names live in one place
//!
//! Because six call sites naming an event by hand is six chances to name one wrongly, and a name the far end does not know
//! is a message it refuses. Every transfer message is built through `envelope_for`, so the name, the addressing and the
//! trace are set once.

use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::ids::{DeviceId, TraceId};

use super::types::SessionError;

/// A message family on the control plane.
///
/// # Why the two directions are one enum
///
/// Because a request and a completion travel in both directions — a receiver answers a completion with a completion — and
/// two enums would be two places the event names live. The names are the protocol's either way.
///
/// Public because [`classify`] returns it: a caller dispatching a link's messages needs to name what it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// The sender proposes a transfer.
    Request,
    /// A block of data, carried as a frame rather than as an envelope.
    Chunk,
    /// The sender has sent everything, or the receiver confirms it verified.
    Complete,
    /// Either side is giving up.
    Abort,
    /// The receiver reports which blocks it holds.
    Progress,
}

impl Message {
    /// The wire name, which is the protocol's.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Request => synra_protocol::event::DataPlaneEvent::FileTransferRequest.as_str(),
            Self::Chunk => synra_protocol::event::DataPlaneEvent::FileTransferChunk.as_str(),
            Self::Complete => synra_protocol::event::DataPlaneEvent::FileTransferComplete.as_str(),
            Self::Abort => synra_protocol::event::DataPlaneEvent::FileTransferAbort.as_str(),
            Self::Progress => synra_protocol::event::DataPlaneEvent::FileTransferProgress.as_str(),
        }
    }
}

/// Builds a control-plane envelope for a transfer.
///
/// # Why every transfer message goes through here
///
/// Because the event name, the addressing and the trace have to be right on each one, and six call sites is six chances to
/// get one of them wrong. The trace is the caller's, so every message of one user action shares it.
pub(super) fn envelope_for<P: serde::Serialize>(
    message: Message,
    from: DeviceId,
    to: DeviceId,
    trace_id: TraceId,
    sent_at_ms: i64,
    payload: &P,
) -> Result<Envelope, SessionError> {
    let event = EventName::parse(message.name())?;
    Ok(Envelope::outbound(
        OutboundSpec { event, target: to, from, trace_id, sent_at_ms, ttl_ms: None },
        Some(payload),
    )?)
}

/// Reads an envelope's payload into a type.
///
/// # Why a `&RawValue` is parsed here rather than a tree
///
/// Because that is how the protocol carries a payload: the envelope holds the bytes and this is the first point that knows
/// what shape they should be. Parsing into a tree first would allocate per field for every message.
pub(super) fn payload_of<T: for<'de> serde::Deserialize<'de>>(
    envelope: &Envelope,
    message: &'static str,
) -> Result<T, SessionError> {
    let raw = envelope.payload.as_ref().ok_or_else(|| SessionError::Payload {
        message,
        why: "the envelope carries no payload".to_owned(),
    })?;
    serde_json::from_str(raw.get()).map_err(|error| SessionError::Payload {
        message,
        why: error.to_string(),
    })
}

/// Whether an envelope is one of the transfer family.
///
/// Returns which, so a caller can dispatch without parsing the payload of a message that is not for it — which matters,
/// because a link carries every other kind of message too.
#[must_use]
pub fn classify(envelope: &Envelope) -> Option<Message> {
    let name = envelope.event.as_str();
    [
        Message::Request,
        Message::Chunk,
        Message::Complete,
        Message::Abort,
        Message::Progress,
    ]
    .into_iter()
    .find(|message| message.name() == name)
}