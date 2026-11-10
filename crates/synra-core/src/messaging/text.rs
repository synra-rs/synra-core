use serde::{Deserialize, Serialize};
use synra_protocol::envelope::{Envelope, EnvelopeError, OutboundSpec};
use synra_protocol::event::{builtin, EventName};
use synra_protocol::ids::{DeviceId, TraceId};

/// The media type `--text` sends.
pub const TEXT_MIME: &str = "text/plain";

/// What a receiver finds in a clipboard event.
///
/// # Why this type exists here and not only in the protocol
///
/// Because `synra-protocol`'s `inbound` module has an equivalent for the *receiving* direction, and this is the sending
/// one. They are two halves of one shape, and having the sender build a struct rather than an ad-hoc JSON value is what
/// makes a field renamed on one side a compile error on the other — where an ad-hoc value would be a silent mismatch that
/// surfaces as a receiver rendering nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardText {
    /// The text.
    pub text: String,
    /// What it is.
    pub mime: String,
    /// Which device sent it, so a receiver can attribute it without the envelope.
    #[serde(rename = "fromDeviceId")]
    pub from_device_id: DeviceId,
}

impl ClipboardText {
    /// Text from this device.
    #[must_use]
    pub fn new(text: impl Into<String>, from_device_id: DeviceId) -> Self {
        Self {
            text: text.into(),
            mime: TEXT_MIME.to_owned(),
            from_device_id,
        }
    }
}

/// Why a message could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MessageError {
    /// The text is empty, or nothing but whitespace.
    ///
    /// # Why this is refused rather than sent
    ///
    /// Because it would arrive as a clipboard event with nothing in it, and a receiver that acted on it would clear the
    /// user's clipboard to nothing. An empty `--text` is a mistake at the shell, and refusing it says so.
    #[error("there is no text to send")]
    Empty,

    /// The text is longer than one envelope may carry.
    ///
    /// # Why this is its own failure rather than a protocol error
    ///
    /// Because the user's next step is different: a message too large for one envelope is one to send as a file, and a
    /// message that failed for another reason is not. Naming both lengths is what makes that actionable.
    #[error("the text is {len} bytes and one message may carry {max} — send it as a file instead")]
    TooLong {
        /// How long it is.
        len: usize,
        /// The ceiling.
        max: usize,
    },

    /// The envelope could not be built.
    #[error("the message could not be built: {0}")]
    Envelope(#[from] EnvelopeError),

    /// The event name was refused by the protocol.
    ///
    /// # Why this variant exists for a name this crate declares
    ///
    /// Because it *can* be refused — the check is a run-time parse of a string constant — and the workspace denies the
    /// `unwrap` that would be the alternative. A variant for an impossible case is cheaper than an escape hatch from a
    /// lint that exists to stop exactly that kind of assumption.
    #[error("the event name was refused: {0}")]
    EventName(#[from] synra_protocol::event::EventNameError),

    /// The profile this device would advertise is not one the protocol accepts.
    ///
    /// # Why the sender checks this at all
    ///
    /// Because the receiving side checks it too, and a request refused there has already been shown to a user who then
    /// has to decide about it. Catching it here costs a string comparison and saves the one thing pairing cannot get
    /// back: the other person's attention.
    #[error("this device cannot ask to pair: {0}")]
    InvalidProfile(&'static str),

    /// The envelope does not carry a readable text message.
    ///
    /// # Why this is not a protocol error
    ///
    /// Because a peer can send a well-formed envelope whose payload is not the shape this event promises — a different
    /// version, a plugin's own event that happens to share the name, a hand-built message. None of those is a broken
    /// connection, and reporting one as a framing error would close a link that is working.
    #[error("the message could not be read: {why}")]
    Unreadable {
        /// What was wrong with it.
        why: String,
    },
}

/// Reads the text out of an envelope that carries one.
///
/// # ★ Why this exists
///
/// Because [`text_to`] had no counterpart. A text message could be **written and sent**, and nothing in the tree could
/// read one back: the payload stayed a `RawValue`, the receiver knew only the event's name, and `inbound`'s built-in
/// parser returned a `ClipboardText` with an empty string and a freshly minted device id because it ignores payloads
/// entirely. A sender with no receiver is half a feature, and this is the other half.
///
/// # What it does not check
///
/// Whether the sender is who the payload claims. `from_device_id` is inside the body and a peer can put anything there;
/// the envelope's own `from` is what the handshake established. A caller deciding *who sent this* must use the envelope,
/// and this function returning the body's claim unexamined is why it is named `text_from` rather than `sender_of`.
///
/// # Errors
///
/// [`MessageError::Unreadable`] when there is no payload, when it is not JSON, or when it is not a `ClipboardText`.
pub fn text_from(envelope: &Envelope) -> Result<ClipboardText, MessageError> {
    let payload = envelope
        .payload
        .as_deref()
        .ok_or_else(|| MessageError::Unreadable {
            why: "the envelope carries no payload".to_owned(),
        })?;
    serde_json::from_str(payload.get()).map_err(|error| MessageError::Unreadable {
        why: error.to_string(),
    })
}

/// Builds the envelope that carries text to a device.
///
/// # Errors
///
/// [`MessageError`] for empty text, text too long for one envelope, or an envelope the protocol refuses.
pub fn text_to(
    from: DeviceId,
    to: DeviceId,
    text: &str,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    if text.trim().is_empty() {
        return Err(MessageError::Empty);
    }

    let payload = ClipboardText::new(text, from);

    // The name is a constant this build declares, so this cannot fail in practice — and it is still handled rather than
    // assumed, because the workspace denies `unwrap` and `panic!` in production code and pretending an error is impossible
    // is what those lints exist to prevent. The test below asserts the constant really is in the catalogue, so a mistake
    // shows up there rather than in a user's session.
    let event = EventName::parse(builtin::CLIPBOARD_RECEIVED)?;

    // The check is the protocol's, run through the builder — but the *sizes* are named here so the message can say what
    // to do about it. A `PayloadTooLarge` from the protocol names two numbers and no advice.
    match Envelope::outbound(
        OutboundSpec {
            event,
            target: to,
            from,
            trace_id,
            sent_at_ms,
            // No lifetime: a clipboard message that arrives an hour late is one the user did not mean to send now, and the
            // receiver has no way to tell. A message with no deadline is dropped by the link when the link closes, which
            // is the honest boundary for it.
            ttl_ms: None,
        },
        Some(&payload),
    ) {
        Ok(envelope) => Ok(envelope),
        Err(EnvelopeError::PayloadTooLarge { len, max }) => Err(MessageError::TooLong { len, max }),
        Err(other) => Err(MessageError::Envelope(other)),
    }
}
