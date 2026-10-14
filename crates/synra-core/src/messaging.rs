//! What the kernel sends to a peer, and the envelope it travels in.
//!
//! # Why this is separate from `host`
//!
//! [`crate::host::Host`] answers *who can I reach and how*; this answers *what do I say*. The two are separate because the
//! second is where the wire format lives, and a change to what a message contains should not be a change to how a
//! connection is made.
//!
//! # Why the text goes as a clipboard event
//!
//! Because that is the protocol's own answer: the built-in event for "text arrived from a peer" is
//! `_synra.clipboard.received`, and its payload is `{ text?, mime, fromDeviceId }`. There is no separate "send text"
//! event, and inventing one would be a second way to say the same thing — which is a second thing for a receiver to
//! understand and a second place for the two to disagree.
//!
//! The `mime` is `text/plain` because that is what `--text` is. The `fromDeviceId` is carried in the payload **as well as**
//! in the envelope's `from`, which looks redundant and is not: the payload is what a plugin reads, and a plugin is handed
//! a payload rather than an envelope. The envelope's field is what the link checks; the payload's is what the receiver's
//! code uses.
//!
//! # Why the size is checked here
//!
//! Because the protocol refuses an over-long payload when the envelope is built, and a refusal after a socket has been
//! dialled has already cost a handshake. Checking first means a user who pasted something enormous is told so without the
//! kernel talking to the network at all.

use serde::{Deserialize, Serialize};
use synra_protocol::envelope::{Envelope, EnvelopeError, OutboundSpec};
use synra_protocol::event::{EventName, builtin};
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
        Self { text: text.into(), mime: TEXT_MIME.to_owned(), from_device_id }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    fn message(text: &str) -> Envelope {
        text_to(device(A), device(B), text, TraceId::new(), 1_000).expect("builds")
    }

    // ── What is built ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_message_is_addressed_and_attributed() {
        // The envelope says who it is for and who it is from, which is what the receiving link checks the second of.
        let envelope = message("hello");
        assert_eq!(envelope.from, device(A));
        assert_eq!(envelope.target, device(B));
        assert_eq!(envelope.sent_at_ms, 1_000);
    }

    #[test]
    fn a_message_is_a_clipboard_event() {
        // ★ The protocol's own answer for "text arrived from a peer". There is no separate send-text event, and inventing
        // one would be a second way to say the same thing — a second thing for a receiver to understand and a second place
        // for the two to disagree.
        assert_eq!(message("hello").event.as_str(), builtin::CLIPBOARD_RECEIVED);
    }

    #[test]
    fn the_payload_carries_the_text_the_media_type_and_the_sender() {
        // ★ The sender is in the payload **as well as** in the envelope, and that is not redundancy: the payload is what a
        // plugin reads, and a plugin is handed a payload rather than an envelope. The envelope's field is what the link
        // checks; this one is what the receiver's code uses.
        let envelope = message("hello there");
        let payload = envelope.payload.as_ref().expect("a payload");
        let parsed: ClipboardText = serde_json::from_str(payload.get()).expect("parses");

        assert_eq!(parsed.text, "hello there");
        assert_eq!(parsed.mime, TEXT_MIME);
        assert_eq!(parsed.from_device_id, device(A));
    }

    #[test]
    fn the_field_is_named_the_way_the_protocol_names_it() {
        // The protocol's event table says `fromDeviceId`, and a receiver parsing that shape would find nothing under
        // `from_device_id`. Asserted against the raw JSON rather than through the struct, because the struct would rename
        // it on both sides of its own test.
        let envelope = message("hello");
        let payload = envelope.payload.as_ref().expect("a payload");
        let value: serde_json::Value = serde_json::from_str(payload.get()).expect("parses");
        assert!(value.get("fromDeviceId").is_some(), "{value}");
        assert!(value.get("from_device_id").is_none(), "{value}");
        assert_eq!(value.get("mime").and_then(serde_json::Value::as_str), Some(TEXT_MIME));
    }

    #[test]
    fn a_payload_the_protocol_will_accept_is_produced() {
        // The envelope is validated by the receiving link, so one this build produces that its own validator refuses is a
        // message that can never arrive.
        let envelope = message("hello");
        assert!(envelope.validate(device(B)).is_ok());
    }

    #[test]
    fn a_text_with_no_lifetime_is_sent() {
        // A clipboard message that arrives an hour late is one the user did not mean to send now, and the receiver has no
        // way to tell. With no deadline it is dropped when the link closes, which is the honest boundary for it.
        assert_eq!(message("hello").ttl_ms, None);
    }

    #[test]
    fn a_message_keeps_the_trace_it_was_given() {
        // The trace groups every step of one user action, so a caller that passed one has to get it back.
        let trace = TraceId::new();
        let envelope = text_to(device(A), device(B), "x", trace, 0).expect("builds");
        assert_eq!(envelope.trace_id, trace);
    }

    #[test]
    fn text_is_carried_verbatim_including_newlines_and_unicode() {
        // A message with a newline in it is ordinary — a pasted excerpt — and one that arrived altered would be a bug the
        // user sees as their own text being wrong.
        let text = "line one\nline two\t tabbed\n  ✅ 中文";
        let envelope = message(text);
        let payload = envelope.payload.as_ref().expect("a payload");
        let parsed: ClipboardText = serde_json::from_str(payload.get()).expect("parses");
        assert_eq!(parsed.text, text);
    }

    // ── What is refused ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn empty_text_is_refused_before_an_envelope_is_built() {
        // ★ It would arrive as a clipboard event with nothing in it, and a receiver that acted on it would clear the
        // user's clipboard to nothing. An empty `--text` is a mistake at the shell, and refusing it says so.
        for text in ["", "   ", "\n", "\t"] {
            assert_eq!(
                text_to(device(A), device(B), text, TraceId::new(), 0),
                Err(MessageError::Empty),
                "{text:?}"
            );
        }
    }

    #[test]
    fn text_too_long_for_one_envelope_is_refused_with_both_lengths() {
        // ★ The user's next step is different from any other failure: a message too large for one envelope is one to send
        // as a file. Naming both lengths is what makes that actionable, where the protocol's own `PayloadTooLarge` names
        // two numbers and no advice.
        let huge = "a".repeat(200 * 1024 * 1024);
        match text_to(device(A), device(B), &huge, TraceId::new(), 0) {
            Err(MessageError::TooLong { len, max }) => {
                assert!(len > max, "{len} <= {max}");
                assert!(max > 0);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_message_at_the_ceiling_is_accepted_or_refused_consistently() {
        // The boundary from both sides, because a refusal that is one byte early rejects a message a user could have sent.
        // The ceiling is not named here — it is the protocol's — so this finds it by bisection rather than by repeating
        // the number, which would be a second place it lives.
        let mut low = 1usize;
        let mut high = 4 * 1024 * 1024;
        while low < high {
            let middle = low + (high - low) / 2;
            let text = "a".repeat(middle);
            match text_to(device(A), device(B), &text, TraceId::new(), 0) {
                Ok(_) => low = middle + 1,
                Err(MessageError::TooLong { .. }) => high = middle,
                // Only a length refusal is a boundary result; anything else would make the bisection meaningless.
                Err(other) => panic!("expected a length refusal or a message, got {other:?}"),
            }
        }
        // `low` is the first length that fails, so one less must succeed — unless the whole range succeeded, which the
        // 200 MB test above has already ruled out for this build.
        let accepted = "a".repeat(low.saturating_sub(1));
        assert!(
            text_to(device(A), device(B), &accepted, TraceId::new(), 0).is_ok(),
            "the boundary is off by one at {low}"
        );
    }

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            MessageError::Empty,
            MessageError::TooLong { len: 500, max: 100 },
            MessageError::Envelope(EnvelopeError::NilField { field: "from" }),
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
        // And the length failure names both numbers and the way out.
        let text = errors[1].to_string();
        assert!(text.contains("500") && text.contains("100"), "{text}");
        assert!(text.contains("file"), "{text}");
    }

    #[test]
    fn the_built_in_event_name_this_build_uses_is_one_it_accepts() {
        // ★ The invariant `text_to` relies on: it parses a name this crate declares, and refuses rather than threading an
        // error for a case that cannot happen. If the protocol's catalogue ever stopped containing the name, this is what
        // says so — at the point of the assumption rather than as a panic in a user's session.
        assert!(
            EventName::parse(builtin::CLIPBOARD_RECEIVED).is_ok(),
            "{} is not a name this build accepts",
            builtin::CLIPBOARD_RECEIVED
        );
    }

    #[test]
    fn the_payload_is_raw_when_it_arrives() {
        // The protocol keeps a payload as a `RawValue` so the kernel can check its shape without building a tree. That it
        // parses into the struct at all is the assertion; that it stays raw on the way is the protocol's.
        let envelope = message("hello");
        let payload: &RawValue = envelope.payload.as_deref().expect("a payload");
        assert!(payload.get().starts_with('{'), "{}", payload.get());
    }
}
