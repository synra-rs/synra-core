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
    let payload = envelope.payload.as_deref().ok_or_else(|| MessageError::Unreadable {
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

/// Builds the envelope that asks a device to pair.
///
/// # Why this lives here rather than in the daemon
///
/// Because the event name, the addressing and the trace have to be right, and the daemon is not the only thing that will
/// want to ask. It is also how a test can check the envelope without a socket: a request built inline in a command
/// handler cannot be inspected without running the command.
///
/// # Errors
///
/// [`MessageError::InvalidProfile`] when the profile this device would advertise is not one the protocol accepts — which
/// is checked here as well as on the receiving side, because a request the other user is shown and then has refused
/// wastes the one thing pairing cannot get back: their attention.
pub fn pair_request(
    from: DeviceId,
    to: DeviceId,
    profile: &synra_protocol::session::PeerProfile,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    profile.validate().map_err(MessageError::InvalidProfile)?;
    let event = EventName::parse(synra_protocol::event::events::PAIR_REQUEST)?;

    Ok(Envelope::outbound(
        OutboundSpec {
            event,
            target: to,
            from,
            trace_id,
            sent_at_ms,
            // A pairing request is answered by a person, and a person takes as long as they take. The window is the
            // session's `pairing` timeout, which both ends hold — an envelope deadline here would be a second, different
            // clock on the same decision.
            ttl_ms: None,
        },
        Some(profile),
    )?)
}

/// Builds the envelope that answers a pairing request.
///
/// # Errors
///
/// [`MessageError::Envelope`] when the protocol refuses the envelope, and
/// [`MessageError::EventName`] if this build's own constant is not one the protocol accepts.
pub fn pair_response(
    request: &Envelope,
    from: DeviceId,
    answer: &synra_protocol::session::PairResponse,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::event::events::PAIR_RESPONSE)?;
    // A reply, so it carries the request's id and trace and is addressed to whoever asked: an answer that could not be
    // correlated would leave the dialer waiting out its own window for a decision already made.
    Ok(Envelope::reply_to(request, event, from, sent_at_ms, Some(answer))?)
}

/// What the receiving device tells the sending one about a sync — `16` §5.2 ⑧'s last act.
///
/// # Why this is not [`crate::plugin_sync::SyncOutcome`] itself
///
/// Because that type is this device's own bookkeeping: which duties it performed, in what order, and whether the whole set
/// was completed. The sender needs four facts and no more, and it must not be handed a list of checks it cannot see the
/// evidence for — a report is not a wire format.
// 两个方向都要：接收端发出它，发起端读回它。一个只能序列化的线上类型是半成品，
// 而往返测试是唯一能证明两边字段名真的对上的东西。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    /// Whether the plugin is installed.
    pub ok: bool,
    /// Which version, when there is one.
    pub installed_version: Option<String>,
    /// Whether **this** device chose to enable it. Local by rule — `16` §5.4 rule 7 — so it is reported, not negotiated.
    pub activated: bool,
    /// What went wrong, when something did.
    pub error: Option<String>,
}

impl SyncResult {
    /// The four fields, taken from the receiver's outcome.
    #[must_use]
    pub fn of(outcome: &crate::plugin_sync::SyncOutcome) -> Self {
        Self {
            ok: outcome.installed,
            installed_version: outcome.installed_version.clone(),
            activated: outcome.activated,
            error: outcome.error.clone(),
        }
    }
}

/// Builds the envelope that ends a sync, as ⑧ requires.
///
/// ★ **Why this had to exist.** [`synra_protocol::event::events::PLUGIN_SYNC_RESULT`] has been declared since the first
/// version of the contract and appears in the inbound allow-list, but nothing ever **sent** it. So the sending device
/// could not learn the outcome, and ⑨ — "A updates its sync state and the interface shows it" — had no source of truth:
/// a push that failed looked exactly like one that succeeded, which is the shape this codebase keeps removing.
///
/// It is a reply rather than a fresh envelope, so it carries the request's id and trace: an outcome the sender cannot
/// correlate with the transfer it asked for is one it will wait out and then retry.
///
/// # Errors
///
/// [`MessageError::Envelope`] when the protocol refuses the envelope, and [`MessageError::EventName`] if this build's own
/// constant is not one the protocol accepts.
pub fn sync_result(
    request: &Envelope,
    from: DeviceId,
    outcome: &crate::plugin_sync::SyncOutcome,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::event::events::PLUGIN_SYNC_RESULT)?;
    let result = SyncResult::of(outcome);
    Ok(Envelope::reply_to(request, event, from, sent_at_ms, Some(&result))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;

    #[test]
    fn a_sync_result_round_trips_and_reads_the_field_names_the_design_writes() {
        // 「出」的一半上一轮做了，这是「进」的一半。一个线上类型只做一个方向是半成品，
        // 而往返测试是唯一能证明两边字段名真的对上的东西。
        let outcome = crate::plugin_sync::SyncOutcome::refused(
            synra_protocol::ids::PluginId::try_from("@acme/chat".to_owned()).expect("a plugin id"),
            crate::plugin_sync::SyncSessionId::new("round-1"),
            "the signature did not verify",
        );
        let result = SyncResult::of(&outcome);

        let json = serde_json::to_string(&result).expect("json");
        assert!(json.contains("\"installedVersion\""), "{json}");
        let back: SyncResult = serde_json::from_str(&json).expect("parsed");
        assert_eq!(back.ok, result.ok);
        assert_eq!(back.error, result.error);

        // 以及直接读文档给出的那个形状：字段名写错的话这里会失败。
        let from_design: SyncResult =
            serde_json::from_str("{\"ok\":true,\"installedVersion\":\"1.2.0\",\"activated\":false,\"error\":null}")
                .expect("the shape the design documents");
        assert!(from_design.ok);
        assert_eq!(from_design.installed_version.as_deref(), Some("1.2.0"));
        assert!(!from_design.activated);
        assert!(from_design.error.is_none());
    }

    #[test]
    fn a_sync_result_carries_the_four_fields_the_design_names() {
        // ★ ⑧ 的最后一件事,而它此前**从未被发出过**:事件名从 v1 就在,入站白名单也认它,
        // 但发起端永远等不到结局 —— ⑨「A 更新同步状态、UI 显示」因此没有信息来源。
        let outcome = crate::plugin_sync::SyncOutcome::installed(
            synra_protocol::ids::PluginId::try_from("@acme/chat".to_owned()).expect("a plugin id"),
            crate::plugin_sync::SyncSessionId::new("round-1"),
            "1.2.0",
            true,
            Vec::new(),
        );
        // 内部类型 `SyncOutcome` 不上线,上线的是这四个字段的载荷。
        let envelope = sync_result(&message("hello"), device(A), &outcome, 2_000).expect("an envelope");

        assert_eq!(envelope.event.as_str(), synra_protocol::event::events::PLUGIN_SYNC_RESULT);

        let payload: serde_json::Value =
            serde_json::from_str(envelope.payload_str().expect("a payload")).expect("json");
        assert_eq!(payload["ok"], true, "{payload}");
        assert_eq!(payload["installedVersion"], "1.2.0", "{payload}");
        assert_eq!(payload["activated"], true, "{payload}");
        assert!(payload["error"].is_null(), "{payload}");
    }

    #[test]
    fn a_sync_result_that_failed_is_not_indistinguishable_from_one_that_worked() {
        // 另一半,而且是这一条存在的原因:一个被拒绝的同步必须让发起端看出来。
        // 「失败与沉默无法区分」是本仓库反复出现的形状,而这条回复是 ⑨ 唯一的输入。
        let outcome = crate::plugin_sync::SyncOutcome::refused(
            synra_protocol::ids::PluginId::try_from("@acme/chat".to_owned()).expect("a plugin id"),
            crate::plugin_sync::SyncSessionId::new("round-1"),
            "the signature did not verify",
        );
        let envelope = sync_result(&message("hello"), device(A), &outcome, 2_000).expect("an envelope");

        let payload: serde_json::Value =
            serde_json::from_str(envelope.payload_str().expect("a payload")).expect("json");
        assert_eq!(payload["ok"], false, "{payload}");
        // 没有版本,因为什么都没装上 —— 报一个版本号会让发起端更新它的同步状态。
        assert!(payload["installedVersion"].is_null(), "{payload}");
        assert_eq!(payload["error"], "the signature did not verify", "{payload}");
    }

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


    // ── Pairing envelopes ─────────────────────────────────────────────────────────────────────────

    /// A profile this device would advertise.
    fn profile(name: &str) -> synra_protocol::session::PeerProfile {
        synra_protocol::session::PeerProfile {
            device_id: device(A),
            display_name: name.to_owned(),
            platform: synra_protocol::session::PlatformKind::Desktop,
            app_version: "0.1.0".to_owned(),
        }
    }

    #[test]
    fn a_pair_request_is_addressed_to_the_device_and_names_the_event() {
        let from = device(A);
        let to = device(B);
        let envelope =
            pair_request(from, to, &profile("This device"), TraceId::new(), 1_000).expect("builds");

        assert_eq!(envelope.event.as_str(), synra_protocol::event::events::PAIR_REQUEST);
        assert_eq!(envelope.target, to);
        assert_eq!(envelope.from, from);

        // The payload is the *sender's* profile: the request's whole purpose is that the other user sees a name rather
        // than an identifier, and a request carrying the recipient's own profile would show them themselves.
        let payload = envelope.payload_str().expect("a payload");
        let sent: synra_protocol::session::PeerProfile =
            serde_json::from_str(payload).expect("the payload is a profile");
        assert_eq!(sent.device_id, from);
        assert_eq!(sent.display_name, "This device");
    }

    #[test]
    fn a_pair_request_carries_no_envelope_deadline() {
        // A person answers in their own time. The window is the session's `pairing` timeout, which both ends hold; an
        // envelope deadline here would be a second, different clock on the same decision.
        let envelope = pair_request(
            device(A),
            device(B),
            &profile("This device"),
            TraceId::new(),
            1_000,
        )
        .expect("builds");
        assert_eq!(envelope.ttl_ms, None);
    }

    #[test]
    fn a_profile_this_device_could_not_advertise_is_refused_before_it_is_sent() {
        // The receiving side checks this too, and a request refused there has already been shown to a user who then has
        // to decide about it. Catching it here costs a comparison and saves their attention.
        let mut blank = profile("");
        blank.display_name = "   ".to_owned();
        assert!(matches!(
            pair_request(
                device(A),
                device(B),
                &blank,
                TraceId::new(),
                1_000
            ),
            Err(MessageError::InvalidProfile(_))
        ));
    }

    #[test]
    fn a_pair_response_is_a_reply_that_names_the_request_and_traces_its_decision() {
        let from = device(A);
        let to = device(B);
        let request =
            pair_request(from, to, &profile("This device"), TraceId::new(), 1_000).expect("builds");

        let answer = synra_protocol::session::PairResponse::accepted(
            "aa".repeat(synra_protocol::handshake::LinkToken::LEN),
        );
        let response = pair_response(&request, to, &answer, 2_000).expect("builds");

        assert_eq!(response.event.as_str(), synra_protocol::event::events::PAIR_RESPONSE);
        // Addressed to whoever asked, and correlated with the request: an answer that could not be correlated would
        // leave the dialer waiting out its own window for a decision already made.
        assert_eq!(response.target, from);
        assert_eq!(response.from, to);
        assert_eq!(response.reply_to, Some(request.request_id));
        assert_eq!(response.trace_id, request.trace_id, "one user action, one trace");
    }
}
