use super::*;
use serde_json::value::RawValue;
use synra_protocol::envelope::{Envelope, EnvelopeError};
use synra_protocol::event::{builtin, EventName};
use synra_protocol::ids::{DeviceId, TraceId};

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
    let from_design: SyncResult = serde_json::from_str(
        "{\"ok\":true,\"installedVersion\":\"1.2.0\",\"activated\":false,\"error\":null}",
    )
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
    let envelope = sync_result(
        synra_protocol::envelope::ReplyContext::of(&message("hello"), device(A)),
        &outcome,
        2_000,
    )
    .expect("an envelope");

    assert_eq!(
        envelope.event.as_str(),
        synra_protocol::event::events::PLUGIN_SYNC_RESULT
    );

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
    let envelope = sync_result(
        synra_protocol::envelope::ReplyContext::of(&message("hello"), device(A)),
        &outcome,
        2_000,
    )
    .expect("an envelope");

    let payload: serde_json::Value =
        serde_json::from_str(envelope.payload_str().expect("a payload")).expect("json");
    assert_eq!(payload["ok"], false, "{payload}");
    // 没有版本,因为什么都没装上 —— 报一个版本号会让发起端更新它的同步状态。
    assert!(payload["installedVersion"].is_null(), "{payload}");
    assert_eq!(
        payload["error"], "the signature did not verify",
        "{payload}"
    );
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
    assert_eq!(
        value.get("mime").and_then(serde_json::Value::as_str),
        Some(TEXT_MIME)
    );
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
