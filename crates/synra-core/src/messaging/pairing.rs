use serde::Serialize;
use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::ids::{DeviceId, TraceId};

use super::text::MessageError;

/// 配对：请求、答复、撤回。
///
/// # 为什么这三条放在 `messaging` 而不是 `pairing`
///
/// 因为这里的职责是「造一个信封」，与剪贴板、插件列表用的是同一套：`OutboundSpec` 定目标与截止，
/// 载荷由协议层校验。`pairing` 那一层不认识信封，也不该认识——它只回答「这个人点了之后该发生什么」。
///
/// # Errors
///
/// [`MessageError::EventName`] 如果本构建自己的常量不被协议接受；[`MessageError::Envelope`] 如果信封被协议拒绝。
pub fn pair_request(
    from: DeviceId,
    to: DeviceId,
    request: &synra_protocol::pairing::PairRequest,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::pairing::PAIR_REQUEST)?;
    pair_envelope(event, from, to, trace_id, sent_at_ms, Some(request))
}

/// 答复对方的配对请求。
///
/// # Errors
///
/// 同 [`pair_request`]。
pub fn pair_response(
    from: DeviceId,
    to: DeviceId,
    response: synra_protocol::pairing::PairResponse,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::pairing::PAIR_RESPONSE)?;
    pair_envelope(event, from, to, trace_id, sent_at_ms, Some(&response))
}

/// 撤回本机发出的配对请求。无载荷：撤回不需要理由。
///
/// # Errors
///
/// 同 [`pair_request`]。
pub fn pair_cancel(
    from: DeviceId,
    to: DeviceId,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::pairing::PAIR_CANCEL)?;
    pair_envelope::<()>(event, from, to, trace_id, sent_at_ms, None)
}

/// 三条配对消息共用的信封。
fn pair_envelope<T: Serialize>(
    event: EventName,
    from: DeviceId,
    to: DeviceId,
    trace_id: TraceId,
    sent_at_ms: i64,
    payload: Option<&T>,
) -> Result<Envelope, MessageError> {
    // No TTL: a pairing request that arrives after the person walked away is one whose code is already dead on the
    // sender's screen, and the receiver answering it would pair two devices on the strength of a stale number.
    let spec = OutboundSpec {
        event,
        target: to,
        from,
        trace_id,
        sent_at_ms,
        ttl_ms: None,
    };
    Envelope::outbound(spec, payload).map_err(MessageError::Envelope)
}
