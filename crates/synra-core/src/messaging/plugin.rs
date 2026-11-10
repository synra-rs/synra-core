use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::ids::{DeviceId, TraceId};

use super::text::MessageError;

/// Asks a peer which plugins it has.
///
/// # Why the request carries no payload
///
/// Because there is nothing to narrow: the answer is the whole list, and a request that offered filters would be a request the
/// answering side has to validate — a second grammar for a question with one form.
///
/// # Errors
///
/// [`MessageError::EventName`] if this build's own constant is not one the protocol accepts.
pub fn plugin_list_request(
    from: DeviceId,
    to: DeviceId,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::event::events::PLUGIN_LIST_REQUEST)?;
    Ok(Envelope::outbound(
        OutboundSpec {
            event,
            target: to,
            from,
            trace_id,
            sent_at_ms,
            ttl_ms: None,
        },
        None::<&synra_protocol::session::PluginList>,
    )?)
}

/// Answers which plugins this device has.
///
/// # Errors
///
/// [`MessageError::EventName`] if this build's own constant is not one the protocol accepts, and
/// [`MessageError::Envelope`] when the protocol refuses the envelope — a list too large for one frame is the case that
/// matters, and it is refused here rather than truncated: a truncated list would read as "this device has fewer plugins".
pub fn plugin_list_response(
    request: &Envelope,
    from: DeviceId,
    list: &synra_protocol::session::PluginList,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::event::events::PLUGIN_LIST_RESPONSE)?;
    Ok(Envelope::reply_to(
        request,
        event,
        from,
        sent_at_ms,
        Some(list),
    )?)
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
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    context: synra_protocol::envelope::ReplyContext,
    outcome: &crate::plugin_sync::SyncOutcome,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(synra_protocol::event::events::PLUGIN_SYNC_RESULT)?;
    let result = SyncResult::of(outcome);
    Ok(Envelope::reply_parts(
        context,
        event,
        sent_at_ms,
        Some(&result),
    )?)
}
