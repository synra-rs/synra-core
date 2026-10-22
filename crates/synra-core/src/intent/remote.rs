//! An intent that runs on another device.
//!
//! # What this is, and why it did not exist
//!
//! `decide` answers "run this, there" by building an envelope — and it used to refuse instead, because nothing could send
//! one. The design names the three events (`INTENT_INVOKE` / `INTENT_RESULT` / `INTENT_CANCEL`), they are in the
//! catalogue, in the automatic-ack table and in `inbound`'s kernel-event list, and **nothing anywhere sent or received
//! one**. So remote dispatch was never a missing contract; it was a missing implementation of four things: send the
//! message, run the plugin locally on receipt, reply with the result, and be idempotent by request identifier.
//!
//! # Why the envelopes are built here rather than in a host
//!
//! The same reason [`crate::messaging::pair_request`] gives: the event name, the addressing and the trace have to be
//! right, and a host is not the only thing that will want to ask. It is also what lets a test check the envelope without
//! a socket — a request built inline in a command handler cannot be inspected without running the command.
//!
//! # Why the library builds the envelope and does not send it
//!
//! Because this crate has no transport and should not grow one: `worker`'s doc makes the same argument for storage
//! ("this crate knows nothing about storage ... the caller owns the write"). A host takes the [`Outbound`] that
//! [`crate::dispatch::orchestrate::decide`] returns and puts it on a link; which link, and how, is the host's business.
//!
//! # The payload, which the design does not specify
//!
//! The documents name the three constants and say nothing about what goes in them, so the shape is decided here and
//! written down:
//!
//! * [`Invoke`] — the plugin, its version, the action, and the arguments the plugin itself proposed. The action and the
//!   arguments are taken from the board's own candidate rather than from whatever the caller sent, for the reason
//!   `board::confirm` gives: acting on a choice that was never shown would run something the user did not choose.
//! * [`InvokeResult`] — whether it ran, what it returned, and why not when it did not.
//! * [`Cancel`] — why a dispatched action is being withdrawn.
//!
//! Both are `camelCase` JSON, like every other payload in this workspace.

use serde::{Deserialize, Serialize};

use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::{EventName, events};
use synra_protocol::ids::{DeviceId, PluginId, RequestId, TraceId};

use crate::messaging::MessageError;

/// What a device is asked to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invoke {
    /// The plugin that offered to handle it.
    pub plugin_id: PluginId,
    /// The version that offered, so the far side can refuse a mismatch rather than run a different build's action.
    pub plugin_version: String,
    /// What it proposed to do.
    pub action: String,
    /// Its own arguments, as the plugin proposed them.
    ///
    /// Carried rather than recomputed: a `can-handle` that proposed opening a particular URL is the whole of what the
    /// user chose, and a receiver that re-derived it from the share would be guessing at what the sender was shown.
    pub args: serde_json::Value,
}

/// What the device that ran it reports back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvokeResult {
    /// Whether the action ran.
    pub ok: bool,
    /// What it returned, when it did.
    pub result: String,
    /// Why it did not, when it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The protocol code for that failure, when it has one.
    ///
    /// # ★ Why the sentence alone was not enough
    ///
    /// Because the interface branches on the code, not on the sentence: `capability_denied` asks the user to grant
    /// something, `plugin_not_installed` asks them to install something, and `Internal` asks them to file a bug. The
    /// sender used to receive only a string and answered `Internal` for every remote failure, so the one fact the page
    /// acts on was the one the wire dropped.
    ///
    /// Optional and defaulted so a peer running an older build still produces a readable result — it just cannot say why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<synra_protocol::ErrorCode>,
    /// How long the call took on the device that made it.
    ///
    /// Measured there rather than here, because this is the only side that can see the plugin run: a sender that timed
    /// the round trip would report the network as the plugin's cost.
    pub elapsed_ms: u64,
}

/// Tells a device to stop running something it was asked to run.
///
/// # ★ Why this carries only a reason
///
/// Because the request identifier in the envelope is what names the work — "the device must be idempotent by request
/// identifier" applies to a withdrawal exactly as it does to an invocation. A payload that named the plugin and action
/// again would be a second description of the same request, and the two could disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancel {
    /// Why, in the words of whoever withdrew it.
    pub reason: String,
}

/// The envelope a host must send to withdraw a dispatched action.
///
/// # Errors
///
/// As [`invoke`].
pub fn cancel(
    from: DeviceId,
    to: DeviceId,
    payload: &Cancel,
    request_id: RequestId,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let mut envelope = build(events::INTENT_CANCEL, from, to, payload, trace_id, sent_at_ms)?;
    // ★ The identifier of the request being withdrawn, **not** a new one.
    //
    // This is the whole of how the far side knows what to stop: it raised the work under the invocation's identifier and
    // looks it up by exactly this value. A fresh identifier would name a request nobody made, the lookup would find
    // nothing, and the withdrawal would be reported as delivered while the other device carried on — which is what the
    // first version did, and what the test that withdrew from another device caught. It is a parameter rather than
    // something minted here so that a caller cannot get it wrong by omission.
    envelope.request_id = request_id;
    Ok(envelope)
}

/// Reads why a dispatched action was withdrawn.
///
/// # Errors
///
/// As [`invoke_from`].
pub fn cancel_from(envelope: &Envelope) -> Result<Cancel, MessageError> {
    read(envelope, "an intent cancellation")
}

/// The envelope a host must send so an action runs somewhere else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outbound {
    /// Which device it is for.
    pub to: DeviceId,
    /// The envelope identifier, which is also the intent's request identifier.
    ///
    /// The same value, deliberately: the request identifier is what makes a resend idempotent, and a second identifier
    /// for the same message would be a second thing for the two sides to disagree about.
    pub request_id: RequestId,
    /// What to put on the link.
    pub envelope: Envelope,
}

/// Builds the envelope that asks a device to run an action.
///
/// # Errors
///
/// [`MessageError::Envelope`] when the payload is too large for a frame, or the event name is not one this build
/// declares — both of which are impossible in practice and handled anyway, because this workspace denies `unwrap` in
/// production code.
pub fn invoke(
    from: DeviceId,
    to: DeviceId,
    payload: &Invoke,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    build(events::INTENT_INVOKE, from, to, payload, trace_id, sent_at_ms)
}

/// Builds the envelope that reports an action's outcome.
///
/// # Errors
///
/// As [`invoke`].
pub fn result(
    from: DeviceId,
    to: DeviceId,
    payload: &InvokeResult,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    build(events::INTENT_RESULT, from, to, payload, trace_id, sent_at_ms)
}

/// The shared builder, so the two events cannot be addressed differently.
fn build(
    event: &str,
    from: DeviceId,
    to: DeviceId,
    payload: &impl Serialize,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let event = EventName::parse(event)?;
    Envelope::outbound(
        OutboundSpec {
            event,
            target: to,
            from,
            trace_id,
            sent_at_ms,
            // No lifetime: an action invoked an hour ago is not one the user means to run now, and the receiver has no way
            // to tell. A message with no deadline is dropped by the link when the link closes, which is the honest
            // boundary for it — the same reasoning a clipboard message follows.
            ttl_ms: None,
        },
        Some(payload),
    )
    .map_err(MessageError::Envelope)
}

/// Reads what a device is being asked to run.
///
/// # Errors
///
/// [`MessageError::Unreadable`] when the payload is absent or is not an [`Invoke`] — named rather than silent, because a
/// request this build cannot read is one it must not guess at.
pub fn invoke_from(envelope: &Envelope) -> Result<Invoke, MessageError> {
    read(envelope, "an intent invocation")
}

/// Reads the outcome a device reported.
///
/// # Errors
///
/// As [`invoke_from`].
pub fn result_from(envelope: &Envelope) -> Result<InvokeResult, MessageError> {
    read(envelope, "an intent result")
}

/// The shared reader, so a payload that cannot be read says which one it was.
fn read<T: for<'de> Deserialize<'de>>(envelope: &Envelope, what: &str) -> Result<T, MessageError> {
    let raw = envelope.payload.as_deref().ok_or_else(|| MessageError::Unreadable {
        why: format!("{what} arrived with no payload"),
    })?;
    serde_json::from_str(raw.get()).map_err(|error| MessageError::Unreadable {
        why: format!("{what} could not be read: {error}"),
    })
}

#[cfg(test)]
mod tests;
