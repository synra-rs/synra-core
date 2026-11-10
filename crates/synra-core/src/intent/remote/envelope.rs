use super::*;

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
    build(
        events::INTENT_INVOKE,
        from,
        to,
        payload,
        trace_id,
        sent_at_ms,
    )
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
    build(
        events::INTENT_RESULT,
        from,
        to,
        payload,
        trace_id,
        sent_at_ms,
    )
}

/// The shared builder, so the two events cannot be addressed differently.
pub(super) fn build(
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
pub(super) fn read<T: for<'de> Deserialize<'de>>(
    envelope: &Envelope,
    what: &str,
) -> Result<T, MessageError> {
    let raw = envelope
        .payload
        .as_deref()
        .ok_or_else(|| MessageError::Unreadable {
            why: format!("{what} arrived with no payload"),
        })?;
    serde_json::from_str(raw.get()).map_err(|error| MessageError::Unreadable {
        why: format!("{what} could not be read: {error}"),
    })
}
