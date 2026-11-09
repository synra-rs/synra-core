use super::*;

/// Abandons an intent.
///
/// # Errors
///
/// [`RouteError`] when the identifier is not one or names an intent this kernel never raised.
pub fn cancel(
    board: &Arc<Mutex<Board>>,
    local_device: DeviceId,
    intent: &str,
    reason: &str,
) -> Result<StateChange, RouteError> {
    let id = parse_intent(intent)?;

    // ★ Read before the move, because cancelling destroys what is needed to tell the far side.
    //
    // A dispatched intent is running on another device, and that device hears about a change of mind only if it is told.
    // The fact that it *was* dispatched — and where — lives in the state this call is about to replace, so reading it
    // afterwards would be reading `Cancelled` and nothing else. The first version of this was a local-only cancellation,
    // which left the other device running work nobody wanted and then reporting its result.
    let dispatched = {
        let intents = board.lock();
        let found = intents.get(id).and_then(|intent| match &intent.state {
            crate::intent::IntentState::Dispatching {
                target, request_id, ..
            } => Some((*target, intent.trace, *request_id)),
            _ => None,
        });
        drop(intents);
        found
    };

    let state = board
        .lock()
        .cancel(id, reason)
        .map_err(|error| refuse_intent(&error))?;

    // ★ Why the local device is a parameter rather than something read from the intent
    //
    // The first version of this tried to recover it from the board and wrote a nil identifier when the intent had been
    // raised here, which is not a device — the envelope would have said it was from nobody, and the far side's reply
    // would have gone nowhere. An intent raised locally records no origin (there is nothing to record); the origin of one
    // raised on somebody else's behalf is *them*. Neither is this device, so the caller says who it is, exactly as
    // `decide` does.
    let outbound = match dispatched {
        Some((target, trace, request_id)) => {
            let envelope = crate::intent::remote::cancel(
                local_device,
                target,
                &crate::intent::remote::Cancel {
                    reason: reason.to_owned(),
                },
                request_id,
                trace,
                synra_store::sqlite::now_ms(),
            )
            .map_err(|error| {
                RouteError::new(synra_protocol::ErrorCode::Internal, error.to_string())
            })?;
            Some(crate::intent::remote::Outbound {
                to: target,
                request_id,
                envelope,
            })
        }
        None => None,
    };

    Ok(StateChange {
        intent_id: id,
        state: state_name(&state),
        outbound,
    })
}

/// Stops work another device withdrew.
///
/// # Returns
///
/// The intent that was cancelled, or `None` when this device never raised one for that request — a cancellation for work
/// that is not here is **not** an error: the sender cannot know whether its invocation arrived, so it withdraws either
/// way, and refusing the withdrawal would leave it unable to clean up.
///
/// # ★ Why there is no reply
///
/// Because the design does not give the intent events an application-level answer beyond `INTENT_RESULT`. They are in the
/// automatic-ack table, so the transport confirms delivery; an acknowledgement envelope of our own would be a second
/// mechanism for the same fact, and the two would disagree the first time one was lost.
///
/// # Errors
///
/// [`RouteError`] when the envelope is not a cancellation this build can read.
pub fn accept_cancel(
    board: &Arc<Mutex<Board>>,
    envelope: &synra_protocol::envelope::Envelope,
) -> Result<Option<synra_protocol::ids::IntentId>, RouteError> {
    let asked = crate::intent::remote::cancel_from(envelope).map_err(|error| {
        RouteError::new(
            synra_protocol::ErrorCode::InvalidArgument,
            error.to_string(),
        )
    })?;

    // """ + S + """ `recall` is the lookup, and it is the same one the idempotency uses.
    //
    // It finds the intent *this* device raised for that origin and request — which is exactly the work the sender is
    // withdrawing, and the only thing a cancellation may touch. Looking it up by anything else, such as the plugin it
    // names, would let one device cancel another's work.
    let found = {
        let intents = board.lock();
        let answer = intents
            .recall(envelope.from, envelope.request_id)
            .map(|intent| intent.id);
        drop(intents);
        answer
    };

    let Some(id) = found else {
        return Ok(None);
    };

    board
        .lock()
        .cancel(id, &asked.reason)
        .map_err(|error| refuse_intent(&error))?;

    Ok(Some(id))
}
