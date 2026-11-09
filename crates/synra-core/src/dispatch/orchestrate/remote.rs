use super::*;

/// Builds the invocation one device sends so another runs a candidate's action.
///
/// # Why this is one function
///
/// Because `decide` and [`resume`] must produce **the same envelope**. A second construction is a second place for the
/// action's arguments, the plugin version or the request identifier to be left out — and the request identifier is the
/// idempotency key, so getting it wrong there runs the action twice rather than failing.
pub(super) fn invocation(
    local: DeviceId,
    candidate: &crate::intent::IntentCandidate,
    target: DeviceId,
    request_id: synra_protocol::ids::RequestId,
    trace: synra_protocol::ids::TraceId,
    now_ms: i64,
) -> Result<crate::intent::remote::Outbound, RouteError> {
    let mut envelope = crate::intent::remote::invoke(
        local,
        target,
        &crate::intent::remote::Invoke {
            plugin_id: candidate.plugin_id.clone(),
            plugin_version: candidate.plugin_version.clone(),
            action: candidate.planned.action.clone(),
            // The plugin's own arguments, not the share: this is what the user was shown when they chose.
            args: candidate.planned.args.clone(),
        },
        trace,
        now_ms,
    )
    .map_err(|error| RouteError::new(synra_protocol::ErrorCode::Internal, error.to_string()))?;
    // ★ The envelope carries the id `confirm` produced, not the one `Envelope::outbound` minted. That id is what the board
    // records, what a resend reuses, and what the reply's `reply_to` returns — a fresh one here made the sender unable to
    // match the answer to its own dispatch, and the receiving side's idempotency keyed on a different id than the one the
    // board kept.
    envelope.request_id = request_id;
    Ok(crate::intent::remote::Outbound {
        to: target,
        request_id,
        envelope,
    })
}

/// The invocation a restored dispatch must be sent again under, when it is one this device sent.
///
/// # Why a restart needs this
///
/// Because a `Dispatching` intent is a request whose answer has not arrived, and the process that sent it is gone. The
/// request identifier is the idempotency key on the receiving side: re-sending it either runs the action once (the first
/// copy never arrived) or returns the outcome that already happened (the first copy did, and its reply was lost). Either
/// answer is better than a card that says "running" for a day.
///
/// # What this deliberately excludes
///
/// * An intent with an [`crate::intent::Intent::origin`] came **from** a peer and is running here; re-sending it would ask
///   the peer to run it again.
/// * A target that is this device never travelled anywhere, so there is nothing to re-send.
/// * A dispatch older than the late-answer window cannot be answered any more; [`crate::intent::persist::expire_unanswered`]
///   is what ends those.
#[must_use]
pub fn resume(
    intent: &crate::intent::Intent,
    local: DeviceId,
    now_ms: i64,
) -> Option<crate::intent::remote::Outbound> {
    let crate::intent::IntentState::Dispatching {
        candidate,
        target,
        request_id,
    } = &intent.state
    else {
        return None;
    };
    if intent.origin.is_some() || *target == local {
        return None;
    }
    if now_ms.saturating_sub(intent.created_at_ms) >= crate::late_queue::MAX_AGE_MS {
        return None;
    }
    invocation(local, candidate, *target, *request_id, intent.trace, now_ms).ok()
}

/// Runs an action another device asked for, and builds the answer to send back.
///
/// # ★ The receiving half, which is three of the design's four pieces
///
/// Doc 07 names them: *"send the message, run the plugin locally on receipt, reply with the result, and be idempotent by
/// request identifier."* The first landed in the round that made `decide` dispatch; this is the other three.
///
/// # Returns
///
/// `Some(envelope)` — the `INTENT_RESULT` to send back — or `None` when there is **nothing to answer yet**: the same
/// request arrived twice and the first copy is still running. Answering then would report an outcome that does not exist,
/// and the first run will answer on its own.
///
/// # The idempotency, and why it is not implemented here
///
/// Because it already is, and in the right place. `Board::raise` takes the origin and the request identifier and looks
/// for an intent this request already raised **before creating anything** — "the failure this exists to prevent, and the
/// one a 'did we already do this' check placed *after* creation cannot prevent". So a resent `INTENT_INVOKE` gets the
/// first attempt's intent, `created` is `false`, and the action does not run a second time. A handler that kept its own
/// cache would be a second answer to "have I seen this", and the two would disagree the first time one of them was
/// cleared.
///
/// # Errors
///
/// [`RouteError`] when the envelope is not an invocation this build can read, or when the plugin it names cannot be run.
pub fn accept_remote(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    local_device: DeviceId,
    envelope: &synra_protocol::envelope::Envelope,
    now_ms: i64,
) -> Result<Option<synra_protocol::envelope::Envelope>, RouteError> {
    let asked = crate::intent::remote::invoke_from(envelope).map_err(|error| {
        RouteError::new(
            synra_protocol::ErrorCode::InvalidArgument,
            error.to_string(),
        )
    })?;

    // The origin is the envelope's sender rather than anything the payload claims: a payload that named its own origin
    // would let one device send another's request, and the idempotency key would be the sender's to forge.
    let origin = envelope.from;
    // ★ The source is `Direct`, which is what makes this a dispatch rather than a share: the sender already named the
    // plugin and the action, so there is nothing to match and `raise` puts it straight into `Dispatching`.
    // Moved rather than cloned: `asked` is the parsed payload and nothing below this line uses it again.
    let source = IntentSource::Direct {
        plugin_id: asked.plugin_id,
        action: asked.action,
        params: asked.args,
        target: local_device,
    };

    let (id, trace, created) = board.lock().receive(
        source,
        origin,
        envelope.request_id,
        envelope.trace_id,
        now_ms,
    );

    if !created {
        // ★ The same request, arriving again. Either it is already over — in which case the answer is the recorded one,
        // because a sender whose reply was lost is entitled to the outcome rather than to a second execution — or it is
        // still running, in which case there is nothing truthful to say yet.
        let concluded = {
            let intents = board.lock();
            let found = intents.get(id).map(|intent| intent.state.clone());
            drop(intents);
            found
        };
        return match concluded.and_then(crate::intent::remote::InvokeResult::from_state) {
            Some(report) => Ok(Some(answer(origin, trace, envelope, &report, now_ms)?)),
            None => Ok(None),
        };
    }

    // The candidate the board built from the sender's own naming, read rather than reconstructed: a receiver that built
    // its own would be running an action of its choosing on a request it was asked to run.
    let candidate = {
        let intents = board.lock();
        let found = intents.get(id).and_then(|intent| match &intent.state {
            crate::intent::IntentState::Dispatching { candidate, .. } => Some(candidate.clone()),
            _ => None,
        });
        drop(intents);
        found
    };
    let Some(candidate) = candidate else {
        return Err(RouteError::new(
            synra_protocol::ErrorCode::Internal,
            "the request was raised but no candidate was recorded for it",
        ));
    };

    let started_ms = now_ms.max(0) as u64;
    let outcome = {
        let mut set = plugins.lock();
        crate::dispatch::execute(
            &mut set,
            &candidate.plugin_id,
            &candidate,
            started_ms,
            trace,
        )
    };

    let outcome = outcome
        .map_err(|failure| synra_protocol::SynraError::new(failure.code(), failure.to_string()))
        .and_then(synra_plugin_host::CallOutcome::into_result)
        .map_err(|error| error.with_trace(trace.to_string()));
    let elapsed_ms =
        u64::try_from(synra_store::sqlite::now_ms().saturating_sub(now_ms)).unwrap_or(0);
    let report = crate::intent::remote::InvokeResult::from_execution(outcome, elapsed_ms);
    let (outcome, elapsed_ms) = report.into_outcome();
    let state = board
        .lock()
        .conclude(id, outcome, elapsed_ms)
        .map_err(|refusal| refuse_intent(&refusal))?;
    match crate::intent::remote::InvokeResult::from_state(state) {
        Some(report) => Ok(Some(answer(origin, trace, envelope, &report, now_ms)?)),
        None => Ok(None),
    }
}

/// The envelope that answers an invocation.
///
/// # ★ Why the reply is addressed from the envelope rather than from this device
///
/// Because this function is given the request and not the local identity. The sender is `envelope.from`, and the answer
/// goes back exactly there — a reply addressed anywhere else is one the other side never correlates, and the request
/// identifier it carries is the same one, which is what the sender's `recall` looks up.
fn answer(
    to: DeviceId,
    trace: synra_protocol::ids::TraceId,
    request: &synra_protocol::envelope::Envelope,
    payload: &crate::intent::remote::InvokeResult,
    now_ms: i64,
) -> Result<synra_protocol::envelope::Envelope, RouteError> {
    let mut envelope = crate::intent::remote::result(request.target, to, payload, trace, now_ms)
        .map_err(|error| RouteError::new(synra_protocol::ErrorCode::Internal, error.to_string()))?;
    // ★ The answer carries the request it answers, so the sender can correlate it even if it sent several at once.
    envelope.reply_to = Some(request.request_id);
    Ok(envelope)
}
