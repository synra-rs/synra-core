use super::*;

///
/// # ★ Why this is the one place an action happens
///
/// Because everything before it is a question. The matching pass asks every plugin whether it can handle a share and
/// produces candidates; this is where the answer becomes an action — and only for the plugin the user picked, which is
/// what stops "what can handle this?" from running third-party code as a side effect.
///
/// # Errors
///
/// [`RouteError`] when the intent is unknown or is not in a state that can be decided, when the named plugin was not among
/// the candidates, or when the identifier is not one.
pub fn decide(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    local_device: DeviceId,
    intent: &str,
    plugin_id: Option<&str>,
    target: Option<&str>,
    now_ms: i64,
) -> Result<Decided, RouteError> {
    let id = parse_intent(intent)?;

    // ★ The choice is resolved against the board's own list, not accepted from the caller.
    //
    // `Board::choose` checks that the plugin and action were actually offered — "a choice arrives from an interface, and
    // acting on one that was never shown would run something the user did not choose". Looking the action up from the
    // board rather than taking it from the client also means a client sends what the user clicked (a plugin) rather than
    // a hand-built action string, which is one fewer thing for it to get wrong.
    let (candidate, request_id, target, trace) = {
        let mut intents = board.lock();
        if let Some(wanted) = plugin_id {
            let plugin = PluginId::try_from(wanted.to_owned()).map_err(|_| {
                RouteError::new(
                    synra_protocol::ErrorCode::InvalidArgument,
                    "that is not a plugin identifier",
                )
            })?;
            // The action comes from the candidate the user is choosing between, so a client cannot name an action the
            // plugin never proposed.
            let offered = intents
                .get(id)
                .and_then(|found| {
                    found
                        .state
                        .candidates()
                        .iter()
                        .find(|candidate| candidate.plugin_id == plugin)
                        .map(|candidate| candidate.planned.action.clone())
                })
                .ok_or_else(|| {
                    RouteError::new(
                        synra_protocol::ErrorCode::InvalidArgument,
                        "that plugin did not offer anything for this share",
                    )
                })?;
            intents
                .choose(id, &crate::intent::CandidateChoice::new(plugin, offered))
                .map_err(|error| refuse_intent(&error))?;
        }
        // ★ The user's answer to "where?", when the plugin that claimed the share did not say.
        //
        // This is the step that had no method: a targetless candidate settles into `Choosing`, which *is* that
        // question, and every other move either refused or undid it. `aim` is what answers it.
        if let Some(named) = target {
            let device = named.parse::<DeviceId>().map_err(|_| {
                RouteError::new(
                    synra_protocol::ErrorCode::InvalidArgument,
                    "that is not a device identifier",
                )
            })?;
            intents
                .aim(id, device)
                .map_err(|error| refuse_intent(&error))?;
        }

        // ★ The target is read **before** confirming, because confirming moves the state and the target is what decides
        // where the action runs. A remote target is not a local call with different arguments: it is a message to another
        // device, and running it here would be doing the user's action on the wrong machine.
        let target = intents.get(id).and_then(|found| match &found.state {
            crate::intent::IntentState::Confirming { target, .. } => Some(*target),
            _ => None,
        });
        let (candidate, request_id) = intents.confirm(id).map_err(|error| refuse_intent(&error))?;
        // ★ The trace is read from the board after `confirm`, in the same lock: it is the intent's own trace, and the
        // decision's log line and answer both need it.
        let trace = intents.get(id).map(|found| found.trace).ok_or_else(|| {
            RouteError::new(
                synra_protocol::ErrorCode::InvalidArgument,
                "this kernel has no such intent",
            )
        })?;
        // Released here rather than at the end of the enclosing block: the board is shared with every other connection,
        // and a guard held past its last use is a second share waiting on this one.
        drop(intents);
        (candidate, request_id, target, trace)
    };

    // ★ Only a target that is **this** device runs here.
    //
    // The board's `confirm` produces a request id because the ordinary dispatch is an envelope to another machine — "the
    // candidate and the envelope id the caller must send under". A target that is not this device therefore produces that
    // envelope, and **not** a local call: running it here would be doing the user's action on the machine they shared
    // *from* rather than the one they chose.
    //
    // ★ This used to refuse, and the refusal was honest while nothing could send.
    //
    // The messenger existed and nobody dispatched with it: `INTENT_INVOKE` was in the catalogue, in the automatic-ack
    // table and in `inbound`'s kernel-event list, with **no sender and no receiver anywhere in the repository**. The board
    // already had both halves of the idempotency the design asks for — `confirm` reuses a request id rather than minting
    // a new one, and `recall` looks an arriving request up by its origin. What was missing was exactly this: build the
    // message, and hand it to a host that can put it on a link.
    if let Some(device) = target.filter(|device| *device != local_device) {
        // ★ The state and the trace are read from the board, never invented.
        //
        // The first version of this branch built a `Dispatching` by hand to get its name, which needed a candidate that
        // does not exist — a fabricated value standing in for the real one, in the one place whose whole purpose is that
        // nothing is fabricated. `confirm` has already moved the intent into `Dispatching` with the candidate it chose,
        // so the board is asked what it holds.
        let state = {
            let intents = board.lock();
            let found = intents.get(id).ok_or_else(|| {
                RouteError::new(
                    synra_protocol::ErrorCode::InvalidArgument,
                    "this kernel has no such intent",
                )
            })?;
            let answer = state_name(&found.state);
            // Released rather than left to the end of the block: the board is shared with every other connection, and the
            // envelope below is built while holding nothing.
            drop(intents);
            answer
        };
        let outbound = invocation(local_device, &candidate, device, request_id, trace, now_ms)?;

        return Ok(Decided {
            intent_id: id,
            trace,
            request_id,
            plugin_id: candidate.plugin_id,
            action: candidate.planned.action,
            // Nothing ran, and nothing failed: it is in flight. `is_dispatched` is what a caller branches on.
            ok: false,
            result: serde_json::Value::Null,
            error: None,
            state,
            outbound: Some(outbound),
        });
    }

    // ★ The call itself. `execute` is the only function in the system that runs a plugin's action, and it is reached
    // from here alone.
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
    // Measured from the moment the call was made rather than from the intent's creation: what a user reads is "this took
    // 40 ms", and an intent that sat in a prompt for a minute did not take a minute to run.
    let elapsed_ms =
        u64::try_from(synra_store::sqlite::now_ms().saturating_sub(now_ms)).unwrap_or(0);
    let report = crate::intent::remote::InvokeResult::from_execution(outcome, elapsed_ms);
    let (outcome, elapsed_ms) = report.into_outcome();
    let state = board
        .lock()
        .conclude(id, outcome, elapsed_ms)
        .map_err(|error| refuse_intent(&error))?;
    let status = state_name(&state);
    let (ok, result, error, _) = crate::intent::remote::InvokeResult::from_state(state).map_or(
        (false, serde_json::Value::Null, None, elapsed_ms),
        crate::intent::remote::InvokeResult::into_parts,
    );

    Ok(Decided {
        intent_id: id,
        trace,
        request_id,
        plugin_id: candidate.plugin_id,
        action: candidate.planned.action,
        ok,
        result,
        error,
        state: status,
        // It ran here, so there is nothing to send.
        outbound: None,
    })
}
