use super::*;

/// Everything an inbound share is routed with.
///
/// # ★ Why these travel together
///
/// Because routing needs both and they are only useful together: the plugins to ask and the board to hold the answers.
/// Passing them as two arguments through the transport would be two chances to pass the wrong one, and the connection
/// handler has no business knowing which is which.
///
/// ★ It does **not** hold this device's identifier, though an earlier version did. Deciding an intent needs to know which
/// device is local — that is how "run it here" is told from "send it somewhere" — but *routing* only asks the plugins and
/// writes the answers down, and a field nothing reads is a field that will be read wrongly later. The identifier lives
/// where the decision is made, which is the control protocol's `intent_decide`.
pub struct Router {
    plugins: Arc<Mutex<PluginSet>>,
    board: Arc<Mutex<Board>>,
}

impl Router {
    /// A router over the daemon's own plugins and intents.
    #[must_use]
    pub const fn new(plugins: Arc<Mutex<PluginSet>>, board: Arc<Mutex<Board>>) -> Self {
        Self { plugins, board }
    }

    /// Routes a share that arrived from a peer.
    ///
    /// The same call `intent_dispatch` makes, because a share from another device and one from this machine's own share
    /// sheet are the same event with a different origin — and two paths would be two places for the rules to differ.
    ///
    /// # Errors
    ///
    /// [`RouteError`] when the item cannot be serialised into the shape a plugin is asked about.
    pub fn route(&self, item: &ShareItem, now_ms: i64) -> Result<Routed, RouteError> {
        dispatch(&self.plugins, &self.board, item, now_ms)
    }
}

/// Routes a share and reports what the plugins said.
///
/// # Errors
///
/// [`RouteError`] when the item cannot be serialised into the shape a plugin is asked about, which is a fact about the
/// item rather than about any plugin.
pub fn dispatch(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    item: &ShareItem,
    now_ms: i64,
) -> Result<Routed, RouteError> {
    // The same JSON the plugin is handed as `can-handle`'s argument. It is produced from the typed item rather than
    // passed through, so a caller cannot ask a plugin about something that is not a share item.
    let item_json = serde_json::to_string(item).map_err(|error| {
        RouteError::new(
            synra_protocol::ErrorCode::Internal,
            format!("the shared item could not be read: {error}"),
        )
    })?;

    // ★ The lock is taken and released around the board work alone, not around building the answer.
    //
    // The board is shared with every other connection, so a guard held while this function formats JSON is a guard that
    // blocks a second share for as long as the first one takes to serialise. Everything the answer needs is collected
    // inside the scope and the guard goes with it.
    let (id, trace, created, report, settled, candidates) = {
        let mut intents = board.lock();
        let (id, trace, created) = intents.raise(
            IntentSource::Share {
                item: item.clone(),
                source_app: None,
            },
            // ★ The default, which is `Automatic`: it is the ordinary share — "open this link", one plugin claims it —
            // and a prompt for that is a dialog the user learns to dismiss. What makes it safe is that `Automatic` is not
            // "pick the first": with two candidates the user is asked exactly as they would be otherwise, so a plugin
            // cannot make itself the silent answer by being installed first.
            crate::intent::Choice::default(),
            None,
            None,
            now_ms,
        );

        let report = {
            let mut set = plugins.lock();
            Matcher::new(&mut set).match_share(&mut intents, id, &item_json, now_ms)
        };

        // ★ The window is closed rather than waited out.
        //
        // `settle` only acts once `now` is past the deadline, and the deadline exists to bound the pass — "one plugin
        // that never returns must not hold up a share for ever". The pass is over by the time we get here: every plugin
        // has answered, or the deadline stopped us asking. So the window's purpose is served, and waiting out the
        // remainder would be a sleep for its own sake.
        let window_ms = i64::try_from(intents.matching_window().as_millis()).unwrap_or(i64::MAX);
        let settled = intents.settle(id, now_ms.saturating_add(window_ms));
        let candidates = candidates_of(&intents, id);
        // Released here rather than at the end of the enclosing block: the board is shared with every other connection,
        // and a guard held past its last use is a second share waiting on this one.
        drop(intents);
        (id, trace, created, report, settled, candidates)
    };

    Ok(Routed {
        intent_id: id,
        trace,
        created,
        state: settled.map_or("unknown", |state| state_name(&state)),
        candidates,
        report,
    })
}

/// Reads an intent's current state and candidates.
///
/// # Errors
///
/// [`RouteError`] when the identifier is not one, or names an intent this kernel never raised or has already forgotten —
/// which is a different answer from "it is over", and the two must not be conflated.
pub fn snapshot(board: &Arc<Mutex<Board>>, intent: &str) -> Result<IntentView, RouteError> {
    let id = parse_intent(intent)?;
    let intents = board.lock();
    let Some(found) = intents.get(id) else {
        return Err(RouteError::new(
            synra_protocol::ErrorCode::InvalidArgument,
            "this kernel has no such intent",
        ));
    };
    let answer = IntentView {
        intent_id: id,
        trace: found.trace,
        state: state_name(&found.state),
        candidates: candidates_of(&intents, id),
        created_at_ms: found.created_at_ms,
        error: match &found.state {
            crate::intent::IntentState::Failed { error, .. } => Some(error.clone()),
            // A refusal is not a failure of the action — nothing ran — but its type carries the check's own sentence and
            // code for the interface to show, so dropping it left the page with "Refused" and no reason.
            crate::intent::IntentState::Refused { refusal } => Some(
                synra_protocol::SynraError::new(refusal.code, refusal.detail.clone()),
            ),
            // A timeout has a state word of its own, but not a reason: "Timed out" does not say whether the matching
            // window closed or a device never answered, and it does not say for how long. The `after` is that fact, and the
            // protocol's `Timeout` code is what the interface translates into a sentence.
            crate::intent::IntentState::TimedOut { after } => {
                Some(synra_protocol::SynraError::new(
                    synra_protocol::ErrorCode::Timeout,
                    format!("nothing answered within {} ms", after.as_millis()),
                ))
            }
            // The other final states are not failures with a sentence: inventing an error for them would give the
            // interface a second, worse description.
            _ => None,
        },
    };
    drop(intents);
    Ok(answer)
}

/// Applies the outcome a device reported for an action this one dispatched.
///
/// # Why the reply's two fields are both needed
///
/// Because `reply_to` says which request this answers and `from` says which device answered it. A result with no
/// `reply_to` cannot be matched to anything, and one whose sender is not the device the action was dispatched to is not an
/// answer to this dispatch — it is either a mistake or somebody else's reply.
///
/// # Errors
///
/// [`RouteError`] when the envelope is not a readable result, or when the intent it names cannot take the outcome.
pub fn apply_result(
    board: &Arc<Mutex<Board>>,
    envelope: &synra_protocol::envelope::Envelope,
) -> Result<Option<synra_protocol::ids::IntentId>, RouteError> {
    let reported = crate::intent::remote::result_from(envelope).map_err(|error| {
        RouteError::new(
            synra_protocol::ErrorCode::InvalidArgument,
            error.to_string(),
        )
    })?;
    let Some(request) = envelope.reply_to else {
        return Err(RouteError::new(
            synra_protocol::ErrorCode::InvalidArgument,
            "this result does not name the request it answers",
        ));
    };
    let found = {
        let intents = board.lock();
        let id = intents.dispatched_to(request, envelope.from);
        let found = id.and_then(|id| intents.get(id).map(|intent| (id, intent.trace)));
        // Released rather than left to the end of the block: the conclude below takes the same board, and holding one
        // guard while asking for the second is a deadlock rather than a slow path.
        drop(intents);
        found
    };
    let Some((id, trace)) = found else {
        // An outcome for a request this device is not waiting on. Ignored rather than refused: a retry, a duplicate or a
        // reply to work that was cancelled is not a protocol error, and saying so keeps a link open.
        return Ok(None);
    };
    let (outcome, elapsed_ms) = reported.into_outcome();
    let outcome = outcome.map_err(|error| error.with_trace(trace.to_string()));
    board
        .lock()
        .conclude(id, outcome, elapsed_ms)
        .map_err(|error| refuse_intent(&error))?;
    Ok(Some(id))
}
