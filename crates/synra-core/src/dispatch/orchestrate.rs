//! Routing a share: asking the plugins, applying the answer, running what was chosen.
//!
//! # ★ Why this is in the library rather than in a host
//!
//! Because **two hosts need it**. The daemon routes a share that arrives from a peer and one the CLI hands it; the desktop
//! shell routes one from this machine's own share sheet. Until this module existed, the whole of that orchestration lived
//! in `synra-daemon/src/runtime/intent.rs` — **inside a binary** — so the shell could not reuse a line of it and would
//! have had to duplicate roughly two hundred and fifty. The shell's `Board` was constructed and never used, and its four
//! intent commands were explained away as "needs the intent board behind `AppState`", which was false: the board was
//! already there.
//!
//! # What is decided here, and what is not
//!
//! This raises the intent, runs the matching pass, closes the window, applies the user's answer and runs the action they
//! chose. What it does **not** do is decide *where* the action runs: a target that is not this device is a message to
//! another device, and sending one is the transport's business rather than this module's. That case is refused rather than
//! run locally, which would be doing the user's action on the machine they shared *from*.
//!
//! # Why the errors are the protocol's own codes
//!
//! Because the two hosts report failures differently — the daemon as a control-protocol refusal, the shell as an
//! `IpcError` — and a library that picked one would make the other translate a foreign type. [`RouteError`] carries the
//! `ErrorCode` the contract already defines and a sentence for a person, and each host wraps that in its own shape: one
//! line each, and no shared vocabulary invented for the purpose.

use std::sync::Arc;

use parking_lot::Mutex;

use synra_protocol::ids::{DeviceId, PluginId};
use synra_protocol::inbound::ShareItem;

use super::matching::Matcher;
use super::plugins::PluginSet;
use crate::intent::{Board, IntentSource};

/// What went wrong while routing, in the protocol's own terms.
///
/// # Why a code and not a variant per failure
///
/// Because every failure here is one a caller already has a code for: an identifier that is not one, a plugin that offered
/// nothing, an action that cannot run on this device. A bespoke enum would be a second vocabulary for the same facts, and
/// each host would translate it back into the codes below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteError {
    /// Which of the contract's codes this is.
    pub code: synra_protocol::ErrorCode,
    /// A sentence for a person, which is what a host shows.
    pub message: String,
}

impl RouteError {
    /// A failure with its code and a sentence.
    #[must_use]
    pub fn new(code: synra_protocol::ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RouteError {}



/// What a routing pass produced.
///
/// # ★ Why a struct rather than JSON
///
/// Because two hosts want different things from the same fact. The daemon renders it for a control-protocol client; the
/// desktop shell fills an `IntentSnapshot` whose fields (a device per candidate, whether it is online, when the intent
/// started) are **not in this shape at all** — so a shell handed JSON could not produce a faithful DTO and would have to
/// invent the missing fields. Typed values let each host ask for what it needs, and the JSON is one rendering among
/// possible others rather than the only way out of the library.
#[derive(Debug, Clone)]
pub struct Routed {
    /// Which intent this is, which a caller uses to answer it later.
    pub intent_id: synra_protocol::ids::IntentId,
    /// The trace this intent belongs to, for a log filter.
    pub trace: synra_protocol::ids::TraceId,
    /// Whether this call raised the intent, or found one already raised for the same request.
    pub created: bool,
    /// What stage it settled at.
    pub state: &'static str,
    /// What the plugins offered.
    pub candidates: Vec<CandidateView>,
    /// The pass's own account of itself.
    pub report: super::matching::MatchReport,
}

/// One way an intent could be handled.
#[derive(Debug, Clone)]
pub struct CandidateView {
    /// The plugin that answered.
    pub plugin_id: PluginId,
    /// The version that answered.
    pub plugin_version: String,
    /// What it proposes to do.
    pub action: String,
    /// Its arguments, as the plugin proposed them.
    pub args: serde_json::Value,
    /// One line for a prompt.
    pub title: String,
    /// Optional detail.
    pub detail: Option<String>,
    /// The capabilities the action needs.
    pub required_caps: Vec<String>,
    /// Where it suggested running, when it had an opinion.
    pub suggested_target: Option<DeviceId>,
}

/// What has become of an intent.
#[derive(Debug, Clone)]
pub struct IntentView {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
    /// Its trace.
    pub trace: synra_protocol::ids::TraceId,
    /// What stage it is at.
    pub state: &'static str,
    /// What the plugins offered.
    pub candidates: Vec<CandidateView>,
    /// When it was raised, in milliseconds since the epoch.
    ///
    /// ★ The snapshot used to report the moment it was **read** under this name. The board has carried the real value from
    /// the first version; not carrying it made "how long has this been running?" answer "zero", every time.
    pub created_at_ms: i64,
    /// Why it failed or was refused, when either happened.
    ///
    /// ★ The board has carried this since `IntentState::Failed` was written, and the view dropped it — so the interface's
    /// "why did it fail?" line read a field no host ever filled. A refusal carries the admission check's own sentence and
    /// code, which its type documents as "a sentence the interface can show".
    pub error: Option<synra_protocol::SynraError>,
}

/// The result of running the action a user chose.
#[derive(Debug, Clone)]
pub struct Decided {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
    /// The trace this action's steps are grouped under.
    ///
    /// ★ Carried so the log line that says what happened can be found by `synra logs --trace`: the routing line already
    /// names the trace, and a decision without it would be the one step a user cannot correlate.
    pub trace: synra_protocol::ids::TraceId,
    /// The envelope id a remote dispatch would be sent under.
    pub request_id: synra_protocol::ids::RequestId,
    /// Which plugin ran.
    pub plugin_id: PluginId,
    /// Which of its actions.
    pub action: String,
    /// Whether it succeeded.
    pub ok: bool,
    /// What it returned, or a sentence describing how it did not.
    pub result: String,
    /// Why the host could not make the call, when that is what happened.
    pub error: Option<String>,
    /// What stage the intent ended at.
    pub state: &'static str,
    /// The envelope a host must send, when the action runs on another device.
    ///
    /// ★ Why the library builds this and does not send it
    ///
    /// Because this crate has no transport and should not grow one — `worker`'s doc makes the same argument for storage
    /// ("this crate knows nothing about storage ... the caller owns the write"). Which link, and how, is the host's
    /// business; *what* to send is not, because the event name, the addressing and the payload shape have to be right and
    /// a host is not the only thing that will want to ask.
    ///
    /// ★ And why `ok` is then `false` rather than a third value
    ///
    /// Because there is no third value in the field. When this is `Some`, the intent is `dispatching`: nothing has run
    /// yet and its outcome arrives later as an `INTENT_RESULT`. A caller must branch on this field before reading `ok`,
    /// and [`Decided::is_dispatched`] is what says so without inspecting a string.
    pub outbound: Option<crate::intent::remote::Outbound>,
}

impl Decided {
    /// Whether the action was handed to another device rather than run here.
    ///
    /// A method rather than a comparison on `state`, because the state is a string for a JSON field and a caller that
    /// compared it to `"dispatching"` would be one keystroke from comparing it to nothing at all.
    #[must_use]
    pub const fn is_dispatched(&self) -> bool {
        self.outbound.is_some()
    }
}

/// An intent's state after a move that produces nothing else.
#[derive(Debug, Clone)]
pub struct StateChange {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
    /// What stage it is at now.
    pub state: &'static str,
    /// The envelope a host must send, when the intent had been dispatched to another device.
    ///
    /// Cancelling locally is not enough for a dispatched intent: the device that is running it has no other way to hear
    /// that the user changed their mind, and it would finish and report a result for work nobody wants.
    pub outbound: Option<crate::intent::remote::Outbound>,
}

impl CandidateView {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pluginId": self.plugin_id.as_str(),
            "pluginVersion": self.plugin_version,
            "action": self.action,
            // The plugin's own arguments, so a client can show what would be acted on — the URL a link candidate
            // would open, rather than only the sentence describing it.
            "args": self.args,
            "title": self.title,
            "detail": self.detail,
            "requiredCaps": self.required_caps,
        })
    }
}

impl Routed {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "trace": self.trace.to_string(),
            // `false` means the same request had already raised an intent. Reported rather than hidden: a caller
            // retrying after a lost answer needs to know it did not create a second one.
            "created": self.created,
            "state": self.state,
            "candidates": self.candidates.iter().map(CandidateView::to_json).collect::<Vec<_>>(),
            // ★ The pass's own report, which is what separates "nothing is installed" from "everything
            // crashed". The two look identical from a candidate list, and a user cannot tell them apart.
            "asked": self.report.asked,
            "handled": self.report.handled,
            "declined": self.report.declined,
            "offered": self.report.offered,
            "misbehaved": self.report.misbehaved.iter().map(|misbehaviour| {
                serde_json::json!({
                    "pluginId": misbehaviour.plugin_id.as_str(),
                    "detail": misbehaviour.detail,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

impl IntentView {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "trace": self.trace.to_string(),
            "state": self.state,
            "createdAtMs": self.created_at_ms,
            "candidates": self.candidates.iter().map(CandidateView::to_json).collect::<Vec<_>>(),
            // `null` when there is none: a client that branches on the field has one shape to read, and `null` is the
            // answer to "why did it fail?" for an intent that has not.
            "error": self.error.as_ref().and_then(|error| serde_json::to_value(error).ok()),
        })
    }
}

impl Decided {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "trace": self.trace.to_string(),
            "requestId": self.request_id.to_string(),
            "pluginId": self.plugin_id.as_str(),
            "action": self.action,
            "ok": self.ok,
            "result": self.result,
            "error": self.error,
            "state": self.state,
            // ★ Present only when the action was handed to another device.
            //
            // Without it, `"ok": false` on a dispatched intent reads as "it did not work" — and it did not *not* work, it
            // has not happened yet. The field is the qualification, and it is emitted next to `ok` rather than instead of
            // it so a client that only knows the old shape still reads a state it can act on.
            "dispatchedTo": self.outbound.as_ref().map(|outbound| outbound.to.to_string()),
        })
    }
}

impl StateChange {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "state": self.state,
            // ★ Present only when the intent had been dispatched and the far side is being told to stop.
            //
            // Emitted for the same reason `Decided` emits it: a client that saw only `"state": "cancelled"` would think the
            // work had stopped, when what has happened is that this side has stopped tracking it and a message is on its
            // way. The device that is running it has not been un-asked yet.
            "cancelledAt": self.outbound.as_ref().map(|outbound| outbound.to.to_string()),
        })
    }
}

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
    pub fn route(
        &self,
        item: &ShareItem,
        now_ms: i64,
    ) -> Result<Routed, RouteError> {
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
            IntentSource::Share { item: item.clone(), source_app: None },
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
            crate::intent::IntentState::Refused { refusal } => {
                Some(synra_protocol::SynraError::new(refusal.code, refusal.detail.clone()))
            }
            // A timeout has a state word of its own, but not a reason: "Timed out" does not say whether the matching
            // window closed or a device never answered, and it does not say for how long. The `after` is that fact, and the
            // protocol's `Timeout` code is what the interface translates into a sentence.
            crate::intent::IntentState::TimedOut { after } => Some(synra_protocol::SynraError::new(
                synra_protocol::ErrorCode::Timeout,
                format!("nothing answered within {} ms", after.as_millis()),
            )),
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
        RouteError::new(synra_protocol::ErrorCode::InvalidArgument, error.to_string())
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
        // Released rather than left to the end of the block: the conclude below takes the same board, and holding one
        // guard while asking for the second is a deadlock rather than a slow path.
        drop(intents);
        id
    };
    let Some(id) = found else {
        // An outcome for a request this device is not waiting on. Ignored rather than refused: a retry, a duplicate or a
        // reply to work that was cancelled is not a protocol error, and saying so keeps a link open.
        return Ok(None);
    };
    board
        .lock()
        .conclude(
            id,
            reported.ok,
            &reported.result,
            reported
                .error
                .map(|error| synra_protocol::SynraError::new(synra_protocol::ErrorCode::Internal, error)),
            reported.elapsed_ms,
        )
        .map_err(|error| refuse_intent(&error))?;
    Ok(Some(id))
}
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
            intents.aim(id, device).map_err(|error| refuse_intent(&error))?;
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
        let trace = intents
            .get(id)
            .map(|found| found.trace)
            .ok_or_else(|| {
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
            let found = intents
                .get(id)
                .ok_or_else(|| RouteError::new(synra_protocol::ErrorCode::InvalidArgument, "this kernel has no such intent"))?;
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
            result: String::new(),
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
        crate::dispatch::execute(&mut set, &candidate.plugin_id, &candidate, started_ms, trace)
    };

    let (ok, result, error) = match outcome {
        Ok(synra_plugin_host::CallOutcome::Ok(payload)) => (true, payload, None),
        Ok(other) => (false, other.as_str().to_owned(), None),
        Err(failure) => (false, String::new(), Some(failure.to_string())),
    };
    // Measured from the moment the call was made rather than from the intent's creation: what a user reads is "this took
    // 40 ms", and an intent that sat in a prompt for a minute did not take a minute to run.
    let elapsed_ms = u64::try_from(synra_store::sqlite::now_ms().saturating_sub(now_ms)).unwrap_or(0);
    let state = board
        .lock()
        .conclude(id, ok, &result, error.as_deref().map(synra_error), elapsed_ms)
        .map_err(|error| refuse_intent(&error))?;

    Ok(Decided {
        intent_id: id,
        trace,
        request_id,
        plugin_id: candidate.plugin_id,
        action: candidate.planned.action,
        ok,
        result,
        error,
        state: state_name(&state),
        // It ran here, so there is nothing to send.
        outbound: None,
    })
}

/// Builds the invocation one device sends so another runs a candidate's action.
///
/// # Why this is one function
///
/// Because `decide` and [`resume`] must produce **the same envelope**. A second construction is a second place for the
/// action's arguments, the plugin version or the request identifier to be left out — and the request identifier is the
/// idempotency key, so getting it wrong there runs the action twice rather than failing.
fn invocation(
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
    Ok(crate::intent::remote::Outbound { to: target, request_id, envelope })
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
    let crate::intent::IntentState::Dispatching { candidate, target, request_id } = &intent.state else {
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
        RouteError::new(synra_protocol::ErrorCode::InvalidArgument, error.to_string())
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

    let (id, trace, created) = board.lock().raise(
        source,
        crate::intent::Choice::default(),
        Some(origin),
        Some(envelope.request_id),
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
        return match concluded {
            Some(crate::intent::IntentState::Succeeded { result, elapsed_ms }) => {
                Ok(Some(answer(origin, trace, envelope, &crate::intent::remote::InvokeResult {
                    ok: true,
                    result: result.as_str().unwrap_or_default().to_owned(),
                    error: None,
                    elapsed_ms,
                }, now_ms)?))
            }
            Some(crate::intent::IntentState::Failed { error, elapsed_ms }) => {
                Ok(Some(answer(origin, trace, envelope, &crate::intent::remote::InvokeResult {
                    ok: false,
                    result: String::new(),
                    error: Some(error.to_string()),
                    elapsed_ms,
                }, now_ms)?))
            }
            // Still in flight, or ended some other way with nothing to report as an outcome. The first copy answers.
            _ => Ok(None),
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
        crate::dispatch::execute(&mut set, &candidate.plugin_id, &candidate, started_ms, trace)
    };

    let (ok, result, error) = match outcome {
        Ok(synra_plugin_host::CallOutcome::Ok(payload)) => (true, payload, None),
        Ok(other) => (false, other.as_str().to_owned(), None),
        Err(failure) => (false, String::new(), Some(failure.to_string())),
    };
    let elapsed_ms = u64::try_from(synra_store::sqlite::now_ms().saturating_sub(now_ms)).unwrap_or(0);
    board
        .lock()
        .conclude(id, ok, &result, error.as_deref().map(synra_error), elapsed_ms)
        .map_err(|refusal| refuse_intent(&refusal))?;

    Ok(Some(answer(
        origin,
        trace,
        envelope,
        &crate::intent::remote::InvokeResult {
            ok,
            result,
            error,
            elapsed_ms,
        },
        now_ms,
    )?))
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
            crate::intent::IntentState::Dispatching { target, request_id, .. } => {
                Some((*target, intent.trace, *request_id))
            }
            _ => None,
        });
        drop(intents);
        found
    };

    let state = board.lock().cancel(id, reason).map_err(|error| refuse_intent(&error))?;

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
                &crate::intent::remote::Cancel { reason: reason.to_owned() },
                request_id,
                trace,
                synra_store::sqlite::now_ms(),
            )
            .map_err(|error| RouteError::new(synra_protocol::ErrorCode::Internal, error.to_string()))?;
            Some(crate::intent::remote::Outbound { to: target, request_id, envelope })
        }
        None => None,
    };

    Ok(StateChange { intent_id: id, state: state_name(&state), outbound })
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
        RouteError::new(synra_protocol::ErrorCode::InvalidArgument, error.to_string())
    })?;

    // """ + S + """ `recall` is the lookup, and it is the same one the idempotency uses.
    //
    // It finds the intent *this* device raised for that origin and request — which is exactly the work the sender is
    // withdrawing, and the only thing a cancellation may touch. Looking it up by anything else, such as the plugin it
    // names, would let one device cancel another's work.
    let found = {
        let intents = board.lock();
        let answer = intents.recall(envelope.from, envelope.request_id).map(|intent| intent.id);
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

/// A stable error the board records, from a message.
///
/// The board wants a `SynraError` so a device that was told to run something receives a code it can branch on rather than
/// a sentence. `Internal` is the honest code for "the host could not make the call": the plugin did not fail, the host
/// did.
fn synra_error(message: &str) -> synra_protocol::SynraError {
    synra_protocol::SynraError::new(synra_protocol::ErrorCode::Internal, message)
}

/// An intent identifier from its text.
fn parse_intent(text: &str) -> Result<synra_protocol::ids::IntentId, RouteError> {
    text.parse::<synra_protocol::ids::IntentId>().map_err(|_| {
        RouteError::new(
            synra_protocol::ErrorCode::InvalidArgument,
            "that is not an intent identifier",
        )
    })
}

/// Turns a board error into a refusal, keeping its own words.
///
/// # Why the board's message is passed through
///
/// Because it already says what a user needs — "this intent is not waiting to be confirmed, it is choosing" names both the
/// attempt and the state — and re-wording it here would be a second description of the same state machine, free to
/// disagree with the first.
fn refuse_intent(error: &crate::intent::IntentError) -> RouteError {
    RouteError::new(synra_protocol::ErrorCode::InvalidArgument, error.to_string())
}

/// The candidates the board is holding for an intent.
///
/// # Why this is not `IntentState::candidates()`
///
/// Because that method answers "what is the user choosing **between**", and it returns an empty slice once the board has
/// settled on one — `Confirming` holds a single candidate rather than a list. A snapshot built from it alone showed a
/// share that had been routed successfully as having no candidates at all, which is precisely the fact a prompt needs.
/// The states are listed here rather than defaulted, so a state added later has to be considered.
fn candidates_of(board: &Board, id: synra_protocol::ids::IntentId) -> Vec<CandidateView> {
    use crate::intent::IntentState;
    let Some(intent) = board.get(id) else {
        return Vec::new();
    };
    let one;
    let candidates: &[crate::intent::IntentCandidate] = match &intent.state {
        IntentState::Matching { candidates, .. } | IntentState::Choosing { candidates } => candidates,
        IntentState::Confirming { candidate, .. } | IntentState::Dispatching { candidate, .. } => {
            one = std::slice::from_ref(candidate);
            one
        }
        // Over, one way or another, and there is nothing left to offer.
        _ => &[],
    };
    candidates
        .iter()
        .map(|candidate| CandidateView {
            plugin_id: candidate.plugin_id.clone(),
            plugin_version: candidate.plugin_version.clone(),
            action: candidate.planned.action.clone(),
            args: candidate.planned.args.clone(),
            title: candidate.title.clone(),
            detail: candidate.detail.clone(),
            required_caps: candidate.required_caps.clone(),
            suggested_target: candidate.suggested_target,
        })
        .collect()
}

/// A stable name for a state, for a client that switches on it.
const fn state_name(state: &crate::intent::IntentState) -> &'static str {
    // One definition, in `IntentState::name`. The match that used to stand here was a second copy, and the two names
    // (`kind` for storage, `name` for the wire) are documented where the states are.
    state.name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Choice, IntentSource};

    fn device(id: &str) -> DeviceId {
        id.parse().expect("a device id")
    }

    fn local() -> DeviceId {
        device("11111111-1111-4111-8111-111111111111")
    }

    fn peer() -> DeviceId {
        device("22222222-2222-4222-8222-222222222222")
    }

    /// A candidate named outright, which is the state a restored dispatch is in.
    fn direct(target: DeviceId) -> IntentSource {
        IntentSource::Direct {
            plugin_id: PluginId::parse("@acme/opener").expect("a plugin id"),
            action: "open".to_owned(),
            params: serde_json::json!({"url": "https://example.com"}),
            target,
        }
    }

    #[test]
    fn a_restored_dispatch_is_rebuilt_as_the_invocation_it_was() {
        // ★ The whole reason this function exists: the request id is the receiving side's idempotency key. A rebuilt
        // envelope with a fresh id is a second request, and the receiver's cache would run the action twice.
        let mut board = Board::new();
        let request_id = synra_protocol::ids::RequestId::new();
        let (id, trace, created) =
            board.raise(direct(peer()), Choice::Automatic, None, Some(request_id), 1_000);
        assert!(created, "a direct source is raised rather than matched");

        let outbound = resume(board.get(id).expect("raised"), local(), 2_000).expect("work this device sent");

        assert_eq!(outbound.to, peer());
        assert_eq!(outbound.request_id, request_id);
        assert_eq!(outbound.envelope.from, local());
        assert_eq!(outbound.envelope.target, peer());
        assert_eq!(outbound.envelope.trace_id, trace);
        assert_eq!(outbound.envelope.event.as_str(), synra_protocol::event::events::INTENT_INVOKE);
        assert_eq!(outbound.envelope.request_id, request_id, "the id is the idempotency key");

        let asked = crate::intent::remote::invoke_from(&outbound.envelope).expect("readable");
        assert_eq!(asked.plugin_id.as_str(), "@acme/opener");
        assert_eq!(asked.action, "open");
        assert_eq!(asked.args["url"], "https://example.com");
    }

    #[test]
    fn work_that_never_travelled_is_not_sent_again() {
        let mut board = Board::new();
        // An intent a peer asked this device to run: re-sending it would ask the peer to run it again.
        let (from_peer, ..) = board.raise(
            direct(peer()),
            Choice::Automatic,
            Some(peer()),
            Some(synra_protocol::ids::RequestId::new()),
            1_000,
        );
        assert!(resume(board.get(from_peer).expect("raised"), local(), 2_000).is_none());

        // A target that is this device: nothing ever left, so there is nothing to re-send.
        let (here, ..) = board.raise(
            direct(local()),
            Choice::Automatic,
            None,
            Some(synra_protocol::ids::RequestId::new()),
            1_000,
        );
        assert!(resume(board.get(here).expect("raised"), local(), 2_000).is_none());

        // A dispatch past the window in which a late answer can still arrive: `expire_unanswered` ends these, this does
        // not re-send them.
        let (stale, ..) = board.raise(
            direct(peer()),
            Choice::Automatic,
            None,
            Some(synra_protocol::ids::RequestId::new()),
            1_000,
        );
        let late = 1_000 + crate::late_queue::MAX_AGE_MS;
        assert!(resume(board.get(stale).expect("raised"), local(), late).is_none());
    }

    #[test]
    fn a_failed_intent_carries_its_error_into_the_view() {
        // ★ The board has held the error since `Failed` was written; the view dropped it, so the interface's "why did it
        // fail?" line read `null` for every real failure.
        let mut board = Board::new();
        let (id, ..) = board.raise(
            direct(peer()),
            Choice::Automatic,
            None,
            Some(synra_protocol::ids::RequestId::new()),
            1_000,
        );
        board
            .conclude(
                id,
                false,
                "",
                Some(synra_protocol::SynraError::new(
                    synra_protocol::ErrorCode::Internal,
                    "the plugin trapped",
                )),
                3,
            )
            .expect("ended");
        let board = Arc::new(Mutex::new(board));

        let view = snapshot(&board, &id.to_string()).expect("a view");
        let error = view.error.as_ref().expect("the failure is carried");
        assert_eq!(error.code, synra_protocol::ErrorCode::Internal);
        assert_eq!(error.message, "the plugin trapped");
        assert_eq!(view.created_at_ms, 1_000, "the raising time is carried, not the reading time");
        assert_eq!(view.to_json()["error"]["code"], "internal");
        assert_eq!(view.to_json()["createdAtMs"], 1_000);
    }

    #[test]
    fn a_timed_out_intent_says_how_long_it_waited() {
        // ★ "Timed out" is a state word, not a reason: it does not say whether the matching window closed or a device never
        // answered, and it does not say for how long. The wait is the fact, and the code is what the page translates.
        let mut board = Board::new();
        let (id, ..) = board.raise(
            direct(peer()),
            Choice::Automatic,
            None,
            Some(synra_protocol::ids::RequestId::new()),
            1_000,
        );
        let _ = board.time_out(id);
        let board = Arc::new(Mutex::new(board));

        let view = snapshot(&board, &id.to_string()).expect("a view");
        assert_eq!(view.state, "timedOut");
        let error = view.error.as_ref().expect("the wait is carried");
        assert_eq!(error.code, synra_protocol::ErrorCode::Timeout);
        assert_eq!(error.message, "nothing answered within 400 ms");
    }

    #[test]
    fn a_refused_intent_carries_the_check_that_refused_it() {
        // ★ "Refused" without a reason is the same failure as "Failed" without one: the refusal type documents its detail
        // as a sentence the interface can show, and the view was dropping both it and its code.
        let mut board = Board::new();
        let (id, ..) = board.raise(
            direct(peer()),
            Choice::Automatic,
            None,
            Some(synra_protocol::ids::RequestId::new()),
            1_000,
        );
        board.refuse(
            id,
            crate::admission::AdmissionRefusal {
                step: crate::admission::AdmissionStep::PluginActive,
                detail: "the plugin is not active".to_owned(),
                code: synra_protocol::ErrorCode::PluginNotInstalled,
            },
        );
        let board = Arc::new(Mutex::new(board));

        let view = snapshot(&board, &id.to_string()).expect("a view");
        assert_eq!(view.state, "refused");
        let error = view.error.as_ref().expect("the refusal's sentence is carried");
        assert_eq!(error.code, synra_protocol::ErrorCode::PluginNotInstalled);
        assert_eq!(error.message, "the plugin is not active");
    }

    #[test]
    fn a_successful_intent_has_no_error_to_show() {
        let mut board = Board::new();
        let (id, ..) = board.raise(
            direct(peer()),
            Choice::Automatic,
            None,
            Some(synra_protocol::ids::RequestId::new()),
            1_000,
        );
        board.conclude(id, true, "opened", None, 1).expect("ended");
        let board = Arc::new(Mutex::new(board));

        let view = snapshot(&board, &id.to_string()).expect("a view");
        assert!(view.error.is_none());
        assert!(view.to_json()["error"].is_null());
    }
}
