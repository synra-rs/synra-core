//! Routing a share: asking the plugins, applying the answer, running what was chosen.
//!
//! # \u2605 Why this is in the library rather than in a host
//!
//! Because **two hosts need it**. The daemon routes a share that arrives from a peer and one the CLI hands it; the desktop
//! shell routes one from this machine's own share sheet. Until this module existed, the whole of that orchestration lived
//! in `synra-daemon/src/runtime/intent.rs` \u2014 **inside a binary** \u2014 so the shell could not reuse a line of it and would
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
//! Because the two hosts report failures differently \u2014 the daemon as a control-protocol refusal, the shell as an
//! `IpcError` \u2014 and a library that picked one would make the other translate a foreign type. [`RouteError`] carries the
//! `ErrorCode` the contract already defines and a sentence for a person, and each host wraps that in its own shape: one
//! line each, and no shared vocabulary invented for the purpose.

use std::sync::Arc;

use parking_lot::Mutex;

use synra_protocol::ids::PluginId;
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
    pub suggested_target: Option<synra_protocol::ids::DeviceId>,
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
}

/// The result of running the action a user chose.
#[derive(Debug, Clone)]
pub struct Decided {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
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
}

/// An intent's state after a move that produces nothing else.
#[derive(Debug, Clone)]
pub struct StateChange {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
    /// What stage it is at now.
    pub state: &'static str,
}

impl CandidateView {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pluginId": self.plugin_id.as_str(),
            "pluginVersion": self.plugin_version,
            "action": self.action,
            // The plugin's own arguments, so a client can show what would be acted on \u2014 the URL a link candidate
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
            "candidates": self.candidates.iter().map(CandidateView::to_json).collect::<Vec<_>>(),
        })
    }
}

impl Decided {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "requestId": self.request_id.to_string(),
            "pluginId": self.plugin_id.as_str(),
            "action": self.action,
            "ok": self.ok,
            "result": self.result,
            "error": self.error,
            "state": self.state,
        })
    }
}

impl StateChange {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "intent": self.intent_id.to_string(), "state": self.state })
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
    pub fn new(plugins: Arc<Mutex<PluginSet>>, board: Arc<Mutex<Board>>) -> Self {
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
    };
    drop(intents);
    Ok(answer)
}

/// Applies the user's answer, and runs what they chose.
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
    local_device: synra_protocol::ids::DeviceId,
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
    let (candidate, request_id, target) = {
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
            let device = named.parse::<synra_protocol::ids::DeviceId>().map_err(|_| {
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
        // Released here rather than at the end of the enclosing block: the board is shared with every other connection,
        // and a guard held past its last use is a second share waiting on this one.
        drop(intents);
        (candidate, request_id, target)
    };

    // ★ Only a target that is **this** device runs here.
    //
    // The board's `confirm` produces a request id because the ordinary dispatch is an envelope to another machine —
    // "the candidate and the envelope id the caller must send under". Sending is not implemented in this build, and
    // pretending otherwise would run a user's action on the machine they shared *from* rather than the one they chose.
    if target != Some(local_device) {
        return Err(RouteError::new(
            synra_protocol::ErrorCode::Unsupported,
            "running an action on another device is not implemented in this build",
        ));
    }

    // ★ The call itself. `execute` is the only function in the system that runs a plugin's action, and it is reached
    // from here alone.
    let started_ms = now_ms.max(0) as u64;
    let outcome = {
        let mut set = plugins.lock();
        crate::dispatch::execute(&mut set, &candidate.plugin_id, &candidate, started_ms)
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
        request_id,
        plugin_id: candidate.plugin_id,
        action: candidate.planned.action,
        ok,
        result,
        error,
        state: state_name(&state),
    })
}

/// Abandons an intent.
///
/// # Errors
///
/// [`RouteError`] when the identifier is not one or names an intent this kernel never raised.
pub fn cancel(
    board: &Arc<Mutex<Board>>,
    intent: &str,
    reason: &str,
) -> Result<StateChange, RouteError> {
    let id = parse_intent(intent)?;
    let state = board.lock().cancel(id, reason).map_err(|error| refuse_intent(&error))?;
    Ok(StateChange { intent_id: id, state: state_name(&state) })
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
    RouteError::new(synra_protocol::ErrorCode::InvalidArgument, &error.to_string())
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
    use crate::intent::IntentState;
    match state {
        IntentState::Matching { .. } => "matching",
        IntentState::Choosing { .. } => "choosing",
        IntentState::Confirming { .. } => "confirming",
        IntentState::Dispatching { .. } => "dispatching",
        IntentState::NoHandler => "noHandler",
        IntentState::TimedOut { .. } => "timedOut",
        IntentState::Refused { .. } => "refused",
        IntentState::Cancelled { .. } => "cancelled",
        IntentState::Succeeded { .. } => "succeeded",
        IntentState::Failed { .. } => "failed",
        // No wildcard: `IntentState` is `#[non_exhaustive]`, which binds callers in *other* crates and not this
        // one, so a state added later is a compile error here — which is where the missing arm should be noticed.
    }
}

