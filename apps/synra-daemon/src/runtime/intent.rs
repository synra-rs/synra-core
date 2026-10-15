//! Routing a share: asking the plugins, and reporting what offered.
//!
//! # ★ Why this module exists
//!
//! Because the matcher had **no production caller at all**. `synra-core` implements routing — ask every plugin whether it
//! can handle this, collect the candidates, offer them to the user, run the one chosen — and nothing could reach it: the
//! control protocol had no intent request, the CLI had no command, and the transport writes an inbound share into an
//! inbox and reports that nothing was delivered. A share arriving became a file rather than an action, and the design
//! document calls this routing "the kernel's most central orchestration".
//!
//! # What is decided here, and what is not
//!
//! This raises the intent, runs the matching pass, and closes the window. It does **not** run anything: a candidate that
//! the user's settings say to run automatically becomes a `Dispatching` state, and confirming and invoking it is the next
//! step — deliberately, because running third-party code is the one thing that should not happen as a side effect of
//! asking "what can handle this?".

use std::sync::Arc;

use parking_lot::Mutex;

use synra_control::Refusal;
use synra_core::dispatch::{Matcher, PluginSet};
use synra_core::intent::{Board, IntentSource};
use synra_protocol::inbound::ShareItem;

/// Routes a share and reports what the plugins said.
///
/// # Errors
///
/// [`Refusal`] when the item cannot be serialised into the shape a plugin is asked about, which is a fact about the
/// item rather than about any plugin.
pub(super) fn dispatch(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    item: &ShareItem,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    // The same JSON the plugin is handed as `can-handle`'s argument. It is produced from the typed item rather than
    // passed through, so a caller cannot ask a plugin about something that is not a share item.
    let item_json = serde_json::to_string(item).map_err(|error| {
        Refusal::new(
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
            synra_core::intent::Choice::default(),
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

    Ok(serde_json::json!({
        "intent": id.to_string(),
        "trace": trace.to_string(),
        // `false` means the same request had already raised an intent. Reported rather than hidden: a caller retrying
        // after a lost answer needs to know it did not create a second one, which is the whole reason the board keeps
        // the request id.
        "created": created,
        "state": settled.map_or("unknown", |state| state_name(&state)),
        "candidates": candidates,
        // ★ The pass's own report, which is what separates "nothing is installed" from "everything crashed". The two
        // look identical from a candidate list, and a user cannot tell them apart.
        "asked": report.asked,
        "handled": report.handled,
        "declined": report.declined,
        "offered": report.offered,
        "misbehaved": report
            .misbehaved
            .iter()
            .map(|misbehaviour| {
                serde_json::json!({
                    "pluginId": misbehaviour.plugin_id.as_str(),
                    "detail": misbehaviour.detail,
                })
            })
            .collect::<Vec<_>>(),
    }))
}

/// Reads an intent's current state and candidates.
///
/// # Errors
///
/// [`Refusal`] when the identifier is not one, or names an intent this kernel never raised or has already forgotten —
/// which is a different answer from "it is over", and the two must not be conflated.
pub(super) fn snapshot(board: &Arc<Mutex<Board>>, intent: &str) -> Result<serde_json::Value, Refusal> {
    let id = parse_intent(intent)?;
    let intents = board.lock();
    let Some(found) = intents.get(id) else {
        return Err(Refusal::new(
            synra_protocol::ErrorCode::InvalidArgument,
            "this kernel has no such intent",
        ));
    };
    let answer = serde_json::json!({
        "intent": id.to_string(),
        "trace": found.trace.to_string(),
        "state": state_name(&found.state),
        "candidates": candidates_of(&intents, id),
    });
    drop(intents);
    Ok(answer)
}

/// Applies the user's answer, and runs what they chose.
///
/// # \u2605 Why this is the one place an action happens
///
/// Because everything before it is a question. The matching pass asks every plugin whether it can handle a share and
/// produces candidates; this is where the answer becomes an action \u2014 and only for the plugin the user picked, which is
/// what stops "what can handle this?" from running third-party code as a side effect.
///
/// # Errors
///
/// [`Refusal`] when the intent is unknown or is not in a state that can be decided, when the named plugin was not among
/// the candidates, or when the identifier is not one.
pub(super) fn decide(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    local_device: synra_protocol::ids::DeviceId,
    intent: &str,
    plugin_id: Option<&str>,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    let id = parse_intent(intent)?;

    // \u2605 The choice is resolved against the board's own list, not accepted from the caller.
    //
    // `Board::choose` checks that the plugin and action were actually offered \u2014 "a choice arrives from an interface, and
    // acting on one that was never shown would run something the user did not choose". Looking the action up from the
    // board rather than taking it from the client also means a client sends what the user clicked (a plugin) rather than
    // a hand-built action string, which is one fewer thing for it to get wrong.
    let (candidate, request_id, target) = {
        let mut intents = board.lock();
        if let Some(wanted) = plugin_id {
            let plugin = synra_protocol::ids::PluginId::try_from(wanted.to_owned()).map_err(|_| {
                Refusal::new(
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
                    Refusal::new(
                        synra_protocol::ErrorCode::InvalidArgument,
                        "that plugin did not offer anything for this share",
                    )
                })?;
            intents
                .choose(id, &synra_core::intent::CandidateChoice::new(plugin, offered))
                .map_err(|error| refuse_intent(&error))?;
        }
        // \u2605 The target is read **before** confirming, because confirming moves the state and the target is what decides
        // where the action runs. A remote target is not a local call with different arguments: it is a message to another
        // device, and running it here would be doing the user's action on the wrong machine.
        let target = intents.get(id).and_then(|found| match &found.state {
            synra_core::intent::IntentState::Confirming { target, .. } => Some(*target),
            _ => None,
        });
        let (candidate, request_id) = intents.confirm(id).map_err(|error| refuse_intent(&error))?;
        // Released here rather than at the end of the enclosing block: the board is shared with every other connection,
        // and a guard held past its last use is a second share waiting on this one.
        drop(intents);
        (candidate, request_id, target)
    };

    // \u2605 Only a target that is **this** device runs here.
    //
    // The board's `confirm` produces a request id because the ordinary dispatch is an envelope to another machine \u2014
    // "the candidate and the envelope id the caller must send under". Sending is not implemented in this build, and
    // pretending otherwise would run a user's action on the machine they shared *from* rather than the one they chose.
    if target != Some(local_device) {
        return Err(Refusal::new(
            synra_protocol::ErrorCode::Unsupported,
            "running an action on another device is not implemented in this build",
        ));
    }

    // \u2605 The call itself. `execute` is the only function in the system that runs a plugin's action, and it is reached
    // from here alone.
    let started_ms = now_ms.max(0) as u64;
    let outcome = {
        let mut set = plugins.lock();
        synra_core::dispatch::execute(&mut set, &candidate.plugin_id, &candidate, started_ms)
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

    Ok(serde_json::json!({
        "intent": id.to_string(),
        "requestId": request_id.to_string(),
        "pluginId": candidate.plugin_id.as_str(),
        "action": candidate.planned.action,
        "ok": ok,
        "result": result,
        "error": error,
        "state": state_name(&state),
    }))
}

/// Abandons an intent.
///
/// # Errors
///
/// [`Refusal`] when the identifier is not one or names an intent this kernel never raised.
pub(super) fn cancel(
    board: &Arc<Mutex<Board>>,
    intent: &str,
    reason: &str,
) -> Result<serde_json::Value, Refusal> {
    let id = parse_intent(intent)?;
    let state = board.lock().cancel(id, reason).map_err(|error| refuse_intent(&error))?;
    Ok(serde_json::json!({
        "intent": id.to_string(),
        "state": state_name(&state),
    }))
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
fn parse_intent(text: &str) -> Result<synra_protocol::ids::IntentId, Refusal> {
    text.parse::<synra_protocol::ids::IntentId>().map_err(|_| {
        Refusal::new(
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
fn refuse_intent(error: &synra_core::intent::IntentError) -> Refusal {
    Refusal::new(synra_protocol::ErrorCode::InvalidArgument, &error.to_string())
}

/// The candidates the board is holding for an intent.
///
/// # Why this is not `IntentState::candidates()`
///
/// Because that method answers "what is the user choosing **between**", and it returns an empty slice once the board has
/// settled on one \u2014 `Confirming` holds a single candidate rather than a list. A snapshot built from it alone showed a
/// share that had been routed successfully as having no candidates at all, which is precisely the fact a prompt needs.
/// The states are listed here rather than defaulted, so a state added later has to be considered.
fn candidates_of(board: &Board, id: synra_protocol::ids::IntentId) -> Vec<serde_json::Value> {
    use synra_core::intent::IntentState;
    let Some(intent) = board.get(id) else {
        return Vec::new();
    };
    let one;
    let candidates: &[synra_core::intent::IntentCandidate] = match &intent.state {
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
        .map(|candidate| {
            // \u2605 The title and detail as well as the identifiers: a prompt is built from these, and a client that only
            // received `(plugin, action)` would have to invent the sentence a user reads \u2014 which is the plugin's own
            // description of what it will do, not something a host can write for it.
            serde_json::json!({
                "pluginId": candidate.plugin_id.as_str(),
                "pluginVersion": candidate.plugin_version,
                "action": candidate.planned.action,
                // The plugin's own arguments, so a client can show what would be acted on \u2014 the URL a link candidate
                // would open, rather than only the sentence describing it.
                "args": candidate.planned.args,
                "title": candidate.title,
                "detail": candidate.detail,
                "requiredCaps": candidate.required_caps,
            })
        })
        .collect()
}

/// A stable name for a state, for a client that switches on it.
const fn state_name(state: &synra_core::intent::IntentState) -> &'static str {
    use synra_core::intent::IntentState;
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
        // `IntentState` is `#[non_exhaustive]`, so a state added later is reported as unknown rather than failing to
        // compile — and `unknown` is honest, because this build does not know what it means.
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use synra_core::dispatch::{PluginSet, PluginSpec};
    use synra_plugin_host::Backend;
    use synra_protocol::ids::DeviceId;
    use synra_protocol::inbound::ShareItem;

    use super::{cancel, decide, dispatch, snapshot};

    /// A set over a scripted engine whose `can-handle` says yes, plus the host a plugin's calls reach.
    fn set_that_accepts(plugin: &str) -> Arc<Mutex<PluginSet>> {
        let backend = synra_plugin_host::ScriptedBackend::new();
        backend.script(
            &synra_plugin_host::Work::CanHandle { item_json: item_json() },
            // \u2605 The shape a real plugin answers with, taken from the deserialiser rather than invented. The first
            // version of this fixture said `pluginId` and `requiredCaps`, and the pass recorded the plugin as
            // **misbehaved** with "can-handle returned missing field `handled`" \u2014 which is the code refusing a payload
            // no plugin would send. A fixture that had been accepted would have proved nothing about plugins.
            //
            // The plugin does not name itself: the host knows which plugin answered, and a plugin that could claim to be
            // another one is a plugin that could claim another one's candidates.
            synra_plugin_host::Scripted::Ok(
                serde_json::json!({
                    "handled": true,
                    "action": "open",
                    "title": "Open the link",
                    "required": [],
                    // \u2605 A target, because without one the board settles the intent into `Choosing` \u2014 the question
                    // "where should this run?" \u2014 and no method on `Board` answers it. `choose` re-enters `Choosing` for a
                    // candidate with no target and `confirm` refuses anything that is not `Confirming`, so an intent in
                    // that state cannot be advanced at all. This fixture names this device so the decide path is
                    // reachable; the gap is recorded rather than worked around in production code.
                    "target": local_device().to_string(),
                    // ★ And it says what to open. This is the field whose absence made the previous round's test pin
                    // `args_json: "null"`: `can-handle` is handed the item and `execute` is not, so with no way to pass
                    // the URL along, a plugin could propose an action it had no way to perform.
                    "args": { "url": "https://example.com" },
                })
                .to_string(),
            ),
        );
        // ★ `share.execute` is scripted with **the arguments the plugin itself proposed from `can-handle`**.
        //
        // The script is keyed on the exact `args_json`, so this is an assertion about what the kernel sends: if the URL
        // did not survive from `can-handle` to `execute`, this call would not match and the test would fail. The round
        // before this one scripted `"null"` here, because that is what the kernel sent — a plugin was told which action
        // to run and nothing about what to run it on.
        backend.script(
            &synra_plugin_host::Work::Execute {
                action: "open".to_owned(),
                args_json: serde_json::json!({ "url": "https://example.com" }).to_string(),
            },
            synra_plugin_host::Scripted::Ok("opened".to_owned()),
        );
        let mut set = PluginSet::new(
            Backend::new(Arc::new(backend)),
            // A host that provides nothing: this test is about routing, and the plugin never reaches a host function.
            Arc::new(crate::runtime::plugin_host::KernelHost::new(
                Arc::new(Mutex::new({
                    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
                    db.migrate().expect("migrates");
                    db
                })),
                "0.1.0-test",
            )),
        );
        let mut grants = synra_capability::CapabilitySet::new();
        grants.insert_str("log:*").expect("a capability");
        set.load(PluginSpec {
            id: synra_protocol::ids::PluginId::try_from(plugin.to_owned()).expect("a plugin id"),
            version: "1.0.0".to_owned(),
            wasm: b"\0asm\x01\0\0\0".to_vec(),
            grants,
            policy: synra_plugin_host::InstancePolicy::Stateless,
            limit: 4,
            quota: synra_plugin_host::quota::Quota::default(),
        })
        .expect("loads");
        Arc::new(Mutex::new(set))
    }

    /// The device these tests treat as "this one".
    ///
    /// ★ A fixed identifier rather than `DeviceId::new()`. The first version generated a fresh one per call, so the
    /// target the fixture's proposal named was never the target `decide` compared against — and the failure read as
    /// "running an action on another device is not implemented", which is a true statement about a test that had invented
    /// two devices.
    fn local_device() -> DeviceId {
        "0e5a1c34-0000-4000-8000-000000000001"
            .parse()
            .expect("a device id")
    }

    fn item() -> ShareItem {
        ShareItem {
            from: local_device(),
            mime: "text/uri-list".to_owned(),
            text: Some("https://example.com".to_owned()),
            transfers: Vec::new(),
            context_id: None,
        }
    }

    fn item_json() -> String {
        serde_json::to_string(&item()).expect("serialises")
    }

    #[test]
    fn a_share_reaches_the_plugins_and_its_candidates_come_back() {
        // \u2605 The test the whole request exists for. Before it, the matcher had **no production caller**: `synra-core`
        // implemented routing and nothing could reach it, so a share that arrived became a file in an inbox rather than an
        // action. The assertion is on the candidates, because a candidate is what routing produces.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));

        let answer = dispatch(&plugins, &board, &item(), 1_000).expect("routed");

        assert_eq!(answer["asked"], 1, "the one plugin was asked: {answer}");
        assert_eq!(answer["handled"], 1, "and it said yes: {answer}");
        let candidates = answer["candidates"].as_array().expect("a list");
        assert_eq!(candidates.len(), 1, "{answer}");
        assert_eq!(candidates[0]["pluginId"], "@acme/opener");
        assert_eq!(candidates[0]["action"], "open");
        // The prompt's own words travel with the candidate: a client that received only identifiers would have to invent
        // the sentence a user reads, and that sentence is the plugin's description of what it will do.
        assert_eq!(candidates[0]["title"], "Open the link");
    }

    #[test]
    fn a_decided_share_runs_the_plugin_and_records_what_it_returned() {
        // \u2605 The end of the line: a share becomes an action.
        //
        // Every test before this one stops at "a candidate was produced". This is the only place in the system where a
        // plugin's action actually runs, and the assertion is on what the plugin was asked to do \u2014 not on the state
        // name, which would pass for an implementation that never called anything.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));

        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();

        let answer =
            decide(&plugins, &board, local_device(), &intent, None, 2_000).expect("decided");

        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["pluginId"], "@acme/opener");
        assert_eq!(answer["action"], "open");
        // The plugin's own return value, carried through rather than replaced by a status word.
        assert_eq!(answer["result"], "opened");
        assert_eq!(answer["state"], "succeeded", "{answer}");

        // \u2605 And the plugin was asked to **execute**, which is the call that has side effects. Asserting only on the
        // state would pass against an implementation that never invoked anything.
        // ★ And what the plugin proposed is what it was given. The call above is scripted on the exact arguments,
        // so this is the thing that would break if the URL stopped being carried — the defect that stood here before.
    }

    #[test]
    fn the_arguments_a_plugin_proposed_are_what_it_is_given_to_execute() {
        // ★ The property that was missing entirely.
        //
        // `can-handle` is handed the shared item and `execute` is not — the contract is
        // `execute(action: string, args-json: string)`. Before `Proposal::args` existed there was **no path** for the URL
        // to travel between them, so every action ran against `null` and a plugin that claimed a link could not open it.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();

        // The candidate the board is holding carries it before anything is decided, which is where the URL has to be for
        // the decision to be able to use it.
        let candidates = routed["candidates"].as_array().expect("a list");
        assert_eq!(
            candidates[0]["args"],
            serde_json::json!({ "url": "https://example.com" }),
            "the proposal's own arguments travel with the candidate: {routed}"
        );

        decide(&plugins, &board, local_device(), &intent, None, 2_000).expect("decided");
    }

    #[test]
    fn an_unknown_intent_is_refused_rather_than_answered_with_an_empty_one() {
        // \u2605 "There is no such intent" and "the intent is over" are different answers, and a client that received an
        // empty snapshot for the first would show a user a prompt for something that never existed.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));

        let refused = snapshot(&board, "01a140ce-0000-7000-8000-000000000000");

        assert!(refused.is_err(), "an unknown intent is not an empty snapshot");
        // And an identifier that is not one is refused before the board is consulted at all.
        assert!(snapshot(&board, "not-an-intent").is_err());
        let _ = plugins;
    }

    #[test]
    fn cancelling_an_intent_ends_it_and_says_so() {
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();

        let answer = cancel(&board, &intent, "the user changed their mind").expect("cancelled");

        assert_eq!(answer["state"], "cancelled", "{answer}");
        // \u2605 And it is no longer live: a cancelled intent that still appeared in the list would be a prompt a user
        // could answer after saying no.
        assert!(board.lock().live().is_empty(), "a cancelled intent is not live");
    }

    #[test]
    fn a_share_nobody_can_handle_is_told_apart_from_nothing_being_installed() {
        // \u2605 The distinction the report exists for, and the one a candidate list cannot make. Both cases offer no
        // candidates, and a user asking "why did nothing happen" needs to know which they are in.
        let plugins = Arc::new(Mutex::new(PluginSet::new(
            Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new())),
            Arc::new(crate::runtime::plugin_host::KernelHost::new(
                Arc::new(Mutex::new({
                    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
                    db.migrate().expect("migrates");
                    db
                })),
                "0.1.0-test",
            )),
        )));
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));

        let answer = dispatch(&plugins, &board, &item(), 1_000).expect("routed");

        assert_eq!(answer["asked"], 0, "nothing was installed to ask: {answer}");
        assert_eq!(answer["candidates"].as_array().map(Vec::len), Some(0));
        assert_eq!(answer["state"], "noHandler");
        assert!(answer["misbehaved"].as_array().is_some_and(Vec::is_empty), "{answer}");
    }
}
