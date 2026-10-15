//! Routing, as this host reaches it.
//!
//! # Why this is a shim rather than the implementation
//!
//! Because the orchestration used to live here \u2014 **inside a binary** \u2014 and a second host needs it. The desktop shell has
//! its own `Board` and its own four intent commands, and it could not reuse a line of what was in this file; it would have
//! had to duplicate it. It lives in [`synra_core::dispatch::orchestrate`] now, where both hosts reach it, and what remains
//! here is the translation: the library answers with a [`RouteError`] carrying a contract code, and the control protocol
//! answers with a `Refusal` carrying the same code and a sentence.
//!
//! # Why the wrappers keep their names and signatures
//!
//! Because the tests below are about the orchestration, and they exercise it through this host\u2019s own entry points. Moving
//! them would have been churn for no coverage; leaving them means the library is tested through a real host as well as on
//! its own.

use std::sync::Arc;

use parking_lot::Mutex;

use synra_control::Refusal;
use synra_core::dispatch::orchestrate::{self, RouteError};
use synra_core::dispatch::PluginSet;
use synra_core::intent::Board;
use synra_protocol::inbound::ShareItem;

/// Everything an inbound share is routed with.
pub use synra_core::dispatch::orchestrate::Router;

/// A library failure as this host reports it.
///
/// One line, and that is the point of the library carrying the contract's own codes: a host that had to map a bespoke
/// enum would be inventing the vocabulary back.
fn as_refusal(error: RouteError) -> Refusal {
    Refusal::new(error.code, error.message)
}

/// Routes a share and reports what the plugins said.
///
/// # Errors
///
/// [`Refusal`] when the item cannot be serialised into the shape a plugin is asked about.
pub(super) fn dispatch(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    item: &ShareItem,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    orchestrate::dispatch(plugins, board, item, now_ms).map(|answer| answer.to_json()).map_err(as_refusal)
}

/// Reads an intent's current state and candidates.
///
/// # Errors
///
/// [`Refusal`] when the identifier is not one, or names an intent this kernel never raised or has already forgotten.
pub(super) fn snapshot(board: &Arc<Mutex<Board>>, intent: &str) -> Result<serde_json::Value, Refusal> {
    orchestrate::snapshot(board, intent).map(|answer| answer.to_json()).map_err(as_refusal)
}

/// Applies the user's answer, and runs what they chose.
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
    target: Option<&str>,
    now_ms: i64,
) -> Result<orchestrate::Decided, Refusal> {
    // ★ The typed answer, not its JSON.
    //
    // This rendered to `serde_json::Value` like its neighbours, and that was fine while a decision could only run here:
    // the answer was the whole outcome. It is not fine now — a remote decision's outcome is an **envelope the host has to
    // send**, and rendering it to JSON threw the envelope away one line before anything could put it on a link. The
    // caller renders it for the wire after it has used what only the type carries.
    orchestrate::decide(plugins, board, local_device, intent, plugin_id, target, now_ms)
        .map_err(as_refusal)
}

/// Abandons an intent.
///
/// # Errors
///
/// [`Refusal`] when the identifier is not one or names an intent this kernel never raised.
pub(super) fn cancel(
    board: &Arc<Mutex<Board>>,
    local_device: synra_protocol::ids::DeviceId,
    intent: &str,
    reason: &str,
) -> Result<orchestrate::StateChange, Refusal> {
    // Typed rather than rendered, for the reason `decide` is: a cancellation of a *dispatched* intent carries an envelope
    // the host has to send, and rendering it here threw that away — the same mistake, in the same place, one round later.
    orchestrate::cancel(board, local_device, intent, reason).map_err(as_refusal)
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
            // ★ The shape a real plugin answers with, taken from the deserialiser rather than invented. The first
            // version of this fixture said `pluginId` and `requiredCaps`, and the pass recorded the plugin as
            // **misbehaved** with "can-handle returned missing field `handled`" — which is the code refusing a payload
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
                    // ★ A target, because without one the board settles the intent into `Choosing` — the question
                    // "where should this run?" — and no method on `Board` answers it. `choose` re-enters `Choosing` for a
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

    /// A set whose `can-handle` answers without suggesting a device.
    ///
    /// ★ The case that used to be unreachable. A candidate with no target settles into `Choosing` — the question
    /// "where should this run?" — and before `Board::aim` there was no method that answered it, so an action could be
    /// proposed here and never performed.
    fn set_that_accepts_without_a_place(plugin: &str) -> Arc<Mutex<PluginSet>> {
        let backend = synra_plugin_host::ScriptedBackend::new();
        backend.script(
            &synra_plugin_host::Work::CanHandle { item_json: item_json() },
            synra_plugin_host::Scripted::Ok(
                serde_json::json!({
                    "handled": true,
                    "action": "open",
                    "title": "Open the link",
                    "required": [],
                    "args": { "url": "https://example.com" },
                })
                .to_string(),
            ),
        );
        backend.script(
            &synra_plugin_host::Work::Execute {
                action: "open".to_owned(),
                args_json: serde_json::json!({ "url": "https://example.com" }).to_string(),
            },
            synra_plugin_host::Scripted::Ok("opened".to_owned()),
        );
        let mut set = PluginSet::new(
            Backend::new(Arc::new(backend)),
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
        // ★ The test the whole request exists for. Before it, the matcher had **no production caller**: `synra-core`
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
        // ★ The end of the line: a share becomes an action.
        //
        // Every test before this one stops at "a candidate was produced". This is the only place in the system where a
        // plugin's action actually runs, and the assertion is on what the plugin was asked to do — not on the state
        // name, which would pass for an implementation that never called anything.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));

        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();

        // The shim hands back the typed answer now, so a test about the rendered shape renders it.
        let answer =
            decide(&plugins, &board, local_device(), &intent, None, None, 2_000).expect("decided").to_json();

        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["pluginId"], "@acme/opener");
        assert_eq!(answer["action"], "open");
        // The plugin's own return value, carried through rather than replaced by a status word.
        assert_eq!(answer["result"], "opened");
        assert_eq!(answer["state"], "succeeded", "{answer}");

        // ★ And the plugin was asked to **execute**, which is the call that has side effects. Asserting only on the
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

        decide(&plugins, &board, local_device(), &intent, None, None, 2_000).expect("decided");
    }

    #[test]
    fn a_share_whose_plugin_named_no_device_is_aimed_and_then_runs() {
        // ★ The whole point of `Board::aim`, end to end.
        //
        // Before it, this share could be routed and could not be acted on: `settle` parked the intent in `Choosing` with
        // its one targetless candidate, `choose` put it back there, and `confirm` refused anything that was not
        // `Confirming`. The user was asked where to run it and there was no way to answer.
        let plugins = set_that_accepts_without_a_place("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();
        assert_eq!(routed["state"], "choosing", "the question is where: {routed}");

        // A decision with no place is refused rather than silently run somewhere — and the refusal is the board's own, so
        // it says what state the intent is in.
        let without_a_place =
            decide(&plugins, &board, local_device(), &intent, None, None, 2_000);
        assert!(without_a_place.is_err(), "where was never answered");

        // Answering it is what lets the intent move, and the action runs.
        let answer = decide(
            &plugins,
            &board,
            local_device(),
            &intent,
            None,
            Some(&local_device().to_string()),
            3_000,
        )
        .expect("aimed and run")
        .to_json();

        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["state"], "succeeded", "{answer}");
        assert_eq!(answer["result"], "opened");
    }

    /// An invocation, as the sending half of this build builds one.
    ///
    /// Built with the library's own constructor rather than by hand, because a fixture that spelled the payload itself
    /// would be a second definition of the shape — and the two would drift the first time either changed.
    fn invocation(request: synra_protocol::ids::RequestId) -> synra_protocol::envelope::Envelope {
        let mut envelope = synra_core::intent::remote::invoke(
            local_device(),
            "0e5a1c34-0000-4000-8000-0000000000ff".parse().expect("a device id"),
            &synra_core::intent::remote::Invoke {
                plugin_id: synra_protocol::ids::PluginId::try_from("@acme/opener".to_owned())
                    .expect("a plugin id"),
                plugin_version: "1.0.0".to_owned(),
                action: "open".to_owned(),
                args: serde_json::json!({ "url": "https://example.com" }),
            },
            synra_protocol::ids::TraceId::new(),
            1_000,
        )
        .expect("an envelope");
        // The identifier is the sender's, and it is what a resend is recognised by.
        envelope.request_id = request;
        envelope
    }

    #[test]
    fn a_request_from_another_device_runs_here_and_answers_with_the_outcome() {
        // ★ The other three of the design's four pieces.
        //
        // Doc 07: "send the message, run the plugin locally on receipt, reply with the result, and be idempotent by
        // request identifier". Sending landed a round ago; this is the receiving end — and the assertion that matters is
        // that the action actually ran, because a handler that answered `ok` without running anything would look
        // identical from the sender's side.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let request = synra_protocol::ids::RequestId::new();

        let answer = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &invocation(request), 2_000)
            .expect("handled")
            .expect("an answer to send");

        assert_eq!(answer.event.as_str(), "_synra.intent.result");
        assert_eq!(answer.target, local_device(), "it goes back to whoever asked");
        assert_eq!(answer.reply_to, Some(request), "and it says which request it answers");
        let payload = synra_core::intent::remote::result_from(&answer).expect("a readable result");
        assert!(payload.ok, "{payload:?}");
        assert_eq!(payload.result, "opened", "the plugin ran, and its answer came back");
    }

    #[test]
    fn the_same_request_twice_runs_once_and_answers_twice() {
        // ★ The fourth piece, and the one whose failure is worst.
        //
        // A sender whose answer was lost resends. If the resend ran the action again, a user's action would happen twice —
        // and the second time is invisible from the sender, which sees one success. The board's `raise` is where this is
        // prevented, before anything is created, so a handler with its own cache would be a second answer to "have I seen
        // this" and the two would disagree the first time one was cleared.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let request = synra_protocol::ids::RequestId::new();

        let first = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &invocation(request), 2_000)
            .expect("handled")
            .expect("an answer");
        let second = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &invocation(request), 3_000)
            .expect("handled")
            .expect("an answer again");

        // ★ The structural fact first, because it is the one that says whether the resend was recognised at all.
        //
        // `len` and not `live`: the first copy **concluded**, so it is no longer live, and a count of live intents would be
        // zero whether the resend was recognised or not — the shape of assertion that passes for the wrong reason, which is
        // what the first version of this test wrote.
        assert_eq!(board.lock().len(), 1, "one request is one intent");

        // And both answers carry the same outcome. `ok`/`result`/`error` are compared rather than the whole struct, because
        // `elapsed_ms` is derived from the **real** wall clock while `now_ms` here is a fixture value — so the two calls
        // cannot agree on it unless the second is answered from the record, and a test that asserted on it would be
        // asserting on how fast the machine is.
        let first = synra_core::intent::remote::result_from(&first).expect("a result");
        let second = synra_core::intent::remote::result_from(&second).expect("a result");
        assert_eq!(first.ok, second.ok, "{first:?} vs {second:?}");
        assert_eq!(first.result, second.result, "{first:?} vs {second:?}");
        assert_eq!(first.error, second.error, "{first:?} vs {second:?}");
    }

    #[test]
    fn an_invocation_this_build_cannot_read_is_refused_rather_than_guessed_at() {
        // A payload that will not parse must not become a default: the default would name a plugin nobody chose and run
        // an action nobody asked for.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let mut empty = invocation(synra_protocol::ids::RequestId::new());
        empty.payload = None;

        let refused = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &empty, 2_000);

        assert!(refused.is_err(), "an unreadable invocation is not a request");
    }

    #[test]
    fn a_share_aimed_at_another_device_produces_an_envelope_instead_of_a_refusal() {
        // ★ This used to refuse, and the refusal was honest while nothing could send.
        //
        // `INTENT_INVOKE` was in the catalogue, in the automatic-ack table and in `inbound`'s kernel-event list, with no
        // sender and no receiver anywhere in the repository. The board already had both halves of the idempotency the
        // design asks for — `confirm` reuses a request id rather than minting a new one, and `recall` looks an arriving
        // request up by its origin — so what was missing was exactly this: build the message and hand it to a host.
        //
        // The other direction matters just as much, and is what the second half asserts: a remote target must **not**
        // run the plugin here. Running it would be doing the user's action on the machine they shared *from* rather than
        // the one they chose, and from the outside that looks identical to success.
        let plugins = set_that_accepts_without_a_place("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();
        let phone = "00000000-0000-4000-8000-0000000000ff";

        let decided = decide(
            &plugins,
            &board,
            local_device(),
            &intent,
            None,
            Some(phone),
            2_000,
        )
        .expect("dispatched rather than refused");
        let answer = decided.to_json();

        assert_eq!(answer["state"], "dispatching", "{answer}");
        assert_eq!(answer["dispatchedTo"], phone, "{answer}");
        // ★ Nothing ran, and nothing failed. `ok` is false because no outcome exists yet, and `dispatchedTo` beside it is
        // what stops that being read as a failure.
        assert_eq!(answer["ok"], false, "{answer}");
        assert_eq!(answer["result"], "", "{answer}");
        assert_eq!(answer["error"], serde_json::Value::Null, "{answer}");

        // The envelope is for the device the user chose, carries the event the far side listens for, and carries the
        // plugin's own arguments — not the share.
        let outbound = decided.outbound.as_ref().expect("an envelope to send");
        assert_eq!(outbound.to.to_string(), phone);
        assert_eq!(outbound.envelope.event.as_str(), "_synra.intent.invoke");
        assert_eq!(outbound.request_id, decided.request_id, "the id a resend is recognised by");
        let payload = synra_core::intent::remote::invoke_from(&outbound.envelope)
            .expect("a readable invocation");
        assert_eq!(payload.action, "open");
        assert_eq!(payload.args, serde_json::json!({ "url": "https://example.com" }));

        // And the plugin did not run: its scripted backend would have answered "opened" had it been called.
        let snapshot = snapshot(&board, &intent).expect("a snapshot");
        assert_eq!(snapshot["state"], "dispatching", "and it stays in flight: {snapshot}");
    }

    #[test]
    fn an_unknown_intent_is_refused_rather_than_answered_with_an_empty_one() {
        // ★ "There is no such intent" and "the intent is over" are different answers, and a client that received an
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
    fn cancelling_a_dispatched_intent_produces_a_withdrawal_for_the_far_side() {
        // ★ Cancelling here does not stop it there.
        //
        // A dispatched intent is running on another device, and that device hears about a change of mind only if it is
        // told. The first version of `cancel` was local-only: the other device finished work the user had withdrawn and
        // reported a result for it, which from this side looks like a cancellation that quietly did not take.
        //
        // ★ And the fact that it *was* dispatched lives in the state being replaced.
        //
        // Reading it after the move gives `Cancelled` and nothing else — no target, no request identifier — so the
        // cancellation is read first. That ordering is the whole of this test's reason for existing.
        let plugins = set_that_accepts_without_a_place("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();
        let phone = "00000000-0000-4000-8000-0000000000ff";

        let _ = decide(&plugins, &board, local_device(), &intent, None, Some(phone), 2_000)
            .expect("dispatched");

        let change = cancel(&board, local_device(), &intent, "the user changed their mind")
            .expect("cancelled");
        let rendered = change.to_json();

        assert_eq!(rendered["state"], "cancelled", "{rendered}");
        assert_eq!(rendered["cancelledAt"], phone, "{rendered}");

        let outbound = change.outbound.as_ref().expect("a withdrawal to send");
        assert_eq!(outbound.to.to_string(), phone);
        assert_eq!(outbound.envelope.event.as_str(), "_synra.intent.cancel");
        let payload = synra_core::intent::remote::cancel_from(&outbound.envelope)
            .expect("a readable cancellation");
        assert_eq!(payload.reason, "the user changed their mind");
    }

    #[test]
    fn a_withdrawal_from_another_device_stops_work_that_has_not_run_yet() {
        // The receiving half, in the case the design cares about: the work is **dispatching** and has not run, and the
        // sender says stop.
        //
        // The envelope names the request; `recall` finds the intent this device raised for that origin, and nothing else
        // may be touched — a lookup by anything else, such as the plugin it names, would let one device cancel another's
        // work.
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let request = synra_protocol::ids::RequestId::new();
        let asked = invocation(request);
        let phone = asked.from;

        // Raised the way `accept_remote` raises it — which is the state a device is in *between* receiving a request and
        // finishing it. Calling `accept_remote` here would run the action to completion, and a withdrawal that arrives
        // afterwards is a different case, covered below.
        let (id, _, created) = board.lock().raise(
            synra_core::intent::IntentSource::Direct {
                plugin_id: synra_protocol::ids::PluginId::try_from("@acme/opener".to_owned())
                    .expect("a plugin id"),
                action: "open".to_owned(),
                params: serde_json::json!({ "url": "https://example.com" }),
                target: local_device(),
            },
            synra_core::intent::Choice::default(),
            Some(phone),
            Some(request),
            2_000,
        );
        assert!(created, "the request is new to this device");

        let withdrawal = synra_core::intent::remote::cancel(
            phone,
            local_device(),
            &synra_core::intent::remote::Cancel { reason: "the user changed their mind".to_owned() },
            request,
            synra_protocol::ids::TraceId::new(),
            3_000,
        )
        .expect("an envelope");

        let cancelled = synra_core::dispatch::orchestrate::accept_cancel(&board, &withdrawal)
            .expect("handled");

        assert_eq!(cancelled, Some(id), "it found the work that request raised");
        let state = board.lock().get(id).map(|intent| intent.state.kind().to_owned());
        assert_eq!(state.as_deref(), Some("cancelled"), "and stopped it");
    }

    #[test]
    fn a_withdrawal_that_arrives_after_the_work_finished_does_not_undo_it() {
        // ★ The race, and the only honest answer to it.
        //
        // A cancellation can cross an `INTENT_RESULT` on the wire. When it does, the work has already happened — running a
        // plugin's action is not reversible by a later message — so the outcome stands. Quietly overwriting `succeeded`
        // with `cancelled` would erase the fact that the action ran, which is the one thing a user needs to know.
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let request = synra_protocol::ids::RequestId::new();
        let asked = invocation(request);
        let phone = asked.from;

        let _ = synra_core::dispatch::orchestrate::accept_remote(
            &plugins,
            &board,
            local_device(),
            &asked,
            2_000,
        )
        .expect("ran")
        .expect("an answer");

        let withdrawal = synra_core::intent::remote::cancel(
            phone,
            local_device(),
            &synra_core::intent::remote::Cancel { reason: "too late".to_owned() },
            request,
            synra_protocol::ids::TraceId::new(),
            3_000,
        )
        .expect("an envelope");

        let found = synra_core::dispatch::orchestrate::accept_cancel(&board, &withdrawal)
            .expect("handled")
            .expect("the work this request raised");

        let state = board.lock().get(found).map(|intent| intent.state.kind().to_owned());
        assert_eq!(state.as_deref(), Some("succeeded"), "the outcome stands: it ran");
    }

    #[test]
    fn a_withdrawal_for_work_this_device_never_raised_is_not_an_error() {
        // The sender cannot know whether its invocation arrived, so it withdraws either way. Refusing would leave it
        // unable to clean up, and there is nothing here to stop.
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let withdrawal = synra_core::intent::remote::cancel(
            local_device(),
            "00000000-0000-4000-8000-0000000000ff".parse().expect("a device id"),
            &synra_core::intent::remote::Cancel { reason: "never mind".to_owned() },
            synra_protocol::ids::RequestId::new(),
            synra_protocol::ids::TraceId::new(),
            3_000,
        )
        .expect("an envelope");

        let nothing = synra_core::dispatch::orchestrate::accept_cancel(&board, &withdrawal)
            .expect("handled without complaint");

        assert!(nothing.is_none(), "there was nothing here to cancel");
    }

    #[test]
    fn cancelling_an_intent_ends_it_and_says_so() {
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();

        let answer =
            cancel(&board, local_device(), &intent, "the user changed their mind").expect("cancelled");
        let rendered = answer.to_json();

        assert_eq!(rendered["state"], "cancelled", "{rendered}");
        // Nothing was dispatched, so there is nothing to tell another device.
        assert_eq!(rendered["cancelledAt"], serde_json::Value::Null, "{rendered}");
        // ★ And it is no longer live: a cancelled intent that still appeared in the list would be a prompt a user
        // could answer after saying no.
        assert!(board.lock().live().is_empty(), "a cancelled intent is not live");
    }

    #[test]
    fn a_share_nobody_can_handle_is_told_apart_from_nothing_being_installed() {
        // ★ The distinction the report exists for, and the one a candidate list cannot make. Both cases offer no
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
