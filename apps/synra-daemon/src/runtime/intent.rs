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
    orchestrate::dispatch(plugins, board, item, now_ms).map_err(as_refusal)
}

/// Reads an intent's current state and candidates.
///
/// # Errors
///
/// [`Refusal`] when the identifier is not one, or names an intent this kernel never raised or has already forgotten.
pub(super) fn snapshot(board: &Arc<Mutex<Board>>, intent: &str) -> Result<serde_json::Value, Refusal> {
    orchestrate::snapshot(board, intent).map_err(as_refusal)
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
) -> Result<serde_json::Value, Refusal> {
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
    intent: &str,
    reason: &str,
) -> Result<serde_json::Value, Refusal> {
    orchestrate::cancel(board, intent, reason).map_err(as_refusal)
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

        let answer =
            decide(&plugins, &board, local_device(), &intent, None, None, 2_000).expect("decided");

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
        .expect("aimed and run");

        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["state"], "succeeded", "{answer}");
        assert_eq!(answer["result"], "opened");
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
    fn cancelling_an_intent_ends_it_and_says_so() {
        let plugins = set_that_accepts("@acme/opener");
        let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
        let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
        let intent = routed["intent"].as_str().expect("an id").to_owned();

        let answer = cancel(&board, &intent, "the user changed their mind").expect("cancelled");

        assert_eq!(answer["state"], "cancelled", "{answer}");
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
