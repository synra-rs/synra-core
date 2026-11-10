use std::sync::Arc;
use parking_lot::Mutex;
use synra_core::dispatch::PluginSet;
use synra_plugin_host::Backend;
use super::super::{cancel, decide, dispatch, snapshot};
use super::{item, local_device, set_that_accepts, set_that_accepts_without_a_place};

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
    // ★ One action, one trace: the decision answers with the id the routing answer used, which is what a user pastes
    // into `synra logs --trace`.
    assert_eq!(answer["trace"], routed["trace"], "the decision keeps the action's trace");
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
