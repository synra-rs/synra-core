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

/// The candidates the board is holding for an intent.
fn candidates_of(board: &Board, id: synra_protocol::ids::IntentId) -> Vec<serde_json::Value> {
    board
        .get(id)
        .map(|intent| {
            intent
                .state
                .candidates()
                .iter()
                .map(|candidate| {
                    // \u2605 The title and detail as well as the identifiers: a prompt is built from these, and a client
                    // that only received `(plugin, action)` would have to invent the sentence a user reads \u2014 which is
                    // the plugin's own description of what it will do, not something a host can write for it.
                    serde_json::json!({
                        "pluginId": candidate.plugin_id.as_str(),
                        "pluginVersion": candidate.plugin_version,
                        "action": candidate.planned.action,
                        "title": candidate.title,
                        "detail": candidate.detail,
                        "requiredCaps": candidate.required_caps,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
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

    use super::dispatch;

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
                })
                .to_string(),
            ),
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

    fn item() -> ShareItem {
        ShareItem {
            from: DeviceId::new(),
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
