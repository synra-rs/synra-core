//! What a matching pass does when plugins answer badly, and when they answer well.
//!
//! # Why these use a scripted backend
//!
//! Because the questions here are about the host's behaviour — does one bad plugin cost the user the good ones, is a
//! decline an error, is a non-answer visible — and every one of them can be asked without a `.wasm` file that would
//! have to be reviewed. A test that needs a real component tests the engine; a test that needs a table tests the host,
//! and these are the second kind.

use synra_capability::CapabilitySet;
use synra_plugin_host::{InstancePolicy, Scripted, ScriptedBackend, Work};
use synra_protocol::ids::{DeviceId, IntentId, PluginId};
use synra_protocol::inbound::ShareItem;

use crate::intent::{Board, Choice, IntentSource};

use super::{PluginSet, PluginSpec};

mod admission;
mod audit;
mod fault_tolerance;
mod instrumentation;
mod matching;
mod quota;
mod reload;
mod wasm_limits;

// A host that refuses everything, for tests that never reach one. It used to be written out here; it now lives in
// `synra_plugin_host::testing`, so the shell can build a `PluginSet` in a test without copying ~170 lines of named
// refusals. The alias keeps every use in this file reading the same.
//
// Why it exists at all: `Host` has no defaults, and `PluginSet::new` requires one — so a set can never be built without a
// host and quietly refuse every call for a reason the caller did not choose.
use synra_plugin_host::testing::RefusingHost as Refusing;

/// A candidate for `plugin_id`, as a matching pass would produce.
fn candidate_for(plugin: &str) -> crate::intent::IntentCandidate {
    use crate::intent::{IntentCandidate, PlannedAction};
    IntentCandidate {
        plugin_id: id(plugin),
        plugin_version: "1.0.0".to_owned(),
        planned: PlannedAction {
            plugin_id: id(plugin),
            action: "open".to_owned(),
            args: serde_json::Value::Null,
        },
        required_caps: Vec::new(),
        suggested_target: None,
        title: "Open".to_owned(),
        detail: None,
    }
}

/// A host for the tests that never reach one.
///
/// `pub(super)` so the test module beside this one — the one that asks what a session is built from — can use the same
/// host rather than writing its own twenty-seven methods.
pub(super) fn host() -> std::sync::Arc<dyn synra_plugin_host::host_calls::Host> {
    std::sync::Arc::new(Refusing)
}


/// A plugin id, from a name, for a test that does not care about scopes.
fn id(name: &str) -> PluginId {
    PluginId::try_from(name.to_owned()).unwrap_or_else(|_| panic!("{name} is not a plugin id"))
}

/// A device id, for a test that does not care about its contents.
fn device() -> DeviceId {
    DeviceId::new()
}

/// A share, as a user would produce one.
fn share() -> ShareItem {
    ShareItem {
        from: device(),
        mime: "text/uri-list".to_owned(),
        text: Some("https://example.invalid/".to_owned()),
        transfers: Vec::new(),
        context_id: None,
    }
}

/// A component-shaped byte string.
///
/// # Why this is not `b"anything"`
///
/// Because the scripted backend checks what a real one would: a body that does not begin with the WebAssembly header
/// is not a component, and refusing it is the whole point of having the check. A test fixture that dodged it would be
/// testing a path that no plugin ever takes.
fn component_bytes() -> Vec<u8> {
    b"\0asm\x01\0\0\0".to_vec()
}

/// Loads one plugin whose `can-handle` is scripted.
///
/// # Why each plugin is scripted separately
///
/// Because the shared script table is keyed by entry point, so a shared `script` call would give every plugin the same
/// answer — and a suite where all nine plugins behave alike cannot show that one of them misbehaving costs the user
/// nothing. That is the property this file is mostly about.
fn load(set: &mut PluginSet, backend: &ScriptedBackend, name: &str, answer: Scripted) {
    backend.script_for(
        name,
        &Work::CanHandle {
            item_json: share_json().to_owned(),
        },
        answer,
    );
    set.load(PluginSpec {
        id: id(name),
        version: "1.0.0".to_owned(),
        wasm: component_bytes(),
        grants: CapabilitySet::new(),
        policy: InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .unwrap_or_else(|error| panic!("{name} did not load: {error}"));
}

/// The share as JSON, which is what the contract's `can-handle` is handed.
///
/// # Why this is written out rather than serialised from [`ShareItem`]
///
/// Because `ShareItem` deliberately does not implement `Serialize`: what crosses the boundary is defined by the plugin
/// contract, not by the protocol's own inbound type, and deriving it here would let a change to an internal struct
/// silently change what every plugin sees.
///
/// # Why the device is a constant
///
/// Because a scripted backend is keyed by the exact string it was handed, so a `share_json()` that produced a fresh
/// device id on each call would script one string and match against another. Every test would then fall through to the
/// backend's empty-payload default, and a suite that passes without exercising anything is worse than one that fails.
const SHARE_JSON: &str = r#"{"from":"0192f7c0-0000-7000-8000-000000000001","mime":"text/uri-list","text":"https://example.invalid/","transfers":[]}"#;

/// The share as JSON, which is what the contract's `can-handle` is handed.
fn share_json() -> &'static str {
    SHARE_JSON
}

/// A board with one intent raised from a share, matching and waiting.
fn raised_board() -> (Board, IntentId) {
    let mut board = Board::new();
    let (intent_id, _trace, created) = board.raise(
        IntentSource::Share {
            item: share(),
            source_app: None,
        },
        Choice::AskWhenAmbiguous,
        None,
        None,
        1_000,
    );
    assert!(created, "the first raise is always new");
    (board, intent_id)
}

/// The candidate list an intent is currently holding.
fn candidates(board: &Board, id: IntentId) -> &[crate::intent::IntentCandidate] {
    board
        .get(id)
        .map(|intent| intent.state.candidates())
        .unwrap_or_default()
}

/// The titles of an intent's candidates.
fn titles(board: &Board, id: IntentId) -> Vec<String> {
    candidates(board, id)
        .iter()
        .map(|candidate| candidate.title.clone())
        .collect()
}

/// The versions of an intent's candidates, which is how an update under the prompt is noticed.
fn versions(board: &Board, id: IntentId) -> Vec<String> {
    candidates(board, id)
        .iter()
        .map(|candidate| candidate.plugin_version.clone())
        .collect()
}
