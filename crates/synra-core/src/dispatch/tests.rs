//! What a matching pass does when plugins answer badly, and when they answer well.
//!
//! # Why these use a scripted backend
//!
//! Because the questions here are about the host's behaviour — does one bad plugin cost the user the good ones, is a
//! decline an error, is a non-answer visible — and every one of them can be asked without a `.wasm` file that would
//! have to be reviewed. A test that needs a real component tests the engine; a test that needs a table tests the host,
//! and these are the second kind.

use synra_capability::CapabilitySet;
use synra_plugin_host::{Backend, InstancePolicy, Scripted, ScriptedBackend, Work};
use synra_protocol::ids::{DeviceId, IntentId, PluginId};
use synra_protocol::inbound::ShareItem;

use crate::intent::{Board, Choice, IntentSource};

use super::{MatchReport, Matcher, PluginSet, PluginSetError, PluginSpec};

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

#[test]
fn a_plugin_that_handles_a_share_becomes_a_candidate() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/browser",
        Scripted::Ok(r#"{"handled":true,"action":"open","title":"Open in Browser"}"#.to_owned()),
    );

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(report.asked, 1, "the one loaded plugin is asked once");
    assert_eq!(report.handled, 1, "it said yes");
    assert_eq!(report.offered, 1, "and the board kept the candidate");
    assert!(
        report.misbehaved.is_empty(),
        "nothing misbehaved: {:?}",
        report.misbehaved
    );
    assert_eq!(
        candidates(&board, intent_id).len(),
        1,
        "the user would be shown one candidate"
    );
}

#[test]
fn declining_is_not_a_failure() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/notes",
        Scripted::Ok(r#"{"handled":false}"#.to_owned()),
    );

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(
        report.declined, 1,
        "a decline is the common answer and is counted as one"
    );
    assert_eq!(report.handled, 0);
    assert!(
        report.misbehaved.is_empty(),
        "a plugin that works must not look like a bug: {:?}",
        report.misbehaved
    );
    assert!(!report.matched(), "nothing was offered");
}

#[test]
fn one_trapping_plugin_does_not_cost_the_user_the_others() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/aaa-broken",
        Scripted::Trap {
            detail: "unreachable".to_owned(),
        },
    );
    load(
        &mut set,
        &backend,
        "@synra/bbb-good",
        Scripted::Ok(r#"{"handled":true,"title":"Good"}"#.to_owned()),
    );

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(report.asked, 2, "both were asked");
    assert_eq!(
        report.offered, 1,
        "the working plugin's answer still reached the board"
    );
    assert_eq!(
        report.misbehaved.len(),
        1,
        "and the trap is recorded rather than lost"
    );
    assert!(
        !report.all_misbehaved(),
        "not every plugin failed, so this is not a total failure"
    );
    assert_eq!(
        candidates(&board, intent_id).len(),
        1,
        "the user still gets their prompt"
    );
}

#[test]
fn every_way_a_plugin_can_misbehave_leaves_the_others_working() {
    // """ + S + """ The sentence `21 §5.1` says nothing asserts: *"内核仍可用 + 其它插件仍可用"*.
    //
    // The isolation test above covers one way a plugin fails — a trap — and a panic has its own. The rest did not exist, and
    // they are the ones a user is most likely to meet: a plugin that reports a failure, one that runs out of its instruction
    // budget, one that hits the memory ceiling, and one that never comes back. Each is a different condition inside the host
    // and each could plausibly be handled by a path that abandons the whole dispatch rather than that one plugin.
    //
    // # What this proves and what it does not
    //
    // It proves the **kernel's** handling: given this outcome from a plugin, the other plugins are still asked and the user
    // still gets a prompt. It does not prove the *engine* produces those outcomes — that is the fuel and memory tests in
    // `synra-plugin-host`, which drive real components. Two halves of one property, and each is worthless without the other:
    // an engine that never exhausts fuel makes this table vacuous, and a kernel that gives up on the first bad outcome makes
    // the engine's enforcement useless.
    let cases: [(&str, Scripted); 6] = [
        ("a reported failure", Scripted::Failed {
            code: "host_failed".to_owned(),
            message: "the device is unreachable".to_owned(),
        }),
        ("a trap", Scripted::Trap { detail: "unreachable".to_owned() }),
        ("an exhausted instruction budget", Scripted::FuelExhausted),
        ("a memory ceiling", Scripted::MemoryExceeded),
        ("a timeout", Scripted::Timeout),
        ("a panic in the host", Scripted::Panic { message: "unwrap on None".to_owned() }),
    ];

    for (index, (what, answer)) in cases.into_iter().enumerate() {
        let backend = ScriptedBackend::new();
        let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
        // A fresh id per case, so one case's scripted answer cannot satisfy another's call.
        let broken = format!("@synra/aaa-broken-{index}");
        load(&mut set, &backend, &broken, answer);
        load(
            &mut set,
            &backend,
            "@synra/bbb-good",
            Scripted::Ok(r#"{"handled":true,"title":"Good"}"#.to_owned()),
        );

        let (mut board, intent_id) = raised_board();
        let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

        assert_eq!(report.asked, 2, "{what}: both were asked");
        assert_eq!(
            report.offered, 1,
            "{what}: the working plugin's answer still reached the board"
        );
        assert_eq!(report.misbehaved.len(), 1, "{what}: and it is recorded");
        assert!(!report.all_misbehaved(), "{what}: not every plugin failed");
        assert_eq!(
            candidates(&board, intent_id).len(),
            1,
            "{what}: the user still gets their prompt"
        );
        // """ + S + """ And the kernel is still usable **afterwards**, which is the half a per-dispatch assertion misses: a
        // dispatch that recovered but left the set poisoned would pass everything above and fail the next share.
        let (mut second_board, second_intent) = raised_board();
        let second =
            Matcher::new(&mut set).match_share(&mut second_board, second_intent, share_json(), 2_000);
        assert_eq!(
            second.offered, 1,
            "{what}: the next share is served by the plugin that works"
        );
    }
}

/// ★ A plugin that makes the **host** panic must not take the kernel with it.
///
/// This is the test behind `[profile.release] panic = "unwind"`, whose comment gives exactly one reason: that a plugin's
/// panic has to be catchable. Until `Scripted::Panic` and the `catch_unwind` in `run_on` existed, nothing in the
/// workspace unwound through a plugin call — so the profile was configured for a mechanism that was never written, and
/// the claim "one plugin's bug cannot stop the kernel" rested on nothing.
///
/// # What the assertions below actually prove
///
/// The dispatch returns, both plugins were asked, the good plugin's answer reached the board, and the panic is recorded
/// against the plugin that raised it. Removing the `catch_unwind` makes this test fail — but it fails **loudly**, by
/// unwinding out of the test function, because the test harness catches a panic at its own boundary.
///
/// So this test does not simulate the production consequence, and it does not claim to. In a real dispatch there is no
/// harness around the call: the unwind would travel out of `run_on`, out of the matcher, and out of whatever kernel
#[test]
fn every_audited_call_reaches_the_sink_as_well_as_the_ring() {
    // ★ The two halves of one trail, and the assertion that they are the same trail.
    //
    // The ring is what the interface reads *now*; the sink is what survives a restart. A record written to one and not the
    // other is a trail that disagrees with itself the moment the process ends — so the two lists are compared rather than
    // each being checked for plausibility.
    //
    // ★ Why this drives the drain rather than a scripted call.
    //
    // The first version of this test ran a matching pass over scripted plugins and asserted the sink had seen something. It
    // had seen nothing, and was right to: `ScriptedBackend` answers from a table, so no guest runs, no host function is
    // called, and nothing is audited. The entries a sink receives are produced by a **real** component calling a host
    // function, which is what the `wasm-text` suite in `synra-plugin-host` drives. What is tested here is the seam this
    // round added — `drain_audit`, which is the one place the two halves are written — with the entries put where a real
    // call puts them.
    let backend = ScriptedBackend::new();
    let delivered = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let collected = std::sync::Arc::clone(&delivered);

    let mut set =
        PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host()).with_audit_sink(
            std::sync::Arc::new(move |entry: &synra_observe::audit::AuditEntry| {
                collected.lock().push(entry.clone());
            }),
        );
    load(&mut set, &backend, "@synra/aaa-notes", Scripted::Ok(r#"{"handled":true}"#.to_owned()));

    let plugin = id("@synra/aaa-notes");
    let entry = synra_observe::audit::AuditEntry::new(
        1_000,
        plugin.clone(),
        synra_capability::Capability::parse("device:list").expect("a capability"),
        synra_observe::audit::AuditOutcome::Allowed,
        Some(4),
    );

    assert!(
        set.drain_record_for_test(&plugin, entry.clone()),
        "the plugin has to be loaded for there to be a buffer to drain"
    );

    assert_eq!(*delivered.lock(), vec![entry.clone()], "the sink saw the record");
    assert_eq!(set.audit(), vec![entry], "and so did the ring");
}

#[test]
fn clearing_one_plugins_history_leaves_the_other() {
    // ★ Clearing is a per-card action: the ring holds every plugin's calls, and a "clear" that took the whole ring would
    // erase what the user was about to read on the next card. The counts are part of the history too, so the assertion is
    // on what the ring answers after the removal rather than on the entries alone.
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/aaa-notes",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    load(
        &mut set,
        &backend,
        "@synra/bbb-notes",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );

    let cleared = id("@synra/aaa-notes");
    let kept = id("@synra/bbb-notes");
    let record = |plugin: &PluginId, at_ms: i64| {
        synra_observe::audit::AuditEntry::new(
            at_ms,
            plugin.clone(),
            synra_capability::Capability::parse("device:list").expect("a capability"),
            synra_observe::audit::AuditOutcome::Allowed,
            Some(1),
        )
    };
    assert!(set.drain_record_for_test(&cleared, record(&cleared, 1_000)));
    assert!(set.drain_record_for_test(&kept, record(&kept, 2_000)));

    set.clear_audit(&cleared);

    assert!(set.audit_for(&cleared).is_empty(), "the cleared plugin has no records left");
    assert_eq!(set.audit_for(&kept).len(), 1, "another plugin's records are not collateral");
}

/// thread was running it — no `Trap` outcome, no audit record, and no prompt for the user. The test detects the
/// regression; the difference it makes in production is larger than the difference it makes here.
#[test]
fn a_plugin_that_panics_the_host_does_not_stop_the_kernel() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/aaa-panicking",
        Scripted::Panic {
            message: "a deliberate panic from a host function".to_owned(),
        },
    );
    load(
        &mut set,
        &backend,
        "@synra/bbb-good",
        Scripted::Ok(r#"{"handled":true,"title":"Good"}"#.to_owned()),
    );

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    // Both were asked, so the panic did not stop the dispatch loop.
    assert_eq!(report.asked, 2, "the panicking plugin ended the round early");
    // The good plugin's answer still arrived, which is the user-visible half of the guarantee.
    assert_eq!(
        report.offered, 1,
        "the working plugin's answer still reached the board"
    );
    assert_eq!(
        report.misbehaved.len(),
        1,
        "the panic is recorded against the plugin rather than lost"
    );
    assert!(
        !report.all_misbehaved(),
        "not every plugin failed, so this is not a total failure"
    );
    assert_eq!(
        candidates(&board, intent_id).len(),
        1,
        "the user still gets their prompt"
    );
}

#[test]
fn an_execution_runs_under_the_plugins_own_quota() {
    // ★ The quota, actually enforced.
    //
    // `CallBudget::from_quota` is documented as the mapping — *"Every field is taken from the quota rather than chosen
    // here, so the number a user sees in a settings screen is the number the sandbox enforces"* — and **production never
    // called it**. Only the scripted backend's `enforcement` and a test did, so `share.execute` ran under a fixed
    // five-second timeout with no instruction limit at all, whatever the plugin's quota said.
    //
    // The scripted backend's `Timeout` answer reports the budget it was given, which is what makes this assertable
    // without an engine: a call that was handed no timeout returns `Ok`, not a timeout, so an outcome here is proof a
    // budget arrived and the number in it is the number that was sent.
    let candidates = [
        ("a quota of its own", 1_234, synra_plugin_host::quota::Quota { call_timeout_ms: 1_234, ..synra_plugin_host::quota::Quota::default() }),
        ("the default quota", 2_000, synra_plugin_host::quota::Quota::default()),
    ];

    for (what, expected_ms, quota) in candidates {
        let backend = ScriptedBackend::new();
        backend.script(
            &Work::Execute { action: "open".to_owned(), args_json: "null".to_owned() },
            Scripted::Timeout,
        );
        let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());
        set.load(PluginSpec {
            id: id("@synra/aaa-quota"),
            version: "1.0.0".to_owned(),
            wasm: component_bytes(),
            grants: CapabilitySet::new(),
            policy: InstancePolicy::Stateless,
            limit: 4,
            quota,
        })
        .expect("loads");

        let outcome = crate::dispatch::execute(
            &mut set,
            &id("@synra/aaa-quota"),
            &candidate_for("@synra/aaa-quota"),
            0,
        )
        .expect("the call is made");

        match outcome {
            synra_plugin_host::CallOutcome::Timeout { after } => assert_eq!(
                after,
                std::time::Duration::from_millis(expected_ms),
                "{what}: the call was given the wrong timeout"
            ),
            // Catches the specific regression this test exists for: before the fix the budget was `execute_budget`'s
            // fixed five seconds with `fuel: None`, and a scripted `Timeout` with a budget is a timeout.
            other => panic!("{what}: expected the quota's timeout, got {other:?}"),
        }
    }
}

#[test]
fn an_artifact_importing_a_function_its_capabilities_do_not_cover_is_refused_at_load() {
    // ★ The load-time half of the three-layer gate, which had no caller until this test existed.
    //
    // `host_surface::undeclared_imports` was written, tested, and called by nothing in production — the pipeline that
    // uses it, `verify::verify`, has no caller either. So a plugin whose Wasm imported a host function its manifest
    // never declared was loaded and run, and the only sign would have been a call refused at the gate long afterwards,
    // on a code path nobody was reading.
    //
    // What is checked is what the **component** imports rather than what the manifest claims, so the double has to be
    // able to report an import for the check to be exercised at all. That is why `ScriptedBackend::importing` exists.
    let backend = ScriptedBackend::new().importing(&["synra:plugin/host#network-fetch"]);
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());

    let refused = set.load(PluginSpec {
        id: id("@synra/aaa-wants-network"),
        version: "1.0.0".to_owned(),
        wasm: component_bytes(),
        // Granted nothing. The artifact imports a function that needs `network:fetch:*`.
        grants: CapabilitySet::new(),
        policy: InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    });

    match refused {
        Err(PluginSetError::UndeclaredImport { import, .. }) => {
            // ★ The message names the **import**, not the capability. An author needs to know which import to drop or
            // declare; naming a capability at a user would suggest a setting they could change, which is the opposite
            // of true.
            assert!(import.contains("network-fetch"), "{import}");
        }
        other => panic!("an undeclared import should refuse the load, got {other:?}"),
    }

    // And nothing was loaded, so a refused plugin cannot be called by accident.
    assert!(set.is_empty(), "a refused plugin must not be in the set: {:?}", set.ids());
}

#[test]
fn an_artifact_importing_a_function_its_capabilities_do_cover_loads() {
    // The other direction, and the one that keeps the check from being a rule nobody can satisfy: the same import with
    // the capability behind it loads.
    let backend = ScriptedBackend::new().importing(&["synra:plugin/host#network-fetch"]);
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());

    let mut grants = CapabilitySet::new();
    grants.insert_str("network:fetch:*").expect("a capability");

    set.load(PluginSpec {
        id: id("@synra/bbb-declared-network"),
        version: "1.0.0".to_owned(),
        wasm: component_bytes(),
        grants,
        policy: InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .expect("the import is covered, so the load succeeds");

    assert_eq!(set.len(), 1);
}

#[test]
fn every_plugin_failing_is_distinguishable_from_nothing_being_installed() {    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(&mut set, &backend, "@synra/aaa", Scripted::Timeout);

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert!(!report.matched(), "nothing was offered either way");
    assert!(
        report.all_misbehaved(),
        "but this one is a bug report, not a fact about what is installed"
    );
}

#[test]
fn an_empty_kernel_matched_nothing_and_asked_nobody() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());
    let (mut board, intent_id) = raised_board();

    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(report.asked, 0);
    assert!(!report.matched());
    assert!(
        !report.all_misbehaved(),
        "nobody failing is not everybody failing, and the difference is a bug report"
    );
}

#[test]
fn an_answer_that_is_not_json_is_recorded_rather_than_guessed_at() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/broken-json",
        Scripted::Ok("not json at all".to_owned()),
    );

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(report.offered, 0, "an unreadable answer is not a candidate");
    assert_eq!(report.misbehaved.len(), 1);
    assert_eq!(
        report.misbehaved[0].plugin_id,
        id("@synra/broken-json"),
        "the report names the plugin"
    );
}

#[test]
fn a_plugin_that_only_says_yes_is_still_offered() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/terse",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(
        report.offered, 1,
        "a short answer is still an answer, and dropping it would hide a working plugin"
    );
    assert_eq!(
        titles(&board, intent_id),
        vec!["@synra/terse".to_owned()],
        "with something for the prompt to show"
    );
}

#[test]
fn calling_a_plugin_that_is_not_loaded_says_so() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend)), host());
    let budget = Matcher::new(&mut set).budget();

    let error = set.call(&id("@synra/absent"), &Work::Deactivate, budget, 0);

    assert_eq!(
        error,
        Err(PluginSetError::NotLoaded {
            id: id("@synra/absent")
        })
    );
}

#[test]
fn a_call_is_counted_and_timed_per_plugin_and_interface() {
    // ★ The plugin group's first two metrics, recorded at the one funnel every call passes. The interface label is
    // `Work::interface` — the protocol's own spelling — so the panel, the card and the wire agree about what a call is.
    use synra_observe::metrics::Value;

    let backend = ScriptedBackend::new();
    let metrics = std::sync::Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host())
        .with_metrics(std::sync::Arc::clone(&metrics));
    load(
        &mut set,
        &backend,
        "@synra/aaa-notes",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    let work = Work::CanHandle { item_json: share_json().to_owned() };
    let budget = Matcher::new(&mut set).budget();

    set.call(&id("@synra/aaa-notes"), &work, budget, 1_000).expect("a call");

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.get("plugin_calls_total{interface=share,plugin=@synra/aaa-notes}"),
        Some(&Value::Counter(1)),
        "the call is counted against the plugin and the interface"
    );
    match snapshot.get("plugin_call_duration_us{interface=share,plugin=@synra/aaa-notes}") {
        Some(Value::Histogram(histogram)) => assert_eq!(histogram.count, 1),
        other => panic!("expected a duration histogram, got {other:?}"),
    }
}

#[test]
fn a_trapped_call_is_counted_as_a_fault_with_its_outcome() {
    // ★ A trap is the case the health ladder was missing for years; the metric makes it visible without reading that
    // ladder, and the outcome label says which kind of misbehaviour it was rather than only that there was one.
    use synra_observe::metrics::Value;

    let backend = ScriptedBackend::new();
    let metrics = std::sync::Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host())
        .with_metrics(std::sync::Arc::clone(&metrics));
    load(
        &mut set,
        &backend,
        "@synra/bad",
        Scripted::Trap { detail: "boom".to_owned() },
    );
    let work = Work::CanHandle { item_json: share_json().to_owned() };
    let budget = Matcher::new(&mut set).budget();

    // A trap is an outcome, not a `PluginSetError`; the assertion is on the recorder, which is what the panel reads.
    let _ = set.call(&id("@synra/bad"), &work, budget, 1_000);

    assert_eq!(
        metrics.snapshot().get("plugin_faulted_total{outcome=trap,plugin=@synra/bad}"),
        Some(&Value::Counter(1)),
        "the trap is counted against the plugin that produced it"
    );
}

#[test]
fn unloading_a_plugin_takes_it_out_of_the_next_pass() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/before",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    load(
        &mut set,
        &backend,
        "@synra/after",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    assert_eq!(set.len(), 2);

    assert!(
        set.unload(&id("@synra/before")),
        "unloading reports whether anything was there"
    );
    assert!(
        !set.unload(&id("@synra/before")),
        "and a second unload reports that nothing was"
    );
    assert_eq!(set.len(), 1);

    let (mut board, intent_id) = raised_board();
    let report = Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);
    assert_eq!(
        report.asked, 1,
        "only the plugin that is still loaded is asked"
    );
}

#[test]
fn loading_twice_replaces_the_plugin() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    load(
        &mut set,
        &backend,
        "@synra/updating",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    load(
        &mut set,
        &backend,
        "@synra/updating",
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );

    assert_eq!(set.len(), 1, "an update is not a second plugin");
    assert_eq!(set.version(&id("@synra/updating")), Some("1.0.0"));
}

#[test]
fn the_version_a_dispatch_records_is_the_one_loaded_now() {
    let backend = ScriptedBackend::new();
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(backend.clone())), host());
    backend.script_for(
        "@synra/moving",
        &Work::CanHandle {
            item_json: share_json().to_owned(),
        },
        Scripted::Ok(r#"{"handled":true}"#.to_owned()),
    );
    set.load(PluginSpec {
        id: id("@synra/moving"),
        version: "2.0.0".to_owned(),
        wasm: component_bytes(),
        grants: CapabilitySet::new(),
        policy: InstancePolicy::Stateless,
        limit: 1,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .unwrap_or_else(|error| panic!("did not load: {error}"));

    let (mut board, intent_id) = raised_board();
    Matcher::new(&mut set).match_share(&mut board, intent_id, share_json(), 1_000);

    assert_eq!(
        versions(&board, intent_id),
        vec!["2.0.0".to_owned()],
        "a plugin updated under the prompt is noticed"
    );
}

#[test]
fn the_report_is_the_default_of_nothing_happening() {
    let report = MatchReport::default();
    assert!(!report.matched());
    assert!(!report.all_misbehaved());
    assert_eq!(report.asked, 0);
}

// ── A real malicious guest, through the kernel ────────────────────────────────────────────────────

/// A component whose `deactivate` never returns.
///
/// # """ + S + """ Why `deactivate`, and why hand-written `.wat`
///
/// `activate`, `can-handle` and `migrate` all take or return a `string`, whose canonical ABI a hand-written component has to
/// implement by hand — a pointer and a length in, a pointer and a length out, a `realloc`, a `post-return`. `deactivate` is
/// `func()`: no parameters, no results, so its lift is a core function with **no signature at all** and four lines of text
/// suffice. The instruction budget is a property of the engine rather than of the interface, so a guest that loops in
/// `deactivate` tests exactly the same limit as one that loops in `activate`.
const SPINS: &str = r#"
(component
  (core module $m
    (func (export "spin")
      (loop $l
        (br $l))))
  (core instance $i (instantiate $m))
  (func $deactivate
    (canon lift (core func $i "spin")))
  (instance $lifecycle (export "deactivate" (func $deactivate)))
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
)
"#;

/// A component whose `deactivate` returns at once.
const FINISHES: &str = r#"
(component
  (core module $m
    (func (export "stop")))
  (core instance $i (instantiate $m))
  (func $deactivate
    (canon lift (core func $i "stop")))
  (instance $lifecycle (export "deactivate" (func $deactivate)))
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
)
"#;

#[test]
fn a_plugin_that_exhausts_its_budget_is_not_broken_afterwards() {
    // """ + S + """ A bad call must not cost the plugin its **next** call, and this was broken.
    //
    // `PluginSet` throws an instance away when a panic unwinds out of a call — the comment there is explicit about why
    // ("the store is in a state nothing can reason about"). It kept the instance when the **engine** stopped the guest, and a
    // trapped component instance cannot be entered again: wasmtime answers the next call with
    // `Trap { detail: "wasm trap: cannot enter component instance" }`.
    //
    // So one budget overrun made a plugin permanently broken: every later call to it failed with a trap that says nothing
    // about the plugin and everything about the instance the kernel was reusing. The user's remedy would be to restart the
    // app.
    let bytes = |wat: &str| wat::parse_str(wat).expect("the fixture is valid text");
    let engine = synra_plugin_host::engine::WasmtimeBackend::new(
        synra_plugin_host::BackendKind::WasmtimeCranelift,
    )
    .expect("an engine");
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(engine)), host());
    set.load(PluginSpec {
        id: id("@synra/aaa-spins"),
        version: "1.0.0".to_owned(),
        wasm: bytes(SPINS),
        grants: CapabilitySet::new(),
        policy: InstancePolicy::Stateless,
        limit: 4,
        quota: synra_plugin_host::quota::Quota::default(),
    })
    .expect("loads");

    let spins = id("@synra/aaa-spins");
    let wasteful = synra_plugin_host::CallBudget {
        fuel: Some(1_000),
        timeout: None,
        max_memory_growth: None,
    };
    let first = set
        .call(&spins, &Work::Deactivate, wasteful, 1_000)
        .expect("a call");
    assert!(
        matches!(first, synra_plugin_host::CallOutcome::FuelExhausted { .. }),
        "the loop must exhaust a thousand instructions, got {first:?}"
    );

    // """ + S + """ The call that matters: the same plugin, asked again with a budget it can meet.
    let generous = synra_plugin_host::CallBudget {
        fuel: None,
        timeout: Some(std::time::Duration::from_millis(250)),
        max_memory_growth: None,
    };
    let second = set.call(&spins, &Work::Deactivate, generous, 2_000).expect("a call");
    assert!(
        !matches!(second, synra_plugin_host::CallOutcome::Trap { .. }),
        "the plugin was asked again with a workable budget and trapped: {second:?}"
    );
    // And it really ran, rather than being reported as fine because nothing happened.
    assert!(
        matches!(second, synra_plugin_host::CallOutcome::Timeout { .. }),
        "an unlimited loop runs until its clock, got {second:?}"
    );
}

#[test]
fn a_real_guest_that_loops_is_stopped_without_costing_the_others() {
    // """ + S + """ The strongest form of `21 §5.1`'s sentence, and the one thing no double can stand in for.
    //
    // The isolation table above proves the **kernel's** handling of an outcome; the engine's own tests prove the engine
    // produces it. Neither runs a real guest **through the kernel**, which is the property a user has: a plugin whose bytes
    // contain `while true` must not stop the kernel, and the plugin beside it must keep working. So this loads a genuine
    // looping component into a `PluginSet` over the real engine, calls it, and then asks the other one.
    //
    // A scripted backend cannot do this. `Scripted::FuelExhausted` is a value somebody wrote down, and the failure it cannot
    // express is the one that matters: the engine really counting instructions and really stopping.
    let bytes = |wat: &str| wat::parse_str(wat).expect("the fixture is valid text");
    let engine = synra_plugin_host::engine::WasmtimeBackend::new(
        synra_plugin_host::BackendKind::WasmtimeCranelift,
    )
    .expect("an engine");
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::new(engine)), host());

    for (name, wat) in [("@synra/aaa-spins", SPINS), ("@synra/bbb-finishes", FINISHES)] {
        set.load(PluginSpec {
            id: id(name),
            version: "1.0.0".to_owned(),
            wasm: bytes(wat),
            grants: CapabilitySet::new(),
            policy: InstancePolicy::Stateless,
            limit: 4,
            quota: synra_plugin_host::quota::Quota::default(),
        })
        .expect("loads");
    }

    // A bounded budget, so the loop cannot run forever and the test cannot hang if the engine does not count.
    let budget = synra_plugin_host::CallBudget {
        fuel: Some(100_000),
        timeout: None,
        max_memory_growth: None,
    };

    let spun = set
        .call(&id("@synra/aaa-spins"), &Work::Deactivate, budget, 1_000)
        .expect("a call");
    assert!(
        matches!(spun, synra_plugin_host::CallOutcome::FuelExhausted { .. }),
        "a real infinite loop must be stopped by its instruction budget, got {spun:?}"
    );

    // """ + S + """ And the kernel is still usable, with the other plugin in the same set: the plugin beside the malicious
    // one answers, twice, so a set left in a bad state fails here rather than at the next share.
    for now in [1_000_u64, 2_000] {
        let finished = set
            .call(&id("@synra/bbb-finishes"), &Work::Deactivate, budget, now)
            .expect("a call");
        assert!(
            !finished.is_misbehaviour(),
            "the plugin beside the looping one must keep working, got {finished:?}"
        );
    }
}
