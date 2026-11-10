use synra_plugin_host::{Backend, Scripted, ScriptedBackend, Work};
use super::super::{Matcher, PluginSet, PluginSetError};
use super::{host, id, load, share_json, raised_board, candidates};

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
        (
            "a reported failure",
            Scripted::Failed {
                code: "host_failed".to_owned(),
                message: "the device is unreachable".to_owned(),
                details: None,
            },
        ),
        (
            "a trap",
            Scripted::Trap {
                detail: "unreachable".to_owned(),
            },
        ),
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
fn a_plugin_at_the_bottom_of_the_ladder_is_faulted_and_refused() {
    // ★ The health ladder and the lifecycle were two accounts of the same plugin. `record_misbehaviour` moved the first
    // and nothing moved the second, so a plugin the host had stopped trusting still looked `Active` and was still asked.
    // This is the join: the last rung of the ladder is a fault, and a faulted plugin is refused before it runs again.
    let backend = std::sync::Arc::new(ScriptedBackend::default());
    let mut set = PluginSet::new(Backend::new(std::sync::Arc::clone(&backend)), host());
    // ★ The window learns about the move, not just about the refusal: `PluginHealthChanged` had no publisher before the
    // sink existed, so a faulted card stayed green until the user re-read the list.
    let reported = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&reported);
    set = set.with_health_sink(std::sync::Arc::new(move |id, health, explanation| {
        sink.lock().push((id.to_string(), health.to_owned(), explanation.to_owned()));
    }));
    let name = "@synra/aaa-faults";
    load(&mut set, &backend, name, Scripted::Trap { detail: "boom".to_owned() });
    let plugin = id(name);
    let work = Work::CanHandle { item_json: share_json().to_owned() };
    let budget = Matcher::new(&mut set).budget();

    // Twenty bad calls in one window is what makes a window persistently bad; the ladder then moves one rung per
    // window, so the fault lands after the sixth. The loop stops the moment a call is refused rather than counting a
    // magic number that would change with the quota.
    let mut now = 0;
    let mut refused = None;
    'windows: for window in 0..8 {
        for _ in 0..synra_plugin_host::quota::PERSISTENT_REFUSALS {
            if let Err(error) = set.call(&plugin, &work, budget, now) {
                refused = Some(error);
                break 'windows;
            }
        }
        now = (window + 1) * 10_000;
    }

    assert!(
        matches!(
            set.lifecycle(&plugin).expect("still loaded").state(),
            synra_plugin_host::State::Faulted { .. }
        ),
        "the ladder reached the bottom without the lifecycle following it"
    );
    assert!(
        matches!(refused, Some(PluginSetError::Faulted { .. })),
        "a faulted plugin was still called: {refused:?}"
    );
    let events = reported.lock();
    assert!(
        events.iter().any(|(id, health, _)| id == name && health == "faulted"),
        "the window was never told about the fault: {events:?}"
    );
    drop(events);

    // ★ A retry is not a reload. Clearing the fault resets the ladder and returns the lifecycle to `Granted`, so
    // `activate` can run against the artifact that is already compiled.
    assert!(set.clear_fault(&plugin, 100_000).expect("a cleared fault"), "it was faulted");
    assert!(
        matches!(set.lifecycle(&plugin).expect("still loaded").state(), synra_plugin_host::State::Granted { .. }),
        "clearing the fault must leave it ready to activate, not active on its own"
    );
    assert_eq!(set.health_of(plugin.as_str()), Some(synra_plugin_host::quota::Health::Good));
    assert!(!set.clear_fault(&plugin, 100_000).expect("a second clear"), "it is not faulted any more");
}
