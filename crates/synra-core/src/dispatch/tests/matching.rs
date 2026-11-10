use synra_plugin_host::{Backend, Scripted, ScriptedBackend};
use super::super::{MatchReport, Matcher, PluginSet};
use super::{host, id, load, share_json, raised_board, candidates, titles};

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
fn every_plugin_failing_is_distinguishable_from_nothing_being_installed() {
    let backend = ScriptedBackend::new();
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
fn the_report_is_the_default_of_nothing_happening() {
    let report = MatchReport::default();
    assert!(!report.matched());
    assert!(!report.all_misbehaved());
    assert_eq!(report.asked, 0);
}
