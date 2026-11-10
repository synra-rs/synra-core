use crate::actions::MAX_NOTIFICATION_LEN;
use crate::host::Platform;
use crate::{PlatformError, Policies};

use super::super::Desktop;
use super::{absolute, over_recorder};

#[test]
fn each_desktop_opens_a_url_with_its_own_program() {
    for (desktop, program) in
        [(Desktop::Linux, "xdg-open"), (Desktop::MacOs, "open"), (Desktop::Windows, "explorer")]
    {
        let (recorder, platform) = over_recorder(desktop);
        platform.open_url("https://example.com").expect("opened");
        assert_eq!(recorder.commands(), vec![format!("{program} https://example.com")]);
    }
    assert_eq!(Desktop::Linux.as_str(), "linux");
}

#[test]
fn revealing_a_file_highlights_it_rather_than_opening_it() {
    // ★ `explorer /select,` and `open -R` are how a file is *shown*; the opener would open the directory instead, which
    // is a different thing to ask for and a different thing to see.
    //
    // No sandbox root, because this is about the command: the sandbox rule is a *refusal* and has its own test.
    let file = absolute("a.txt");
    let expected = format!("explorer /select, {}", file.display());

    let root = absolute("");
    let (recorder, platform) = over_recorder(Desktop::Windows);
    platform.reveal_path(&file, Some(&root)).expect("revealed");
    assert_eq!(recorder.commands(), vec![expected]);

    let (recorder, platform) = over_recorder(Desktop::MacOs);
    platform.reveal_path(&file, Some(&root)).expect("revealed");
    assert_eq!(recorder.commands(), vec![format!("open -R {}", file.display())]);

    let (recorder, platform) = over_recorder(Desktop::Linux);
    platform.reveal_path(&file, Some(&root)).expect("revealed");
    assert_eq!(recorder.commands(), vec![format!("xdg-open {}", file.display())]);
}

#[test]
fn a_url_the_policy_refuses_never_reaches_the_runner() {
    // ★ The order is the point. A check that ran after the launch would be a check that reported a window it had
    // already opened.
    for url in ["javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd"] {
        let (recorder, platform) = over_recorder(Desktop::Linux);
        let refused = platform.open_url(url);
        assert!(refused.is_err(), "{url} was accepted");
        assert_eq!(recorder.count(), 0, "{url} ran a program anyway: {:?}", recorder.commands());
    }

    // And a URL that is fine does reach it, so the check is not one that refuses everything.
    let (recorder, platform) = over_recorder(Desktop::Linux);
    platform.open_url("https://example.com").expect("opened");
    assert_eq!(recorder.count(), 1);
}

#[test]
fn a_path_the_policy_refuses_never_reaches_the_runner() {
    // A reveal is sandbox-restricted by default, so a plugin cannot show the user their own `~/.ssh` in a file manager.
    let (recorder, platform) = over_recorder(Desktop::Linux);
    let sandbox = absolute("sandbox");
    let outside = if cfg!(windows) {
        std::path::PathBuf::from("C:\\Users\\someone\\.ssh\\id_ed25519")
    }
    else {
        std::path::PathBuf::from("/home/someone/.ssh/id_ed25519")
    };
    let refused = platform.reveal_path(&outside, Some(&sandbox));
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(recorder.count(), 0, "a refused reveal ran a program: {:?}", recorder.commands());

    let inside = sandbox.join("data").join("file.txt");
    platform.reveal_path(&inside, Some(&sandbox)).expect("revealed");
    assert_eq!(recorder.count(), 1);
}

#[test]
fn simulating_keys_is_refused_by_policy_before_the_rate_limit_or_the_runner() {
    // ★ A plugin that can type into whatever window is focused can do anything the user can, so this is off by
    // default — and the refusal is about the policy rather than about the interval, which is the message an author
    // needs.
    let (recorder, platform) = over_recorder(Desktop::Linux);
    match platform.simulate_keys("ctrl+s") {
        Err(PlatformError::SimulateKeysNotGranted) => {}
        other => panic!("expected a policy refusal, got {other:?}"),
    }
    assert_eq!(recorder.count(), 0);

    // With the policy allowing it, the chord reaches the desktop's own tool.
    let (recorder, platform) = over_recorder(Desktop::Linux);
    let platform = platform.with_policies(Policies::new().with_simulate_keys(true));
    platform.simulate_keys("ctrl+s").expect("simulated");
    assert_eq!(
        recorder.commands(),
        vec!["xdotool key -- ctrl+s".to_owned()]
    );
}

#[test]
fn a_chord_that_is_not_a_chord_is_refused_before_the_runner() {
    // A chord reaches a command line, so what may be in one is checked rather than trusted.
    // The guard's job is what a chord may *be*, not whether it is a key the desktop knows: a chord reaches a program's
    // argument list, so an empty one and an over-long one are refused, and `ctrl+;` is left to the desktop to reject.
    for chord in ["", "   ", "a".repeat(200).as_str()] {
        let (recorder, platform) = over_recorder(Desktop::MacOs);
        let platform = platform.with_policies(Policies::new().with_simulate_keys(true));
        let refused = platform.simulate_keys(chord);
        assert!(refused.is_err(), "{chord:?} was accepted");
        assert_eq!(recorder.count(), 0, "{chord:?} ran a program");
    }
}

#[test]
fn a_notification_over_the_length_limit_never_reaches_the_runner() {
    let (recorder, platform) = over_recorder(Desktop::Linux);
    let long = "x".repeat(MAX_NOTIFICATION_LEN + 1);
    let refused = platform.notify("a title", &long);
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(recorder.count(), 0);

    platform.notify("Hello", "World").expect("notified");
    assert_eq!(
        recorder.commands(),
        vec!["notify-send -- Hello World".to_owned()]
    );
}

#[test]
fn a_plugins_notification_text_is_an_argument_and_never_part_of_a_script() {
    // The macOS script is fixed; data follows the option terminator as separate argv values.
    let (recorder, platform) = over_recorder(Desktop::MacOs);
    platform.notify("Title\" & (do shell script \"rm -rf /\") & \"", "Body").expect("notified");
    let command = recorder.commands().first().cloned().expect("a command");
    assert!(command.starts_with("osascript -e on run argv"), "{command}");
    assert!(command.contains("item 1 of argv"), "the script reads its arguments: {command}");
    // The title and the body are the last two arguments; the title carries the injection attempt.
    assert!(command.ends_with("Body"), "{command}");
    // ★ And what `osascript -e` is given as its *script* is three fixed fragments, the last of which ends at `end run`.
    // The title lands after that, so nothing a plugin wrote is part of the program — which is the property that makes
    // this a fixed program reading `argv` rather than an assembled one.
    let script: Vec<&str> = command.split(" -e ").skip(1).take(3).collect();
    assert_eq!(script.len(), 3, "{command}");
    assert_eq!(script.first().copied(), Some("on run argv"), "{command}");
    assert!(
        script
            .get(2)
            .is_some_and(|fragment| fragment.contains("end run")),
        "{command}"
    );
    let (program, arguments) = command
        .split_once("end run -- ")
        .expect("the script and its arguments");
    assert_eq!(
        arguments,
        "Title\" & (do shell script \"rm -rf /\") & \" Body"
    );
    assert!(
        !program.contains("rm -rf"),
        "the injection reached the program: {program}"
    );

    // A different notification has the same program up to `end run`, which is what says the program is fixed rather
    // than assembled from the text — everything after that point is the two arguments.
    let (second, platform) = over_recorder(Desktop::MacOs);
    platform.notify("Other", "Other").expect("notified");
    let other = second.commands().first().cloned().expect("a command");
    let other_program = other
        .split_once("end run -- ")
        .map(|(program, _)| program.to_owned());
    assert_eq!(
        Some(program.to_owned()),
        other_program,
        "the program depends on the text"
    );
}

#[test]
fn option_like_notification_text_follows_the_option_terminator() {
    for desktop in [Desktop::MacOs, Desktop::Linux] {
        let (recorder, platform) = over_recorder(desktop);
        platform.notify("-e", "literal data").expect("notification");
        let arguments = recorder
            .seen
            .lock()
            .expect("recorded command")
            .first()
            .expect("one command")
            .1
            .clone();
        let separated = matches!(arguments.as_slice(), [.., separator, title, body]
            if separator == "--" && title == "-e" && body == "literal data");
        assert!(separated);
    }
}
