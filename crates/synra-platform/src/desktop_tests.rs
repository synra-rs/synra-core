//! The desktop platform, driven with a runner that records rather than launches.
//!
//! Every test here is about *order*: the policy check happens before the runner is reached, so a refusal that still ran
//! a program would be a refusal that opened a window. The stub records, and the assertions are on what it saw.

use std::sync::Mutex;
use std::time::Duration;

use crate::actions::MAX_NOTIFICATION_LEN;

use super::*;

/// A runner that records what it was asked and answers with whatever it was told to.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<(String, Vec<String>)>>,
    input: Mutex<Vec<Option<String>>>,
    /// What a successful run prints, which is how `read_clipboard` is tested.
    stdout: String,
    /// Whether every run fails, which is how a missing program is tested.
    failing: bool,
}

impl Recorder {
    fn printing(stdout: &str) -> Self {
        Self { stdout: stdout.to_owned(), ..Self::default() }
    }

    fn failing() -> Self {
        Self { failing: true, ..Self::default() }
    }

    /// Every command that reached the runner, as `program arg arg`.
    fn commands(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|(program, arguments)| format!("{program} {}", arguments.join(" ")).trim().to_owned())
            .collect()
    }

    /// How many commands reached the runner.
    fn count(&self) -> usize {
        self.seen.lock().expect("not poisoned").len()
    }
}

impl CommandRunner for Recorder {
    fn is_available(&self) -> bool {
        true
    }
    fn run(
        &self,
        program: &str,
        arguments: &[&str],
        input: Option<&str>,
    ) -> Result<String, PlatformError> {
        self.input
            .lock()
            .expect("not poisoned")
            .push(input.map(str::to_owned));
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((program.to_owned(), arguments.iter().map(|value| (*value).to_owned()).collect()));
        }
        if self.failing {
            return Err(PlatformError::RunnerFailed {
                program: program.to_owned(),
                reason: "no such program".to_owned(),
            });
        }
        Ok(self.stdout.clone())
    }
}

/// An absolute path on this platform.
///
/// `/tmp/a.txt` is absolute on one rung and a relative path with a weird name on another, and the guard is right to
/// refuse the second — so the fixture is built from the platform rather than written down, and what the test is about
/// stays the command.
fn absolute(name: &str) -> std::path::PathBuf {
    if cfg!(windows) {
        std::path::PathBuf::from(format!("C:\\synra\\{name}"))
    }
    else {
        std::path::PathBuf::from(format!("/tmp/{name}"))
    }
}

/// The recorder and a platform over it, with the two kept apart so both can be borrowed.
fn over_recorder(desktop: Desktop) -> (std::sync::Arc<Recorder>, CommandPlatform) {
    let recorder = std::sync::Arc::new(Recorder::default());
    (std::sync::Arc::clone(&recorder), CommandPlatform::with(desktop, Box::new(Shared(recorder))))
}

/// An `Arc<Recorder>` as a `CommandRunner`, so a test can keep the recorder and hand the platform a boxed copy.
struct Shared(std::sync::Arc<Recorder>);

impl CommandRunner for Shared {
    fn is_available(&self) -> bool {
        self.0.is_available()
    }
    fn run(
        &self,
        program: &str,
        arguments: &[&str],
        input: Option<&str>,
    ) -> Result<String, PlatformError> {
        self.0.run(program, arguments, input)
    }
}

/// A platform whose runner prints `stdout`.
fn over_printer(desktop: Desktop, stdout: &str) -> (std::sync::Arc<Recorder>, CommandPlatform) {
    let recorder = std::sync::Arc::new(Recorder::printing(stdout));
    (std::sync::Arc::clone(&recorder), CommandPlatform::with(desktop, Box::new(Shared(recorder))))
}

// ── The commands ──────────────────────────────────────────────────────────────────────────────────

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
fn a_clipboard_read_returns_what_the_program_printed() {
    let (recorder, platform) = over_printer(Desktop::MacOs, "the clipboard");
    assert_eq!(platform.read_clipboard().expect("read"), Some("the clipboard".to_owned()));
    assert_eq!(recorder.commands(), vec!["pbpaste".to_owned()]);

    let (_, platform) = over_recorder(Desktop::Linux);
    let _ = platform.read_clipboard().expect("read");
}

#[test]
fn a_clipboard_write_delivers_utf8_data_as_standard_input() {
    let (recorder, platform) = over_recorder(Desktop::MacOs);
    let text = "\"literal\"; $value\r\n中文🖱️";
    platform.write_clipboard(text).expect("write");
    assert_eq!(
        *recorder.input.lock().expect("input"),
        [Some(text.to_owned())]
    );
    assert_eq!(recorder.commands(), ["pbcopy"]);
}

#[test]
fn an_unavailable_runner_advertises_no_actions_and_never_runs_a_command() {
    struct Unavailable;
    impl CommandRunner for Unavailable {
        fn is_available(&self) -> bool {
            false
        }
        fn run(
            &self,
            _program: &str,
            _args: &[&str],
            _input: Option<&str>,
        ) -> Result<String, PlatformError> {
            panic!("an unavailable runner was called");
        }
    }
    let platform = CommandPlatform::with(Desktop::Linux, Box::new(Unavailable));
    assert!(platform.supported_actions().is_empty());
    assert!(matches!(
        platform.open_url("https://example.com"),
        Err(PlatformError::Unsupported(_))
    ));
    assert!(matches!(
        platform.read_clipboard(),
        Err(PlatformError::Unsupported(_))
    ));
    assert!(matches!(
        platform.write_clipboard("text"),
        Err(PlatformError::Unsupported(_))
    ));
}

#[test]
fn clipboard_writes_feed_each_desktop_without_interpolating_data() {
    let text = "\"literal\"; $value\r\n中文🖱️";
    for desktop in [Desktop::Linux, Desktop::MacOs, Desktop::Windows] {
        let (recorder, platform) = over_recorder(desktop);
        platform.write_clipboard(text).expect("written");
        assert_eq!(
            *recorder.input.lock().expect("input"),
            [Some(text.to_owned())]
        );
        assert!(
            !recorder.commands().join(" ").contains(text),
            "data entered the command line"
        );
        assert_eq!(recorder.count(), 1);
    }
}

#[test]
fn windows_clipboard_reads_nullable_json_without_losing_empty_text() {
    for value in [None, Some(""), Some("null"), Some("中文🖱️\\\"\r\n")] {
        let answer = serde_json::to_string(&value).expect("JSON");
        let (_, platform) = over_printer(Desktop::Windows, &answer);
        assert_eq!(platform.read_clipboard().expect("read").as_deref(), value);
    }
    let (_, platform) = over_printer(Desktop::Windows, "not JSON");
    assert!(matches!(
        platform.read_clipboard(),
        Err(PlatformError::RunnerFailed { .. })
    ));
}

#[test]
fn clipboard_limits_count_utf8_bytes_before_writes_and_after_reads() {
    let too_long = "选".repeat(MAX_CLIPBOARD_BYTES / 3 + 1);
    for desktop in [Desktop::Linux, Desktop::MacOs, Desktop::Windows] {
        let (recorder, platform) = over_recorder(desktop);
        assert!(matches!(
            platform.write_clipboard(&too_long),
            Err(PlatformError::TooLong { .. })
        ));
        assert_eq!(recorder.count(), 0);
        let answer = if desktop == Desktop::Windows {
            serde_json::to_string(&Some(&too_long)).expect("JSON")
        } else {
            too_long.clone()
        };
        let (_, platform) = over_printer(desktop, &answer);
        assert!(matches!(
            platform.read_clipboard(),
            Err(PlatformError::RunnerOutputTooLong { .. })
        ));
    }
    assert!(matches!(
        crate::HeadlessPlatform::new().write_clipboard(&too_long),
        Err(PlatformError::TooLong { .. })
    ));
    let at_limit = "x".repeat(MAX_CLIPBOARD_BYTES);
    assert!(check_clipboard_text(&at_limit).is_ok());
}

#[test]
fn a_program_that_is_not_installed_is_reported_rather_than_ignored() {
    let recorder = std::sync::Arc::new(Recorder::failing());
    let platform = CommandPlatform::with(Desktop::Linux, Box::new(Shared(std::sync::Arc::clone(&recorder))));
    match platform.open_url("https://example.com") {
        Err(PlatformError::RunnerFailed { program, reason }) => {
            assert_eq!(program, "xdg-open");
            assert!(!reason.is_empty());
        }
        other => panic!("expected a runner failure, got {other:?}"),
    }
    assert_eq!(recorder.count(), 1, "it tried");
}

// ── The rate limit ────────────────────────────────────────────────────────────────────────────────

#[test]
fn notifications_are_rate_limited_by_the_hour() {
    // A notification has no permission to check — it is user-visible, so the risk is being annoying rather than being
    // dangerous. The limit is what it has instead.
    let (recorder, platform) = over_recorder(Desktop::Linux);
    let policies = Policies::new().with_notifications_per_hour(2).with_notification_interval(Duration::ZERO);
    let platform = platform.with_policies(policies);

    platform.notify("one", "b").expect("first");
    platform.notify("two", "b").expect("second");
    // Either refusal is correct — the hourly count or the interval — and which one fires first is the limiter's
    // business rather than this test's.
    match platform.notify("three", "b") {
        Err(PlatformError::RateLimited { .. } | PlatformError::QuotaExceeded { .. }) => {}
        other => panic!("expected a limit, got {other:?}"),
    }
    assert_eq!(recorder.count(), 2, "the refused notification reached the runner");
}

#[test]
fn how_many_notifications_are_left_is_a_question_the_interface_asks() {
    let (_, platform) = over_recorder(Desktop::Linux);
    let policies = Policies::new().with_notifications_per_hour(5).with_notification_interval(Duration::ZERO);
    let platform = platform.with_policies(policies);
    let now = CommandPlatform::now_ms();
    assert_eq!(platform.notifications_remaining(now), 5, "nothing has been sent yet");

    platform.notify("one", "b").expect("first");
    assert_eq!(platform.notifications_remaining(CommandPlatform::now_ms()), 4);
}

// ── What the interface is told ────────────────────────────────────────────────────────────────────

#[test]
fn the_supported_actions_are_the_ones_a_menu_can_offer() {
    // ★ The list an interface draws from. A menu item that is never available is worse than one that explains why it
    // is not, so the list is the *askable* set rather than the implemented one.
    let (_, platform) = over_recorder(Desktop::MacOs);
    let actions = platform.supported_actions();
    assert!(actions.contains(&PlatformAction::OpenUrl));
    assert!(actions.contains(&PlatformAction::Notify));
    assert!(actions.contains(&PlatformAction::WriteClipboard));
    assert!(!actions.contains(&PlatformAction::SimulateKeys), "it is off by default");

    // With the policy on, it is offered.
    let platform = platform.with_policies(Policies::new().with_simulate_keys(true));
    assert!(platform.supported_actions().contains(&PlatformAction::SimulateKeys));

    let (_, platform) = over_recorder(Desktop::Linux);
    assert!(
        platform
            .supported_actions()
            .contains(&PlatformAction::WriteClipboard)
    );
}

#[test]
fn the_name_says_which_desktop_decides_the_programs() {
    for (desktop, name) in [
        (Desktop::Linux, "desktop-linux"),
        (Desktop::MacOs, "desktop-macos"),
        (Desktop::Windows, "desktop-windows"),
    ] {
        let (_, platform) = over_recorder(desktop);
        assert_eq!(platform.name(), name);
        assert_eq!(platform.desktop(), desktop);
    }
    // And the headless host is still its own name, so a health screen can tell the two apart.
    assert_eq!(crate::host::HeadlessPlatform::new().name(), "headless");
}

#[test]
fn the_platform_this_build_runs_on_is_the_one_it_was_compiled_for() {
    // The `cfg` is in `current` and nowhere else, so everything decided from it is ordinary code a test drives.
    let current = Desktop::current();
    #[cfg(target_os = "windows")]
    assert_eq!(current, Desktop::Windows);
    #[cfg(target_os = "macos")]
    assert_eq!(current, Desktop::MacOs);
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    assert_eq!(current, Desktop::Linux);
    assert!(!current.as_str().is_empty());
    assert!(!current.opener().is_empty());
}

#[test]
fn the_default_platform_is_the_one_this_build_runs_on_with_a_direct_runner() {
    let platform = CommandPlatform::default();
    assert_eq!(platform.desktop(), Desktop::current());
    assert!(!platform.policies().allows_simulate_keys(), "off by default");
}

#[test]
fn the_policies_a_platform_was_given_are_the_ones_it_enforces() {
    // The limiter is rebuilt from them, because the interval and the hourly count are what it enforces: a limiter left
    // over from the old policies would enforce the ones nobody chose.
    let (_, platform) = over_recorder(Desktop::Linux);
    let strict = Policies::new().with_notifications_per_hour(1).with_notification_interval(Duration::from_secs(3_600));
    let platform = platform.with_policies(strict);
    assert_eq!(platform.policies().notifications_per_hour(), 1);

    platform.notify("one", "b").expect("first");
    match platform.notify("two", "b") {
        // Either refusal is correct — the hourly count or the interval — and which one fires first is the limiter's
        // business rather than this test's.
        Err(PlatformError::RateLimited { .. } | PlatformError::QuotaExceeded { .. }) => {}
        other => panic!("expected a limit, got {other:?}"),
    }
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
