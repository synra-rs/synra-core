//! Actual child-process tests. The test executable provides a controlled subprocess entry point.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{CommandRunner, Gate, MAX_ARGUMENTS, MAX_ERROR_OUTPUT, MAX_OUTPUT, SystemRunner};
use crate::{MAX_CLIPBOARD_BYTES, PlatformError};

const ENTRY: &str = "desktop::runner::tests::child_process_entry";
const MARKER: &str = "<synra-input>";

fn local(timeout: Duration) -> SystemRunner {
    SystemRunner {
        timeout,
        gate: Arc::new(Gate::new(1)),
    }
}

fn args(mode: &str, pid_file: Option<&std::path::Path>) -> Vec<String> {
    let mut args = vec![
        "--exact".to_owned(),
        ENTRY.to_owned(),
        "--nocapture".to_owned(),
        "--test-threads=1".to_owned(),
        "--skip".to_owned(),
        format!("__synra_mode={mode}"),
    ];
    if let Some(path) = pid_file {
        args.extend([
            "--skip".to_owned(),
            format!("__synra_pid_file={}", path.display()),
        ]);
    }
    args
}

fn child(
    runner: &SystemRunner,
    mode: &str,
    input: Option<&str>,
    pid_file: Option<&std::path::Path>,
) -> Result<String, PlatformError> {
    let exe = std::env::current_exe().expect("test executable");
    let args = args(mode, pid_file);
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    runner.run(exe.to_str().expect("UTF-8 executable path"), &args, input)
}

fn wait_until_clean(runner: &SystemRunner) {
    let until = Instant::now() + Duration::from_secs(5);
    while runner.active_commands() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(runner.active_commands(), 0);
    assert_eq!(runner.pending_cleanup(), 0);
}

#[test]
fn actual_processes_preserve_input_refuse_excess_output_and_clean_up_timeouts() {
    let runner = local(Duration::from_secs(5));
    for input in [None, Some(""), Some("\"literal\"; $secret\r\n中文🖱️\\")] {
        let output = child(&runner, "echo", input, None).expect("echo");
        assert_eq!(
            output.split_once(MARKER).map(|(_, text)| text),
            Some(input.unwrap_or_default())
        );
        wait_until_clean(&runner);
    }
    for (mode, stream, limit) in [
        ("stdout", "stdout", MAX_OUTPUT),
        ("stderr", "stderr", MAX_ERROR_OUTPUT),
    ] {
        let error = child(&runner, mode, None, None).expect_err("output ceiling");
        assert!(
            matches!(error, PlatformError::RunnerOutputTooLong { stream: actual, max, .. } if actual == stream && max == limit),
            "{error:?}"
        );
        wait_until_clean(&runner);
    }
    let error = child(&runner, "invalid-utf8", None, None).expect_err("UTF-8 refusal");
    assert!(matches!(error, PlatformError::RunnerFailed { .. }));
    let error = child(&runner, "fail", None, None).expect_err("exit failure");
    assert!(matches!(error, PlatformError::RunnerFailed { .. }));
    assert!(!error.to_string().contains("sensitive-clipboard-content"));
    wait_until_clean(&runner);

    let root = tempfile::tempdir().expect("owned temporary directory");
    let pid_file = root.path().join("pid");
    let runner = runner.with_timeout(Duration::from_millis(500));
    let before = Instant::now();
    let input = "x".repeat(MAX_CLIPBOARD_BYTES);
    let error =
        child(&runner, "hang", Some(&input), Some(&pid_file)).expect_err("blocked stdin deadline");
    assert!(
        matches!(error, PlatformError::RunnerTimedOut { .. }),
        "{error:?}"
    );
    assert!(before.elapsed() < Duration::from_secs(3));
    wait_until_clean(&runner);
    let pid: u32 = std::fs::read_to_string(&pid_file)
        .expect("child started")
        .parse()
        .expect("pid");
    assert_process_gone(pid);
}

#[test]
fn inherited_pipes_retain_admission_until_their_workers_finish() {
    let runner = local(Duration::from_millis(500));
    let error = child(&runner, "inherit", None, None).expect_err("inherited pipe deadline");
    assert!(
        matches!(
            error,
            PlatformError::RunnerTimedOut {
                cleanup_pending: true,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(runner.active_commands(), 1);
    assert_eq!(runner.pending_cleanup(), 1);
    assert!(matches!(
        child(&runner, "echo", None, None),
        Err(PlatformError::RunnerBusy { limit: 1 })
    ));
    wait_until_clean(&runner);
    assert!(
        child(&runner, "echo", None, None)
            .expect("slot recovered")
            .ends_with(MARKER)
    );
    wait_until_clean(&runner);
}

#[test]
fn admission_is_shared_and_input_limits_precede_process_launch() {
    let runner = local(Duration::from_secs(1));
    let clone = runner.clone();
    let lease = runner.gate.acquire().expect("first slot");
    assert!(matches!(
        clone.run("not-a-command", &[], None),
        Err(PlatformError::RunnerBusy { limit: 1 })
    ));
    drop(lease);
    assert_eq!(clone.active_commands(), 0);
    let input = "选".repeat(MAX_CLIPBOARD_BYTES / 3 + 1);
    assert!(matches!(
        runner.run("not-a-command", &[], Some(&input)),
        Err(PlatformError::TooLong { .. })
    ));
    assert!(matches!(
        runner.run("not-a-command", &vec!["arg"; MAX_ARGUMENTS + 1], None),
        Err(PlatformError::TooLong { .. })
    ));
    assert!(matches!(
        runner
            .clone()
            .with_timeout(Duration::ZERO)
            .run("not-a-command", &[], None),
        Err(PlatformError::RunnerTimedOut { .. })
    ));
    assert_eq!(runner.active_commands(), 0);
    assert_eq!(
        runner.with_timeout(Duration::MAX).timeout,
        super::DEFAULT_TIMEOUT
    );
    let default = SystemRunner::default();
    assert!(Arc::ptr_eq(&default.gate, &SystemRunner::default().gate));
}

#[test]
fn retained_processes_are_reaped_and_release_their_reserved_job_slot() {
    let runner = local(Duration::from_secs(5));
    let lease = runner.gate.acquire().expect("reserved slot");
    let mut command = Command::new(std::env::current_exe().expect("self"));
    command
        .args(args("hold", None))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    // Ownership is transferred to Gate::reap, which performs the wait without holding its mutex.
    #[allow(clippy::zombie_processes)]
    let child = command.spawn().expect("retained child");
    runner.gate.retain(child, &lease);
    lease.retire();
    drop(lease);
    assert!(format!("{runner:?}").contains("unreaped: 1"));
    assert_eq!(runner.active_commands(), 1);
    assert_eq!(runner.pending_cleanup(), 1);
    wait_until_clean(&runner);
}

// This ordinary test returns immediately in the parent. A selected self-invocation uses only
// test-harness --skip values for its fixture mode, so no custom binary or external interpreter is needed.
#[test]
fn child_process_entry() {
    let Some(mode) =
        std::env::args().find_map(|arg| arg.strip_prefix("__synra_mode=").map(str::to_owned))
    else {
        return;
    };
    if let Some(path) =
        std::env::args().find_map(|arg| arg.strip_prefix("__synra_pid_file=").map(str::to_owned))
    {
        std::fs::write(path, std::process::id().to_string()).expect("fixture pid");
    }
    match mode.as_str() {
        "echo" => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).expect("stdin");
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(MARKER.as_bytes()).expect("marker");
            stdout.write_all(&input).expect("echo");
            stdout.flush().expect("flush");
        }
        "stdout" => {
            let _ = std::io::stdout().write_all(&vec![b'x'; MAX_OUTPUT + 1]);
        }
        "stderr" => {
            let _ = std::io::stderr().write_all(&vec![b'x'; MAX_ERROR_OUTPUT + 1]);
        }
        "invalid-utf8" => {
            let _ = std::io::stdout().write_all(&[0xff]);
        }
        "fail" => {
            let _ = std::io::stderr().write_all(b"sensitive-clipboard-content");
            std::process::exit(23);
        }
        "hang" => loop {
            std::thread::park();
        },
        "inherit" => {
            let mut command = Command::new(std::env::current_exe().expect("self"));
            command
                .args(args("hold", None))
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt as _;
                command.creation_flags(0x0800_0000);
            }
            // The parent must exit while the descendant holds its pipes. Waiting here removes the regression fixture.
            #[allow(clippy::zombie_processes)]
            let _descendant = command.spawn().expect("controlled short-lived descendant");
        }
        "hold" => std::thread::sleep(Duration::from_millis(1600)),
        _ => panic!("unknown fixture mode"),
    }
    std::process::exit(0);
}

fn assert_process_gone(pid: u32) {
    let runner = SystemRunner::default();
    #[cfg(windows)]
    {
        let script = format!(
            "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 9 }}; [Console]::Write('gone')"
        );
        assert_eq!(
            runner
                .run(
                    "powershell",
                    &["-NoProfile", "-NonInteractive", "-Command", &script],
                    None
                )
                .expect("query process"),
            "gone"
        );
    }
    #[cfg(not(windows))]
    assert!(
        runner
            .run("/bin/kill", &["-0", &pid.to_string()], None)
            .is_err()
    );
}
