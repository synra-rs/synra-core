//! The desktop platform, driven with a runner that records rather than launches.
//!
//! Every test here is about *order*: the policy check happens before the runner is reached, so a refusal that still ran
//! a program would be a refusal that opened a window. The stub records, and the assertions are on what it saw.

use std::sync::Mutex;

use crate::PlatformError;

use super::{CommandPlatform, CommandRunner, Desktop};

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

mod actions;
mod clipboard;
mod runner;
mod notifications;
mod capabilities;
