use crate::host::Platform;
use crate::PlatformError;

use super::super::{CommandPlatform, CommandRunner, Desktop};
use super::{Recorder, Shared};

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
