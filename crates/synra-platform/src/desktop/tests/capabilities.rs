use std::time::Duration;

use crate::host::Platform;
use crate::{PlatformAction, PlatformError, Policies};

use super::super::{CommandPlatform, Desktop};
use super::over_recorder;

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
