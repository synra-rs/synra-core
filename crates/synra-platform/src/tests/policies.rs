use core::time::Duration;
use super::super::actions::{PlatformAction, Policies};

#[test]
fn the_defaults_are_the_restrictive_ones() {
    // A host that wants to be permissive has to say so, which is the opposite of a configuration whose
    // defaults quietly allow whatever was added last.
    let policies = Policies::new();
    assert!(!policies.allows_insecure_urls());
    assert!(!policies.allows_simulate_keys());
    assert!(policies.restricts_reveal_to_sandbox());
    assert_eq!(policies.notifications_per_hour(), 20);
    assert!(policies.foreground_window() > Duration::ZERO);
    assert!(policies.key_chord_interval() > Duration::ZERO);
    assert!(policies.notification_interval() > Duration::ZERO);
}

#[test]
fn a_policy_describes_what_a_grant_would_allow() {
    // Composed from the policy rather than written per action, so a policy change cannot leave the prompt
    // describing something the host no longer does.
    let strict = Policies::new();
    let open = Policies::new()
        .with_insecure_urls(true)
        .with_simulate_keys(true)
        .with_reveal_outside_sandbox(true);

    assert!(strict.describe(PlatformAction::OpenUrl).contains("https"));
    assert!(!open.describe(PlatformAction::OpenUrl).contains("https only"));

    assert!(strict.describe(PlatformAction::SimulateKeys).contains("turned off"));
    assert!(!open.describe(PlatformAction::SimulateKeys).contains("turned off"));

    assert!(strict.describe(PlatformAction::RevealPath).contains("own data directory"));
    assert!(!open.describe(PlatformAction::RevealPath).contains("own data directory"));

    // Every action has a description under both policies, so the screen has something to render.
    for action in [
        PlatformAction::OpenUrl,
        PlatformAction::OpenPath,
        PlatformAction::RevealPath,
        PlatformAction::SimulateKeys,
        PlatformAction::ReadClipboard,
        PlatformAction::WriteClipboard,
        PlatformAction::Notify,
    ] {
        assert!(!strict.describe(action).is_empty(), "{action}");
        assert!(!open.describe(action).is_empty(), "{action}");
    }
}

#[test]
fn the_builders_are_chainable() {
    let policies = Policies::new()
        .with_insecure_urls(true)
        .with_local_schemes(true)
        .with_simulate_keys(true)
        .with_foreground_requirement(false)
        .with_foreground_window(Duration::from_secs(5))
        .with_key_chord_interval(Duration::from_millis(10))
        .with_notification_interval(Duration::from_secs(1))
        .with_notifications_per_hour(5)
        .with_reveal_outside_sandbox(true);

    assert!(policies.allows_insecure_urls());
    assert!(policies.allows_simulate_keys());
    assert!(!policies.restricts_reveal_to_sandbox());
    assert_eq!(policies.foreground_window(), Duration::from_secs(5));
    assert_eq!(policies.key_chord_interval(), Duration::from_millis(10));
    assert_eq!(policies.notifications_per_hour(), 5);
}
