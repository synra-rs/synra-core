use super::super::actions::PlatformAction;

#[test]
fn every_action_has_its_own_capability() {
    // An authorisation that covered "the platform" would be one a user granted for a different reason. Each
    // action names exactly one effect, and none implies another.
    let actions = [
        PlatformAction::OpenUrl,
        PlatformAction::OpenPath,
        PlatformAction::RevealPath,
        PlatformAction::SimulateKeys,
        PlatformAction::ReadClipboard,
        PlatformAction::WriteClipboard,
        PlatformAction::Notify,
    ];
    let mut capabilities = std::collections::HashSet::new();
    for action in actions {
        let capability = action.capability();
        assert!(capabilities.insert(capability), "{capability} is shared");
        assert!(capability.starts_with("platform:"), "{capability}");
    }
    // Reading and writing the clipboard are separate grants.
    assert_ne!(
        PlatformAction::ReadClipboard.capability(),
        PlatformAction::WriteClipboard.capability()
    );
    // And opening a file is not opening a URL: the first can run a program.
    assert_ne!(PlatformAction::OpenUrl.capability(), PlatformAction::OpenPath.capability());
}

#[test]
fn only_simulating_keys_is_off_by_default() {
    // It is the one action that lets a plugin drive other applications, and the design document requires it to
    // be a separate, default-off authorisation.
    for action in [
        PlatformAction::OpenUrl,
        PlatformAction::OpenPath,
        PlatformAction::RevealPath,
        PlatformAction::ReadClipboard,
        PlatformAction::WriteClipboard,
        PlatformAction::Notify,
    ] {
        assert!(!action.is_off_by_default(), "{action}");
    }
    assert!(PlatformAction::SimulateKeys.is_off_by_default());
}

#[test]
fn the_silent_actions_are_the_ones_needing_an_indicator() {
    // A browser window announces itself. Reading the clipboard and typing do not, which is why they need
    // something else.
    assert!(PlatformAction::SimulateKeys.needs_visible_indicator());
    assert!(PlatformAction::ReadClipboard.needs_visible_indicator());
    assert!(!PlatformAction::WriteClipboard.needs_visible_indicator());
    assert!(!PlatformAction::Notify.needs_visible_indicator());
    // And the visible ones do not need an extra indicator, because they are their own.
    assert!(PlatformAction::OpenUrl.is_user_visible());
    assert!(!PlatformAction::SimulateKeys.is_user_visible());
}

#[test]
fn every_action_names_its_risk() {
    // The consent screen is where a user decides, so a variant without a sentence is one the interface cannot
    // render.
    for action in [
        PlatformAction::OpenUrl,
        PlatformAction::OpenPath,
        PlatformAction::RevealPath,
        PlatformAction::SimulateKeys,
        PlatformAction::ReadClipboard,
        PlatformAction::WriteClipboard,
        PlatformAction::Notify,
    ] {
        let risk = action.risk();
        assert!(risk.len() > 20, "{action} -> {risk}");
    }
}

#[test]
fn action_capabilities_parse_as_capabilities() {
    // The names have to be ones the capability DSL accepts, or a manifest cannot request them.
    for action in [
        PlatformAction::OpenUrl,
        PlatformAction::OpenPath,
        PlatformAction::RevealPath,
        PlatformAction::SimulateKeys,
        PlatformAction::ReadClipboard,
        PlatformAction::WriteClipboard,
        PlatformAction::Notify,
    ] {
        // `synra-capability` is not a dependency here, so the check is the character set its grammar allows,
        // taken from the same constant: `[A-Za-z0-9._@/*-]` per segment, with a `:` between segments.
        let capability = action.capability();
        let (domain, rest) = capability.split_once(':').expect("has a domain");
        assert_eq!(domain, "platform");
        assert!(!rest.is_empty());
        for segment in rest.split(':') {
            assert!(!segment.is_empty(), "{capability}");
            assert!(
                segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '/' | '*' | '-')),
                "{capability}: segment {segment:?} has a character outside the grammar"
            );
        }
    }
}

#[test]
fn an_action_displays_its_capability() {
    assert_eq!(PlatformAction::OpenUrl.to_string(), "platform:open-url");
}
