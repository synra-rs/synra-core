use synra_platform::PlatformAction;
use super::super::host_requirement;
use super::capability;

#[test]
fn every_platform_capability_maps_to_a_host_action() {
    // Keeping the mapping in one function means a new capability cannot be added without deciding whether it needs
    // a host action — and a capability that needed one and had none would be admitted on a host that cannot do it.
    let expected = [
        ("platform:open-url", PlatformAction::OpenUrl),
        ("platform:open-path", PlatformAction::OpenPath),
        ("platform:reveal-path", PlatformAction::RevealPath),
        ("platform:simulate-keys", PlatformAction::SimulateKeys),
        ("platform:read-clipboard", PlatformAction::ReadClipboard),
        ("platform:write-clipboard", PlatformAction::WriteClipboard),
        ("platform:notify", PlatformAction::Notify),
    ];
    for (text, action) in expected {
        assert_eq!(host_requirement(&capability(text)), Some(action), "{text}");
    }
}

#[test]
fn a_non_platform_capability_needs_no_host_action() {
    // A device send or a filesystem read is not something the operating system has to be asked about, and reporting
    // one would refuse the call on a host with no platform actions at all.
    for text in [
        "device:send:peer",
        "storage:local:read",
        "network:fetch:api.example.com",
        "log:*",
    ] {
        assert_eq!(host_requirement(&capability(text)), None, "{text}");
    }
}

#[test]
fn a_platform_capability_with_no_action_is_not_a_host_requirement() {
    // `platform:*` is a grant over the domain with no specific action, so there is nothing for the host to be
    // asked about. It is still a capability the plugin must hold, which step 5 covers.
    assert_eq!(host_requirement(&capability("platform:*")), None);
    // A platform resource with no action this host knows: still a capability, still nothing to ask the OS about.
    assert_eq!(host_requirement(&capability("platform:unknown")), None);
}
