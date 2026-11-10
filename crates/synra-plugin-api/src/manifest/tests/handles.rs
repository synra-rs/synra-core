use super::super::error::ManifestError;
use super::super::types::{Manifest, ManifestContext};
use super::{MINIMAL, minimal, parse};

/// The minimal manifest with the given `handles` entries.
fn with_handles(entries: &str) -> Manifest {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        &format!("\"capabilities\": [{{ \"cap\": \"log:*\" }}], \"handles\": [{entries}]"),
    );
    parse(&text)
}

#[test]
fn a_known_host_event_may_be_handled() {
    for event in [
        "_synra.transfer.completed",
        "_synra.device.changed",
        "_synra.share.received",
    ] {
        let manifest = with_handles(&format!("{{ \"event\": \"{event}\" }}"));
        assert_eq!(
            manifest.validate(&ManifestContext::default()),
            Ok(()),
            "{event}"
        );
    }
}

#[test]
fn a_plugin_may_handle_its_own_declared_event() {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.text\" }], \
             \"handles\": [{ \"event\": \"_plugin.@synra-plugin/chat.text\" }]",
    );
    assert_eq!(parse(&text).validate(&ManifestContext::default()), Ok(()));
}

#[test]
fn a_wildcard_handle_is_accepted_by_its_grammar() {
    for pattern in [
        "_plugin.@synra-plugin/chat.*",
        "_synra.*",
        "_synra.device.*",
    ] {
        let manifest = with_handles(&format!("{{ \"event\": \"{pattern}\" }}"));
        assert_eq!(
            manifest.validate(&ManifestContext::default()),
            Ok(()),
            "{pattern}"
        );
    }
}

#[test]
fn a_handle_that_can_never_fire_is_refused() {
    // A plugin that silently never receives anything is the hardest kind of bug to find.
    for entry in ["", "nonsense", "not-an-event", "_unknown.thing"] {
        let manifest = with_handles(&format!("{{ \"event\": \"{entry}\" }}"));
        assert!(
            matches!(
                manifest.validate(&ManifestContext::default()),
                Err(ManifestError::BadHandle { .. })
            ),
            "{entry:?} should be refused"
        );
    }
}

#[test]
fn a_handle_may_carry_a_condition() {
    let manifest = with_handles(
        "{ \"event\": \"_synra.transfer.completed\", \"match\": { \"kind\": \"attachment\" } }",
    );
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
}

#[test]
fn event_routes_do_not_claim_to_prove_binary_entry_points() {
    let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
    assert_eq!(minimal().validate(&ManifestContext::default()), Ok(()));
}
