use synra_protocol::PluginId;
use super::super::error::ManifestError;
use super::super::types::{Manifest, ManifestContext};
use super::{MINIMAL, parse};

/// The minimal manifest with one event declared.
fn with_event(name: &str) -> Manifest {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        &format!(
            "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"{name}\", \
                 \"payload\": {{ \"type\": \"object\", \"properties\": {{}}, \
                 \"additionalProperties\": false }} }}]"
        ),
    );
    parse(&text)
}

#[test]
fn publishers_and_conventional_prefixes_do_not_alias_manifest_event_owners() {
    let mut manifest = with_event("_plugin.@synra-plugin/chat.text");
    assert!(manifest.validate(&ManifestContext::default()).is_ok());
    for id in ["@other/chat", "@synra-plugin/synra-plugin-chat"] {
        manifest.id = PluginId::parse(id).unwrap();
        assert!(matches!(
            manifest.validate(&ManifestContext::default()),
            Err(ManifestError::ForeignEventNamespace { .. })
        ));
    }
}

#[test]
fn malformed_owned_events_are_not_valid_declarations() {
    for name in [
        "_plugin.@synra-plugin/chat.a b",
        "_plugin.@synra-plugin/chat.a..b",
        "_plugin.@synra-plugin/chat.*",
    ] {
        assert!(
            matches!(
                with_event(name).validate(&ManifestContext::default()),
                Err(ManifestError::BadEventName { .. })
            ),
            "{name}"
        );
    }
    let long = format!("_plugin.@synra-plugin/chat.{}", "x".repeat(240));
    assert!(matches!(
        with_event(&long).validate(&ManifestContext::default()),
        Err(ManifestError::BadEventName { .. })
    ));
}

#[test]
fn event_identity_does_not_require_a_short_project_directory_name() {
    let mut manifest = parse(MINIMAL);
    manifest.id = PluginId::parse("@acme/synra-plugin-").unwrap();
    assert!(manifest.project_slug().is_err());
    assert_eq!(manifest.event_namespace(), "_plugin.@acme/synra-plugin-.");
    assert!(manifest.validate(&ManifestContext::default()).is_ok());
}

#[test]
fn an_event_in_the_plugins_own_namespace_is_accepted() {
    let manifest = with_event("_plugin.@synra-plugin/chat.text");
    assert_eq!(manifest.event_namespace(), "_plugin.@synra-plugin/chat.");
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
}

#[test]
fn an_event_in_another_plugins_namespace_is_refused() {
    // The check that stops one plugin emitting under another's name, which a receiving side would route as
    // a legitimate message with nothing in any log to say otherwise.
    let manifest = with_event("_plugin.@synra-plugin/notes.text");
    match manifest.validate(&ManifestContext::default()) {
        Err(ManifestError::ForeignEventNamespace { name, namespace }) => {
            assert_eq!(name, "_plugin.@synra-plugin/notes.text");
            assert_eq!(namespace, "_plugin.@synra-plugin/chat.");
        }
        other => panic!("expected a namespace refusal, got {other:?}"),
    }
}

#[test]
fn an_event_outside_any_plugin_namespace_is_refused() {
    for name in ["_synra.device.changed", "device.ping", "chat.text"] {
        let manifest = with_event(name);
        assert!(
            manifest.validate(&ManifestContext::default()).is_err(),
            "{name} should be refused"
        );
    }
}

#[test]
fn the_namespace_prefix_alone_is_not_an_event() {
    // `_plugin.@synra-plugin/chat.` names nothing, and accepting it would make an event whose logical name is empty.
    let manifest = with_event("_plugin.@synra-plugin/chat.");
    assert!(manifest.validate(&ManifestContext::default()).is_err());
}

#[test]
fn a_duplicate_event_name_is_refused() {
    let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [\
             { \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": { \"type\": \"object\" } }, \
             { \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": { \"type\": \"object\" } }]",
        );
    let manifest = parse(&text);
    assert!(matches!(
        manifest.validate(&ManifestContext::default()),
        Err(ManifestError::DuplicateName { kind: "event", .. })
    ));
}

#[test]
fn an_event_may_declare_no_payload() {
    // An event that is only a notification has nothing to carry, and requiring a schema would make authors
    // write `{"type":"object","properties":{}}` to say nothing.
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.ping\" }]",
    );
    assert_eq!(parse(&text).validate(&ManifestContext::default()), Ok(()));
}
