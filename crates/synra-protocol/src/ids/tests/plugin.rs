use super::super::{IdError, MAX_PLUGIN_ID_LEN, MAX_PLUGIN_SLUG_LEN, PluginId, PluginSlug};

#[test]
fn plugin_id_requires_a_scope() {
    assert_eq!(PluginId::parse("chat"), Err(IdError::Unscoped));
    assert_eq!(PluginId::parse("@synra-plugin"), Err(IdError::Unscoped));
    assert_eq!(PluginId::parse("@synra-plugin/"), Err(IdError::Unscoped));
    assert_eq!(PluginId::parse("@/chat"), Err(IdError::Unscoped));
    // A second slash is outside the grammar.
    assert_eq!(PluginId::parse("@a/b/c"), Err(IdError::Unscoped));
}

#[test]
fn plugin_id_splits_into_scope_and_name() {
    let id = PluginId::parse("@synra-plugin/github-bridge").expect("valid");
    assert_eq!(id.scope(), "synra-plugin");
    assert_eq!(id.name(), "github-bridge");
    assert_eq!(id.as_str(), "@synra-plugin/github-bridge");
}

#[test]
fn plugin_id_rejects_bad_characters() {
    assert!(matches!(
        PluginId::parse("@Synra/chat"),
        Err(IdError::InvalidCharacter { ch: 'S', .. })
    ));
    assert!(matches!(
        PluginId::parse("@synra/chat_bot"),
        Err(IdError::InvalidCharacter { ch: '_', .. })
    ));
    // A leading hyphen is not a valid start.
    assert!(matches!(
        PluginId::parse("@synra/-chat"),
        Err(IdError::InvalidCharacter { ch: '-', .. })
    ));
}

#[test]
fn plugin_id_points_at_the_offending_character() {
    // The offset must be into the whole string, or an error message sends the reader to the
    // wrong place. `@ok/baD`: `@`=0 `o`=1 `k`=2 `/`=3 `b`=4 `a`=5 `D`=6.
    let err = PluginId::parse("@ok/baD").expect_err("invalid");
    assert_eq!(err, IdError::InvalidCharacter { ch: 'D', index: 6 });

    // And in the scope half.
    let err = PluginId::parse("@oK/chat").expect_err("invalid");
    assert_eq!(err, IdError::InvalidCharacter { ch: 'K', index: 2 });
}

#[test]
fn plugin_id_enforces_length() {
    let long = format!("@{}", "a".repeat(MAX_PLUGIN_ID_LEN));
    assert!(matches!(PluginId::parse(&long), Err(IdError::TooLong { .. })));
}

#[test]
fn event_namespaces_preserve_the_full_package_identity() {
    for (id, namespace) in [
        ("@synra-plugin/chat", "_plugin.@synra-plugin/chat."),
        (
            "@imba97/synra-plugin-notes",
            "_plugin.@imba97/synra-plugin-notes.",
        ),
        ("@acme/chat", "_plugin.@acme/chat."),
        ("@other/chat", "_plugin.@other/chat."),
        (
            "@acme/synra-plugin-chat",
            "_plugin.@acme/synra-plugin-chat.",
        ),
    ] {
        assert_eq!(
            PluginId::parse(id).expect("valid").event_namespace(),
            namespace
        );
    }
}

#[test]
fn plugin_slug_validation() {
    assert!(PluginSlug::parse("chat").is_ok());
    assert!(PluginSlug::parse("chat-2").is_ok());
    assert!(PluginSlug::parse("2chat").is_ok());

    assert_eq!(PluginSlug::parse(""), Err(IdError::Empty));
    assert!(matches!(
        PluginSlug::parse("-chat"),
        Err(IdError::InvalidCharacter { ch: '-', .. })
    ));
    assert!(matches!(
        PluginSlug::parse("chat-"),
        Err(IdError::InvalidCharacter { ch: '-', .. })
    ));
    assert!(matches!(
        PluginSlug::parse("Chat"),
        Err(IdError::InvalidCharacter { ch: 'C', .. })
    ));
    assert!(matches!(
        PluginSlug::parse("a".repeat(MAX_PLUGIN_SLUG_LEN + 1).as_str()),
        Err(IdError::TooLong { .. })
    ));
}

#[test]
fn plugin_id_and_slug_round_trip_through_json() {
    let id = PluginId::parse("@synra-plugin/chat").expect("valid");
    let json = serde_json::to_string(&id).expect("serialises");
    assert_eq!(json, "\"@synra-plugin/chat\"");
    let back: PluginId = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, id);

    // An invalid id must not deserialise: validation happens on the way in, so a value of this
    // type is always well-formed.
    assert!(serde_json::from_str::<PluginId>("\"chat\"").is_err());
}
