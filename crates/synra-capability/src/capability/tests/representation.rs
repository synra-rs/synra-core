use super::*;

#[test]
fn every_capability_has_a_human_description() {
    // The consent prompt must not show a user a DSL string: a user who cannot read
    // `network:fetch:api.github.com:POST` is being asked to approve something they cannot
    // evaluate.
    for text in [
        "log:debug",
        "network:fetch:api.github.com",
        "network:fetch:*",
        "fs:read:/data/**",
        "device:send:@synra-pc",
        "device:list",
        "platform:open-url",
        "platform:read-clipboard",
        "storage:local:read",
        "file:transfer:send",
        "event:emit:_plugin.@acme/chat.*",
        "ui:page",
    ] {
        let capability = Capability::parse(text).expect("valid");
        let description = capability.describe();
        assert!(!description.is_empty(), "{text}");
        // No glob: a user reading a wildcard has been shown the mechanism rather than the answer,
        // and the wildcard is the part that decides how much is being asked for.
        assert!(!description.contains('*'), "{text} -> {description}");
        // No DSL punctuation, so the prompt cannot be mistaken for a capability string.
        for punctuation in [':', '{', '}'] {
            assert!(
                !description.contains(punctuation),
                "{text} -> {description} contains {punctuation}",
            );
        }
    }

    // A wildcard grant reads as unlimited, in words.
    let any_host = Capability::parse("network:fetch:**").expect("valid");
    assert!(any_host.describe().contains("any website"), "{}", any_host.describe());
}

#[test]
fn display_and_parse_round_trip() {
    for text in ["log:debug", "network:fetch:api.github.com:POST", "fs:read:/data/**"] {
        let capability = Capability::parse(text).expect("valid");
        assert_eq!(capability.to_string(), text);
        assert_eq!(Capability::parse(&capability.to_string()).expect("re-parses"), capability);
    }

    assert!(Capability::parse(&Capability::parse("ui:page").expect("valid").to_string()).is_ok());
}

#[test]
fn the_legacy_clipboard_spelling_is_recognised_and_corrected() {
    // ★ The boundary correction, not a second name in the matcher. The generated contract has always required
    // `platform:read-clipboard`; the documentation used the nested spelling, so a manifest written from it declared a
    // permission the gate never checked. `canonical_spelling` is what the manifest reader and the store migration use to
    // turn one into the other — and a capability that is already canonical is left alone.
    assert_eq!(crate::canonical_spelling("platform:clipboard:read"), Some("platform:read-clipboard"));
    assert_eq!(crate::canonical_spelling("platform:clipboard:write"), Some("platform:write-clipboard"));
    assert_eq!(crate::canonical_spelling("platform:read-clipboard"), None);
    assert_eq!(crate::canonical_spelling("platform:write-clipboard"), None);
    assert_eq!(crate::canonical_spelling("platform:open-url"), None);
    assert_eq!(crate::canonical_spelling("log:*"), None);
}

#[test]
fn scoped_wildcard_qualifiers_keep_their_position() {
    for (pattern, allowed, denied) in [
        (
            "network:fetch:api.github.com:*",
            "network:fetch:api.github.com:POST",
            "network:fetch:other.example:POST",
        ),
        (
            "network:fetch:api.github.com:**",
            "network:fetch:api.github.com:GET",
            "network:fetch:other.example:api.github.com",
        ),
        (
            "action:invoke:@acme/formatter:*",
            "action:invoke:@acme/formatter:format",
            "action:invoke:@acme/other:format",
        ),
    ] {
        let pattern = Capability::parse(pattern).unwrap();
        assert!(
            pattern.matches(&Capability::parse(allowed).unwrap()),
            "{pattern}"
        );
        assert!(
            !pattern.matches(&Capability::parse(denied).unwrap()),
            "{pattern}"
        );
    }
}
