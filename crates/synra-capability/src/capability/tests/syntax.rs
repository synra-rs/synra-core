use super::*;

#[test]
fn real_capabilities_parse() {
    // Every form the design document lists, so a change to the grammar cannot quietly stop
    // accepting one of them.
    for text in [
        "log:*",
        "log:debug",
        "event:emit:_plugin.@acme/chat.*",
        "event:subscribe:_synra.device.*",
        "device:list",
        "device:send:@synra-pc",
        "device:broadcast",
        "storage:local:read",
        "storage:local:write",
        "storage:secure:read",
        "network:fetch:api.github.com",
        "network:fetch:api.x.com:POST",
        "network:websocket",
        "fs:read:/data/**",
        "fs:write:/cache/*",
        "fs:watch",
        "file:transfer:send",
        "file:transfer:receive",
        "platform:open-url",
        "platform:simulate-keys",
        "platform:read-clipboard",
        "action:declare:format-date",
        "action:invoke:*:format-date",
        "ui:page",
        "ui:navigate",
        "ui:toast",
        "ui:confirm",
        "ui:notify",
        "ui:modal",
    ] {
        let capability = Capability::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(capability.as_str(), text, "the text is preserved verbatim");
    }
}

#[rstest]
#[case("", CapabilityError::Empty)]
#[case("ui::navigate", CapabilityError::EmptySegment { text: "ui::navigate".into(), position: 1 })]
#[case(":ui:navigate", CapabilityError::EmptySegment { text: ":ui:navigate".into(), position: 0 })]
#[case("ui:", CapabilityError::EmptySegment { text: "ui:".into(), position: 1 })]
#[case("*", CapabilityError::BareWildcard("*".into()))]
#[case("**", CapabilityError::BareWildcard("**".into()))]
fn malformed_capabilities_are_refused(#[case] text: &str, #[case] _expected: CapabilityError) {
    assert!(Capability::parse(text).is_err(), "{text:?} should not parse");
}

#[test]
fn a_bare_wildcard_is_refused_by_the_grammar() {
    // Not by convention. A grammar that can express "every capability" will eventually be used
    // to express it, and the user's consent screen would show them a single asterisk.
    assert!(matches!(Capability::parse("*"), Err(CapabilityError::BareWildcard(_))));
    assert!(matches!(Capability::parse("**"), Err(CapabilityError::BareWildcard(_))));
    // But a wildcard inside a longer capability is fine.
    assert!(Capability::parse("log:*").is_ok());
    assert!(Capability::parse("network:fetch:**").is_ok());
}

#[test]
fn a_wildcard_cannot_stand_in_for_the_domain() {
    // If it could, `contains` could not use the domain bitmask to refuse a capability without
    // examining any strings at all.
    assert!(matches!(
        Capability::parse("*:read"),
        Err(CapabilityError::WildcardPrefix { position: 0, .. })
    ));
    assert!(Capability::parse("**/something").is_err());
}

#[test]
fn an_unknown_domain_is_named_in_the_error() {
    match Capability::parse("telepathy:read") {
        Err(CapabilityError::UnknownDomain(unknown)) => assert_eq!(unknown.name, "telepathy"),
        other => panic!("expected an unknown domain, got {other:?}"),
    }
}

#[test]
fn the_length_and_segment_limits_are_enforced() {
    let long = format!("log:{}", "a".repeat(MAX_LEN));
    assert!(matches!(Capability::parse(&long), Err(CapabilityError::TooLong { .. })));

    let many = "log:a:b:c:d:e:f";
    assert!(matches!(
        Capability::parse(many),
        Err(CapabilityError::TooManySegments { .. })
    ));
    // Exactly at the limit is fine.
    assert!(Capability::parse("log:a:b:c:d:e").is_ok());
}

#[test]
fn a_prefix_must_be_lowercase_and_start_with_a_letter() {
    for bad in ["log:Debug", "log:1read", "log:-read", "log:read_me", "log:re ad"] {
        assert!(Capability::parse(bad).is_err(), "{bad:?} should not parse");
    }
    // Digits and hyphens after the first character are fine.
    assert!(Capability::parse("log:debug-2").is_ok());
}

#[test]
fn a_qualifier_admits_the_forms_the_domains_need() {
    // One character class covering every domain's qualifier: a hostname, an HTTP method, a path, a
    // device id, an event pattern and a page key.
    for text in [
        "network:fetch:api.github.com",
        "network:fetch:api.x.com:POST",
        "network:fetch:xn--fsqu00a.com",
        "fs:read:/data/**",
        "device:send:@synra-pc",
        "event:emit:_plugin.@acme/chat.*",
        "ui:navigate:settings-page",
    ] {
        assert!(Capability::parse(text).is_ok(), "{text}");
    }
}

#[test]
fn the_segment_ceiling_is_enforced() {
    // The longest capability the design document lists is four segments.
    assert!(Capability::parse("network:fetch:api.github.com:POST").is_ok());
    // Room for extra qualifier segments, up to the ceiling.
    assert!(Capability::parse("network:fetch:api.github.com:POST:extra").is_ok());

    // One past the ceiling. The count is bounded because it decides the cost of matching, and
    // matching runs on every host call.
    let over = ["network", "fetch", "api.github.com", "POST", "a", "b", "c", "d"].join(":");
    assert!(matches!(
        Capability::parse(&over),
        Err(CapabilityError::TooManySegments { found: 8, max: MAX_SEGMENTS })
    ));
}

#[test]
fn a_qualifier_has_a_character_class_of_its_own() {
    // A qualifier admits dots, slashes, `@` and `*`, which a prefix does not: `api.github.com`,
    // `/data/**`, `@synra-pc` and `_plugin.@acme/chat.*` are qualifiers, and rejecting them would reject
    // every capability the design document lists.
    for text in [
        "network:fetch:api.github.com",
        "network:fetch:api.x.com:POST",
        "fs:read:/data/**",
        "device:send:@synra-pc",
        "event:emit:_plugin.@acme/chat.*",
    ] {
        assert!(Capability::parse(text).is_ok(), "{text} should parse");
    }

    // A prefix is narrower: a bare name. Dots and slashes belong to qualifiers.
    assert!(Capability::parse("network:api.github.com:x").is_err());
    assert!(Capability::parse("log:api.github.com").is_err());
}

#[test]
fn a_qualifier_cannot_carry_whitespace_or_markup() {
    // These are the characters that would let a value be reinterpreted somewhere else: in a path,
    // in a log line, in a prompt.
    for bad in [
        "network:fetch:api github.com",
        "ui:page:<script>",
        "ui:page:a\"b",
        "ui:page:a\\\\b",
        "ui:page:a;b",
    ] {
        assert!(Capability::parse(bad).is_err(), "{bad:?} should not parse");
    }
}

#[test]
fn segments_are_split_where_the_domains_expect() {
    let capability = Capability::parse("network:fetch:api.github.com:POST").expect("parses");
    assert_eq!(capability.domain(), Domain::Network);
    assert_eq!(
        capability.prefixes().iter().map(Segment::as_str).collect::<Vec<_>>(),
        vec!["fetch"]
    );
    assert_eq!(
        capability.qualifier().iter().map(Segment::as_str).collect::<Vec<_>>(),
        vec!["api.github.com", "POST"]
    );
}

#[test]
fn a_capability_with_no_qualifier_has_none() {
    let capability = Capability::parse("device:list").expect("parses");
    assert_eq!(capability.prefixes().len(), 1);
    assert!(capability.qualifier().is_empty());
}
