//! The capability tests.

use rstest::rstest;

use crate::domain::Domain;

use super::{Capability, CapabilityError, MAX_LEN, MAX_SEGMENTS, Segment};

#[test]
fn real_capabilities_parse() {
    // Every form the design document lists, so a change to the grammar cannot quietly stop
    // accepting one of them.
    for text in [
        "log:*",
        "log:debug",
        "event:emit:_plugin.chat.*",
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
        "event:emit:_plugin.chat.*",
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
    // `/data/**`, `@synra-pc` and `_plugin.chat.*` are qualifiers, and rejecting them would reject
    // every capability the design document lists.
    for text in [
        "network:fetch:api.github.com",
        "network:fetch:api.x.com:POST",
        "fs:read:/data/**",
        "device:send:@synra-pc",
        "event:emit:_plugin.chat.*",
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

// ── Matching: the table from the design document, verbatim ───────────────────────────────────

#[rstest]
#[case("ui:*", "ui:page", true, "one-segment wildcard")]
#[case("ui:*", "ui:page:extra", false, "different segment count")]
#[case("ui:**", "ui:page:extra", true, "multi-segment wildcard")]
#[case("ui:**", "device:list", false, "different first segment")]
#[case("network:fetch:**", "network:fetch:api.x.com", true, "")]
#[case("network:fetch:**", "network:send:api.x.com", false, "second segment differs")]
#[case("network:fetch:api.x.com", "network:fetch:api.x.com:POST", false, "no wildcard, so segment counts must match")]
#[case("ui:page", "ui:page", true, "exact")]
#[case("log:*", "log:debug", true, "")]
#[case("log:debug", "log:debug", true, "")]
#[case("log:debug", "log:info", false, "")]
#[case("ui:*", "log:debug", false, "different domain")]
fn matching_matches_the_documented_table(
    #[case] pattern: &str,
    #[case] candidate: &str,
    #[case] expected: bool,
    #[case] why: &str,
) {
    let pattern = Capability::parse(pattern).expect("valid pattern");
    let candidate = Capability::parse(candidate).expect("valid capability");
    assert_eq!(pattern.matches(&candidate), expected, "{pattern} vs {candidate}: {why}");
}

#[test]
fn a_multi_segment_wildcard_can_match_nothing() {
    // `**` matches zero or more, so `network:fetch:**` covers plain `network:fetch`. Zero is not
    // an afterthought: a plugin granted the fetch family should be able to fetch the bare
    // resource name too.
    let pattern = Capability::parse("network:fetch:**").expect("valid");
    let candidate = Capability::parse("network:fetch").expect("valid");
    assert!(pattern.matches(&candidate));

    // And a middle `**` works, not only a trailing one.
    let middle = Capability::parse("fs:**").expect("valid");
    assert!(middle.matches(&Capability::parse("fs:read:/data/**").expect("valid")));
}

#[test]
fn a_single_wildcard_does_not_cross_a_segment() {
    let pattern = Capability::parse("ui:*").expect("valid");
    assert!(pattern.matches(&Capability::parse("ui:page").expect("valid")));
    assert!(!pattern.matches(&Capability::parse("ui:page:extra").expect("valid")));
}

#[test]
fn a_missing_qualifier_is_not_a_statement_about_qualified_capabilities() {
    // `network:fetch` does not cover `network:fetch:api.github.com`. Treating it as a prefix match
    // would make the grant the user was shown ("read from the network") different from what the
    // plugin got.
    let broad = Capability::parse("network:fetch").expect("valid");
    let specific = Capability::parse("network:fetch:api.github.com").expect("valid");
    assert!(!broad.matches(&specific));
    // And the reverse: a grant for one host is not a grant for the whole resource.
    assert!(!specific.matches(&broad));
}

#[test]
fn a_trailing_double_wildcard_in_a_qualifier_matches_a_path_family() {
    let pattern = Capability::parse("fs:read:/data/**").expect("valid");
    assert!(pattern.matches(&Capability::parse("fs:read:/data/a").expect("valid")));
    assert!(pattern.matches(&Capability::parse("fs:read:/data/a/b/c").expect("valid")));
    assert!(pattern.matches(&Capability::parse("fs:read:/data/").expect("valid")));
    // A sibling directory is not under `/data`.
    assert!(!pattern.matches(&Capability::parse("fs:read:/database").expect("valid")));
    assert!(!pattern.matches(&Capability::parse("fs:read:/other/a").expect("valid")));
}

#[test]
fn a_single_wildcard_in_a_qualifier_stays_within_one_segment() {
    // `/cache/*` is "one entry directly in /cache", and reaching deeper is what `**` is for.
    // Without this, a grant for one level would silently cover the whole tree.
    let pattern = Capability::parse("fs:write:/cache/*").expect("valid");
    assert!(pattern.matches(&Capability::parse("fs:write:/cache/file").expect("valid")));
    assert!(!pattern.matches(&Capability::parse("fs:write:/cache/sub/file").expect("valid")));
}

#[test]
fn an_event_pattern_qualifier_matches_a_family() {
    let pattern = Capability::parse("event:emit:_plugin.chat.*").expect("valid");
    assert!(pattern.matches(&Capability::parse("event:emit:_plugin.chat.text").expect("valid")));
    assert!(!pattern.matches(&Capability::parse("event:emit:_plugin.notes.text").expect("valid")));
}

#[test]
fn a_hostname_wildcard_does_not_match_a_deeper_subdomain_prefix() {
    // `*.example.com` is not expressible as a whole prefix, and the qualifier matcher must not
    // accidentally behave like a general glob: `api.example.com` is not `example.com`.
    let pattern = Capability::parse("network:fetch:api.example.com").expect("valid");
    assert!(!pattern.matches(&Capability::parse("network:fetch:example.com").expect("valid")));
    assert!(!pattern.matches(&Capability::parse("network:fetch:api.example.com.evil").expect("valid")));
}

#[test]
fn is_exact_distinguishes_a_value_from_a_family() {
    assert!(Capability::parse("device:list").expect("valid").is_exact());
    assert!(Capability::parse("network:fetch:api.github.com").expect("valid").is_exact());
    assert!(Capability::parse("network:fetch:api.x.com:POST").expect("valid").is_exact());

    assert!(!Capability::parse("log:*").expect("valid").is_exact());
    assert!(!Capability::parse("ui:**").expect("valid").is_exact());
    // A wildcard inside a qualifier counts: `/data/**` covers many paths even though it is
    // written as one segment.
    assert!(!Capability::parse("fs:read:/data/**").expect("valid").is_exact());
    assert!(!Capability::parse("event:emit:_plugin.chat.*").expect("valid").is_exact());
}

#[test]
fn specificity_increases_with_literals_and_falls_with_wildcards() {
    let exact = Capability::parse("network:fetch:api.github.com").expect("valid");
    let wildcard = Capability::parse("network:fetch:**").expect("valid");
    let broad = Capability::parse("network:**").expect("valid");

    assert!(exact.specificity() > wildcard.specificity());
    assert!(wildcard.specificity() > broad.specificity());
}

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
        "event:emit:_plugin.chat.*",
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
