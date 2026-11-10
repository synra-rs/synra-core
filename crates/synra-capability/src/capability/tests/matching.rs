use super::*;

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
    let pattern = Capability::parse("event:emit:_plugin.@acme/chat.*").expect("valid");
    assert!(
        pattern.matches(&Capability::parse("event:emit:_plugin.@acme/chat.text").expect("valid"))
    );
    assert!(
        !pattern.matches(&Capability::parse("event:emit:_plugin.@acme/notes.text").expect("valid"))
    );
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
    assert!(
        !Capability::parse("fs:read:/data/**")
            .expect("valid")
            .is_exact()
    );
    assert!(
        !Capability::parse("event:emit:_plugin.@acme/chat.*")
            .expect("valid")
            .is_exact()
    );
}

#[test]
fn specificity_increases_with_literals_and_falls_with_wildcards() {
    let exact = Capability::parse("network:fetch:api.github.com").expect("valid");
    let wildcard = Capability::parse("network:fetch:**").expect("valid");
    let broad = Capability::parse("network:**").expect("valid");

    assert!(exact.specificity() > wildcard.specificity());
    assert!(wildcard.specificity() > broad.specificity());
}
