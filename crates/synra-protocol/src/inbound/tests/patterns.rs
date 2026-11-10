use crate::event::EventName;
use super::super::{HandlePattern, PatternError, HandleSet, HandleSetError, MAX_PATTERN_WILDCARDS, MAX_WILDCARD_RULES};

#[test]
fn package_patterns_keep_publisher_identity_and_have_a_length_bound() {
    let pattern = HandlePattern::parse("_plugin.@acme/chat.*").unwrap();
    assert!(pattern.matches("_plugin.@acme/chat.ready"));
    assert!(!pattern.matches("_plugin.@other/chat.ready"));
    assert!(!pattern.matches("_plugin.@acme/synra-plugin-chat.ready"));
    for bad in [
        "_plugin.chat.*",
        "_plugin.@acme/../chat.*",
        "_plugin.@acme/chat.topic/extra",
    ] {
        assert!(HandlePattern::parse(bad).is_err(), "{bad}");
    }
    let prefix = "_plugin.@acme/chat.";
    let at_limit = format!(
        "{prefix}{}",
        "x".repeat(crate::event::MAX_EVENT_NAME_LEN - prefix.len())
    );
    assert!(HandlePattern::parse(&at_limit).is_ok());
    assert!(matches!(
        HandlePattern::parse(&format!("{at_limit}x")),
        Err(PatternError::TooLong { .. })
    ));
}

#[test]
fn an_exact_pattern_matches_only_itself() {
    let pattern = HandlePattern::parse("_synra.transfer.completed").expect("valid");
    assert!(pattern.is_exact());
    assert_eq!(pattern.wildcard_count(), 0);
    assert!(pattern.matches("_synra.transfer.completed"));
    assert!(!pattern.matches("_synra.transfer.failed"));
    // A prefix is not a match: `handles` is not a glob language.
    assert!(!pattern.matches("_synra.transfer.completed.extra"));
}

#[test]
fn a_trailing_wildcard_matches_exactly_one_segment() {
    let pattern = HandlePattern::parse("_plugin.@acme/chat.*").expect("valid");
    assert!(!pattern.is_exact());
    assert_eq!(pattern.wildcard_count(), 1);

    assert!(pattern.matches("_plugin.@acme/chat.text"));
    assert!(pattern.matches("_plugin.@acme/chat.typing"));
    // Deeper names do not match. A pattern that could match an unbounded number of segments
    // makes "which plugin gets this event" unanswerable from a manifest.
    assert!(!pattern.matches("_plugin.@acme/chat.room.message"));
    // And neither does a shorter one.
    assert!(!pattern.matches("_plugin.@acme/chat"));
    // Nor another plugin's namespace.
    assert!(!pattern.matches("_plugin.@acme/notes.text"));
}

#[test]
fn a_wildcard_family_matches_its_prefix_only() {
    let pattern = HandlePattern::parse("file.transfer.*").expect("valid");
    assert!(pattern.matches("file.transfer.chunk"));
    assert!(pattern.matches("file.transfer.complete"));
    assert!(!pattern.matches("file.other.chunk"));
    // The prefix must end at a segment boundary, not mid-character.
    assert!(!pattern.matches("file.transferX.chunk"));
}

#[test]
fn multiple_trailing_wildcards_are_allowed() {
    let pattern = HandlePattern::parse("_synra.*.*").expect("valid");
    assert_eq!(pattern.wildcard_count(), 2);
    assert!(pattern.matches("_synra.device.changed"));
    assert!(!pattern.matches("_synra.device.changed.now"));

    // An all-wildcard pattern matches any name of the right length.
    let any_two = HandlePattern::parse("*.*").expect("valid");
    assert!(any_two.matches("a.b"));
    assert!(!any_two.matches("a.b.c"));
    assert!(!any_two.matches("a"));
}

#[test]
fn a_partial_wildcard_is_refused() {
    // `tex*` is a different feature. Accepting it silently would make a manifest mean something
    // its author did not intend.
    assert!(matches!(
        HandlePattern::parse("_plugin.@acme/chat.tex*"),
        Err(PatternError::PartialWildcard(_))
    ));
    assert!(HandlePattern::parse("_plugin.*chat.text").is_err());
}

#[test]
fn malformed_patterns_are_refused() {
    assert!(matches!(HandlePattern::parse(""), Err(PatternError::Empty)));
    assert!(matches!(
        HandlePattern::parse("_plugin..text"),
        Err(PatternError::EmptySegment(_))
    ));
    assert!(matches!(
        HandlePattern::parse("_plugin.@acme/chat.a/b"),
        Err(PatternError::BadCharacter { .. })
    ));
    assert!(matches!(
        HandlePattern::parse("_plugin.@acme/chat.a b"),
        Err(PatternError::BadCharacter { .. })
    ));
}

#[test]
fn wildcard_count_is_bounded() {
    // One wildcard too many.
    let mut pattern = String::from("x");
    for _ in 0..=MAX_PATTERN_WILDCARDS {
        pattern.push_str(".*");
    }
    assert!(matches!(
        HandlePattern::parse(&pattern),
        Err(PatternError::TooManyWildcards { .. })
    ));

    // Exactly at the limit is fine.
    let mut at_limit = String::from("x");
    for _ in 0..MAX_PATTERN_WILDCARDS {
        at_limit.push_str(".*");
    }
    assert!(HandlePattern::parse(&at_limit).is_ok());
}

#[test]
fn exact_patterns_and_wildcards_agree_with_event_names() {
    // A pattern that parses must be able to match at least one *sendable* name, or the plugin
    // declares a subscription that can never fire.
    let pattern = HandlePattern::parse("_plugin.@acme/chat.*").expect("valid");
    assert!(pattern.matches("_plugin.@acme/chat.text"));
    assert!(EventName::parse("_plugin.@acme/chat.text").is_ok());
}

#[test]
fn a_handle_set_separates_exact_from_wildcards() {
    let set = HandleSet::compile([
        "_synra.transfer.completed",
        "_synra.device.changed",
        "_plugin.@acme/chat.*",
    ])
    .expect("compiles");

    assert_eq!(set.exact_count(), 2);
    assert_eq!(set.wildcard_count(), 1);
    assert!(!set.is_empty());

    assert!(set.matches("_synra.transfer.completed"));
    assert!(set.matches("_plugin.@acme/chat.text"));
    assert!(!set.matches("_synra.share.received"));
    assert!(!set.matches("_plugin.@acme/notes.text"));
}

#[test]
fn an_empty_handle_set_matches_nothing() {
    let set = HandleSet::compile(Vec::<String>::new()).expect("compiles");
    assert!(set.is_empty());
    assert!(!set.matches("_synra.device.changed"));
}

#[test]
fn a_bad_pattern_fails_the_whole_declaration() {
    // Better to refuse at load than to install a plugin whose subscriptions are silently
    // missing an entry.
    let result = HandleSet::compile(["_synra.device.changed", "not a pattern"]);
    assert!(matches!(result, Err(HandleSetError::Pattern(_))));
}

#[test]
fn wildcard_rules_are_bounded() {
    let many: Vec<String> = (0..=MAX_WILDCARD_RULES)
        .map(|i| format!("_plugin.@acme/p{i}.*"))
        .collect();
    assert!(matches!(
        HandleSet::compile(many),
        Err(HandleSetError::TooManyWildcards { max: MAX_WILDCARD_RULES })
    ));

    let at_limit: Vec<String> = (0..MAX_WILDCARD_RULES)
        .map(|i| format!("_plugin.@acme/p{i}.*"))
        .collect();
    assert!(HandleSet::compile(at_limit).is_ok());
}
