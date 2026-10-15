//! The refusal, against the two sets it is derived from.

use crate::error::CapabilityDenied;
use crate::set::CapabilitySet;

fn held(capabilities: &[&str]) -> CapabilitySet {
    CapabilitySet::parse_all(capabilities.iter().copied()).expect("a set")
}

#[test]
fn a_refusal_carries_all_three_things() {
    // ★ The three the design names. The first was all that existed: `GateRefusal::NotGranted` carried the needed
    // capability and nothing about what the plugin held.
    let refused = CapabilityDenied::of("storage:local:write", &held(&["storage:local:read", "log:info"]));

    assert_eq!(refused.needed, "storage:local:write");
    assert_eq!(refused.granted, vec!["storage:local:read".to_owned(), "log:info".to_owned()]);
    assert!(refused.suggestion.contains("storage:local:write"), "{}", refused.suggestion);
}

#[test]
fn the_suggestion_notices_a_capability_in_the_same_domain() {
    // ★ The reason the second element is worth carrying. An author whose plugin already holds `storage:local:read` has a
    // narrower problem than one who holds nothing in that domain — the user has already trusted the plugin with storage,
    // and one permission inside it is missing.
    let same_domain = CapabilityDenied::of("storage:local:write", &held(&["storage:local:read"]));
    assert!(
        same_domain.suggestion.contains("already holds `storage:local:read`"),
        "{}",
        same_domain.suggestion
    );

    let other_domain = CapabilityDenied::of("storage:local:write", &held(&["log:info"]));
    assert!(other_domain.suggestion.contains("nothing in that domain"), "{}", other_domain.suggestion);
}

#[test]
fn a_plugin_that_holds_nothing_is_told_so_rather_than_left_to_guess() {
    let refused = CapabilityDenied::of("device:send:*", &CapabilitySet::new());

    assert!(refused.granted.is_empty());
    assert!(refused.suggestion.contains("nothing in that domain"), "{}", refused.suggestion);
}

#[test]
fn a_needed_capability_that_will_not_parse_still_produces_a_refusal() {
    // ★ The gate's capabilities come from a generated table and always parse — but this does not assume it. An unparseable
    // one yields a suggestion with no domain hint rather than **no refusal**, because turning a bad refusal into no
    // refusal is the one outcome a gate must never produce.
    let refused = CapabilityDenied::of("not a capability", &held(&["log:info"]));

    assert_eq!(refused.needed, "not a capability");
    assert!(refused.suggestion.contains("not a capability"), "{}", refused.suggestion);
    assert!(!refused.suggestion.contains("domain"), "and it does not invent one: {}", refused.suggestion);
}

#[test]
fn the_json_carries_the_three_fields_a_plugin_reads() {
    let refused = CapabilityDenied::of("storage:local:write", &held(&["storage:local:read"]));
    let parsed: serde_json::Value = serde_json::from_str(&refused.to_json()).expect("valid JSON");

    assert_eq!(parsed["capability"], "storage:local:write");
    assert_eq!(parsed["granted"][0], "storage:local:read");
    assert!(parsed["suggestion"].as_str().is_some_and(|text| text.contains("ask the user")));
}

#[test]
fn the_json_escapes_what_it_has_to() {
    // The needed capability reaches this from a table, but the escape is what makes the output JSON **whatever** it is
    // handed — and a refusal whose `details` do not parse is one a plugin cannot read.
    let refused = CapabilityDenied::of("odd\"capability\\here", &CapabilitySet::new());
    let parsed: serde_json::Value = serde_json::from_str(&refused.to_json()).expect("valid JSON");

    assert_eq!(parsed["capability"], "odd\"capability\\here");
}

#[test]
fn a_refusal_reads_as_a_sentence_for_a_person() {
    let refused = CapabilityDenied::of("device:send:*", &CapabilitySet::new());

    assert_eq!(refused.to_string(), "this plugin does not hold `device:send:*`");
}
