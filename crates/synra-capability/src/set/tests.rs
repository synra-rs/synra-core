//! The capability set's tests.

use super::*;

use crate::capability::Capability;
use crate::domain::Domain;

fn cap(text: &str) -> Capability {
    Capability::parse(text).expect("valid capability")
}

fn set(texts: &[&str]) -> CapabilitySet {
    CapabilitySet::parse_all(texts.iter().copied()).expect("valid set")
}

#[test]
fn an_empty_set_grants_nothing() {
    let empty = CapabilitySet::new();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(empty.domains().is_empty());
    assert!(!empty.contains(&cap("log:debug")));
    assert_eq!(empty.iter().count(), 0);
    assert_eq!(empty.to_string(), "(no capabilities)");
    assert!(empty.describe_all().is_empty());
}

#[test]
fn an_exact_capability_grants_itself() {
    let set = set(&["log:debug", "device:list"]);
    assert!(set.contains(&cap("log:debug")));
    assert!(set.contains(&cap("device:list")));
    assert!(!set.contains(&cap("log:info")));
    assert!(!set.contains(&cap("device:send:@x")));
    assert_eq!(set.len(), 2);
}

#[test]
fn a_pattern_grants_its_family() {
    let set = set(&["log:*"]);
    assert!(set.contains(&cap("log:debug")));
    assert!(set.contains(&cap("log:info")));
    // Not another domain.
    assert!(!set.contains(&cap("device:list")));
}

#[test]
fn the_domain_mask_refuses_the_common_case_without_looking_at_strings() {
    // A plugin with only log capabilities must not be able to reach the network, and the check
    // must not have to examine any capability text to establish that.
    let set = set(&["log:debug", "storage:local:read"]);
    assert!(set.domains().has(Domain::Log));
    assert!(set.domains().has(Domain::Storage));
    assert!(!set.domains().has(Domain::Network));
    assert!(!set.domains().has(Domain::Platform));

    assert!(!set.contains(&cap("network:fetch:api.github.com")));
    assert!(!set.contains(&cap("platform:open-url")));
}

#[test]
fn a_grant_is_not_widened_by_a_missing_qualifier() {
    let set = set(&["network:fetch"]);
    assert!(set.contains(&cap("network:fetch")));
    // `network:fetch` says nothing about `network:fetch:api.github.com`.
    assert!(!set.contains(&cap("network:fetch:api.github.com")));
}

#[test]
fn patterns_are_ordered_by_specificity_without_affecting_the_answer() {
    let set = set(&["network:**", "network:fetch:**", "network:fetch:api.github.com"]);
    let specificity: Vec<u32> = set.patterns().map(Capability::specificity).collect();

    // Descending: the most specific pattern is reported first, so "which pattern applies?" has a
    // deterministic answer in the interface and in an audit record.
    assert!(
        specificity.windows(2).all(|pair| pair[0] >= pair[1]),
        "{specificity:?}"
    );

    // And the answer itself does not depend on that order.
    assert!(set.contains(&cap("network:fetch:api.github.com")));
    assert!(set.contains(&cap("network:fetch:other.com")));
    assert!(set.contains(&cap("network:send:x")));
}

#[test]
fn inserting_the_same_capability_twice_is_idempotent() {
    let mut set = CapabilitySet::new();
    set.insert_str("log:debug").expect("first");
    set.insert_str("log:debug").expect("second");
    assert_eq!(set.len(), 1);

    set.insert_str("log:*").expect("pattern");
    set.insert_str("log:*").expect("pattern again");
    assert_eq!(set.len(), 2);
    assert_eq!(set.patterns().count(), 1);
}

#[test]
fn a_bad_capability_fails_the_whole_set() {
    // Refusing at load is better than installing a plugin whose grant is silently missing an
    // entry: the failure would appear as a denied call at runtime, in a place unrelated to the
    // typo.
    assert!(matches!(
        CapabilitySet::parse_all(["log:debug", "not a capability"]),
        Err(SetError::Capability(_))
    ));
}

#[test]
fn the_capability_count_is_bounded() {
    let mut set = CapabilitySet::new();
    // Distinct exact capabilities, all in one domain.
    for index in 0..MAX_CAPABILITIES {
        set.insert_str(&format!("log:level-{index}")).expect("within the limit");
    }
    assert_eq!(set.len(), MAX_CAPABILITIES);
    assert!(matches!(
        set.insert_str("log:one-too-many"),
        Err(SetError::TooMany { max: MAX_CAPABILITIES })
    ));
}

#[test]
fn the_pattern_count_is_bounded_and_lower_than_the_total() {
    // Patterns are scanned on every check, so they are the expensive part. A manifest must not be
    // able to make itself costly by declaring wildcards.
    // Through `black_box`, so the check survives constant folding: comparing two constants directly
    // is evaluated at compile time and would pass even after one of them changed.
    let (patterns, capabilities) = core::hint::black_box((MAX_PATTERNS, MAX_CAPABILITIES));
    assert!(patterns < capabilities);

    let mut set = CapabilitySet::new();
    for index in 0..MAX_PATTERNS {
        set.insert_str(&format!("log:debug:{index}*")).expect("within the limit");
    }
    assert!(matches!(
        set.insert_str("log:debug:one-too-many*"),
        Err(SetError::TooManyPatterns { max: MAX_PATTERNS })
    ));

    // Exact capabilities are unaffected by the pattern limit.
    set.insert_str("device:list").expect("exact still fits");
}

#[test]
fn exact_and_pattern_capabilities_coexist() {
    let set = set(&["log:debug", "log:*", "device:list"]);
    assert_eq!(set.len(), 3);
    assert_eq!(set.patterns().count(), 1);
    assert!(set.contains(&cap("log:debug")));
    assert!(set.contains(&cap("log:trace")));
    assert!(set.contains(&cap("device:list")));
    assert!(!set.contains(&cap("device:send:@x")));
}

#[test]
fn iteration_covers_every_capability_exactly_once() {
    let set = set(&["log:debug", "log:info", "log:*", "device:list", "device:send:@a"]);
    let mut seen: Vec<String> = set.iter().map(ToString::to_string).collect();
    seen.sort();
    let mut expected = vec![
        "log:debug",
        "log:info",
        "log:*",
        "device:list",
        "device:send:@a",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(seen, expected);
    assert_eq!(set.iter().count(), set.len());
}

#[test]
fn descriptions_are_deduplicated_and_readable() {
    // Two capabilities can mean the same thing to a user. Showing the same sentence twice makes
    // the prompt look like it is padding the request.
    let set = set(&["network:fetch:*", "network:fetch:**", "log:debug"]);
    let descriptions = set.describe_all();
    let unique: std::collections::HashSet<&String> = descriptions.iter().collect();
    assert_eq!(descriptions.len(), unique.len(), "{descriptions:?}");
    assert!(descriptions.contains(&"read from any website".to_owned()), "{descriptions:?}");
    assert!(descriptions.contains(&"write log messages".to_owned()), "{descriptions:?}");
}

#[test]
fn a_set_displays_its_contents() {
    let set = set(&["log:debug"]);
    assert_eq!(set.to_string(), "log:debug");
}

// ── Effective capabilities ────────────────────────────────────────────────────────────────────

#[test]
fn a_grant_outside_the_manifest_is_refused() {
    // The user's consent was obtained for a different set than the one being used.
    let wanted = set(&["log:debug"]);
    let granted = set(&["log:debug", "network:fetch:api.github.com"]);
    let imports = ImportSet::new();

    assert!(matches!(
        verify_effective_caps(&wanted, &granted, &imports),
        Err(VerifyError::GrantNotRequested { .. })
    ));
}

#[test]
fn an_import_with_no_grant_is_refused() {
    // The plugin would call a host function with no authorisation behind it, and the gate would
    // deny it on every call. Refusing at load reports it once, where it can be explained.
    let wanted = set(&["log:debug", "network:fetch:api.github.com"]);
    let granted = set(&["log:debug"]);
    let imports = ImportSet::from_interfaces(["host:log", "host:network"]);

    match verify_effective_caps(&wanted, &granted, &imports) {
        Err(VerifyError::UncoveredImport { interface }) => assert_eq!(interface, "host:network"),
        other => panic!("expected an uncovered import, got {other:?}"),
    }
}

#[test]
fn a_covering_grant_makes_an_import_acceptable() {
    let wanted = set(&["log:debug", "network:fetch:api.github.com"]);
    let granted = set(&["log:debug", "network:fetch:api.github.com"]);
    let imports = ImportSet::from_interfaces(["host:log", "host:network"]);

    let effective = verify_effective_caps(&wanted, &granted, &imports).expect("reconciles");
    assert!(effective.is_loadable());
    assert!(effective.granted.contains(&cap("log:debug")));
    assert!(effective.granted.contains(&cap("network:fetch:api.github.com")));
    assert!(effective.uncovered.is_empty());
}

#[test]
fn a_grant_the_module_cannot_use_is_a_warning_not_an_error() {
    // Not dangerous — an unimported function cannot be called — but the consent prompt showed the
    // user something the plugin cannot use, which is worth reporting.
    let wanted = set(&["log:debug", "platform:open-url"]);
    let granted = set(&["log:debug", "platform:open-url"]);
    let imports = ImportSet::from_interfaces(["host:log"]);

    let effective = verify_effective_caps(&wanted, &granted, &imports).expect("reconciles");
    assert!(effective.is_loadable());
    assert_eq!(effective.unused.len(), 1);
    assert_eq!(effective.unused[0].to_string(), "platform:open-url");
}

#[test]
fn the_effective_set_is_the_intersection() {
    // Asked for three, granted two, imported one. The plugin holds what was both asked for and
    // granted.
    let wanted = set(&["log:debug", "log:info", "device:list"]);
    let granted = set(&["log:debug", "device:list"]);
    let imports = ImportSet::from_interfaces(["host:log", "host:device"]);

    let effective = verify_effective_caps(&wanted, &granted, &imports).expect("reconciles");
    assert_eq!(effective.granted.len(), 2);
    assert!(effective.granted.contains(&cap("log:debug")));
    assert!(!effective.granted.contains(&cap("log:info")), "never granted");
    assert!(effective.granted.contains(&cap("device:list")));
}

#[test]
fn every_domain_has_an_interface() {
    // A domain without an interface could never be covered by an import, so every plugin using it
    // would be refused at load.
    let mut names = std::collections::HashSet::new();
    for domain in Domain::ALL {
        let interface = interface_for_domain(*domain);
        assert!(interface.starts_with("host:"), "{domain} -> {interface}");
        assert!(names.insert(interface), "{domain} shares an interface with another domain");
    }
}

#[test]
fn an_import_set_reports_what_was_imported() {
    let imports = ImportSet::from_interfaces(["host:log", "host:network", "host:log"]);
    assert_eq!(imports.len(), 2, "duplicates collapse");
    assert!(imports.contains("host:log"));
    assert!(imports.contains("host:network"));
    assert!(!imports.contains("host:fs"));
    assert!(!imports.is_empty());

    assert!(ImportSet::new().is_empty());
}
