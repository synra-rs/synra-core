use super::*;

#[test]
fn a_configuration_with_nothing_but_a_default_has_one_place_to_look() {
    let order = config().resolve("@acme/chat");
    assert_eq!(order, vec![DEFAULT_REGISTRY.to_owned()]);
}

#[test]
fn mirrors_are_tried_by_priority_and_the_default_is_last() {
    let config = config()
        .with_mirror(RegistryMirror::new("https://slow.example", 90))
        .with_mirror(RegistryMirror::new("https://fast.example", 10))
        .with_mirror(RegistryMirror::new("https://middle.example", 50));

    assert_eq!(
        config.resolve("@acme/chat"),
        vec![
            "https://fast.example".to_owned(),
            "https://middle.example".to_owned(),
            "https://slow.example".to_owned(),
            DEFAULT_REGISTRY.to_owned(),
        ]
    );
}

#[test]
fn two_mirrors_at_one_priority_keep_the_order_they_were_configured_in() {
    // "Last one configured wins" is an ordering nobody reading a configuration file can predict, so the sort is
    // stable and the declaration order decides.
    let config = config()
        .with_mirror(RegistryMirror::new("https://first.example", 10))
        .with_mirror(RegistryMirror::new("https://second.example", 10));

    let order = config.resolve("@acme/chat");
    assert_eq!(order.first().map(String::as_str), Some("https://first.example"));
    assert_eq!(order.get(1).map(String::as_str), Some("https://second.example"));
}

#[test]
fn a_disabled_mirror_is_not_tried() {
    let config = config()
        .with_mirror(RegistryMirror::new("https://off.example", 1).disabled())
        .with_mirror(RegistryMirror::new("https://on.example", 2));

    assert_eq!(config.resolve("@acme/chat"), vec!["https://on.example".to_owned(), DEFAULT_REGISTRY.to_owned()]);
}

#[test]
fn an_exact_override_is_the_only_place_a_package_is_looked_for() {
    // ★ A decision, not a preference. Falling back from a mirror the user configured for a package to a public
    // registry is how a private package's name gets asked for in public.
    let config = config().with_override(PackagePattern::new("@acme/secret"), "https://private.example");
    assert_eq!(config.resolve("@acme/secret"), vec!["https://private.example".to_owned()]);
    // And a package it does not name still gets the ordinary order.
    assert_eq!(config.resolve("@acme/other"), vec![DEFAULT_REGISTRY.to_owned()]);
}

#[test]
fn an_exact_override_wins_over_a_wildcard_one() {
    let config = config()
        .with_override(PackagePattern::new("@acme/*"), "https://scope.example")
        .with_override(PackagePattern::new("@acme/one"), "https://exact.example");

    assert_eq!(config.resolve("@acme/one"), vec!["https://exact.example".to_owned()]);
    assert_eq!(config.resolve("@acme/two"), vec!["https://scope.example".to_owned()]);
    // And the exact one is found even when it is declared second, which is what "exact > wildcard" means.
    let reversed = RegistryConfig::new()
        .with_override(PackagePattern::new("@acme/one"), "https://exact.example")
        .with_override(PackagePattern::new("@acme/*"), "https://scope.example");
    assert_eq!(reversed.resolve("@acme/one"), vec!["https://exact.example".to_owned()]);
}

#[test]
fn a_pattern_matches_what_it_says_and_nothing_else() {
    let exact = PackagePattern::new("@acme/chat");
    assert!(exact.matches("@acme/chat"));
    assert!(!exact.matches("@acme/chatty"), "an exact pattern is not a prefix");
    assert!(exact.is_exact());

    let wildcard = PackagePattern::new("@acme/*");
    assert!(wildcard.matches("@acme/chat"));
    assert!(wildcard.matches("@acme/"));
    assert!(!wildcard.matches("@other/chat"));
    assert!(!wildcard.is_exact());
    assert_eq!(wildcard.as_str(), "@acme/*");

    // Case matters, because a package name is a string a registry compares byte for byte.
    assert!(!PackagePattern::new("@acme/*").matches("@Acme/chat"));
}

#[test]
fn the_default_is_not_listed_twice_when_a_mirror_points_at_it() {
    let config = config().with_mirror(RegistryMirror::new(DEFAULT_REGISTRY, 1));
    assert_eq!(config.resolve("@acme/chat"), vec![DEFAULT_REGISTRY.to_owned()]);
}
