use synra_protocol::ids::PluginId;
use synra_protocol::inbound::MAX_WILDCARD_RULES;
use super::super::{EventRegistry, MAX_DISTINCT_NAMES, Registration, RouteOutcome, RouterError, RouterReport};
use super::{key, registry, rules};

#[test]
fn the_report_carries_what_the_interface_needs() {
    let mut registry = registry();
    registry
        .register(&key("@a/one"), &rules(&["device.ping", "_synra.device.*"]))
        .expect("registers");

    let report = registry.report();
    assert_eq!(report.subscriptions, 2);
    assert_eq!(report.wildcard_rules, 1);
    assert_eq!(report.subscribers, 1);
    assert_eq!(report.max_distinct_names, MAX_DISTINCT_NAMES);
    assert_eq!(report.max_wildcard_rules, MAX_WILDCARD_RULES);
    assert!(!report.is_near_a_bound());
}

#[test]
fn a_report_notices_a_bound_being_approached() {
    // A device that has reached a bound is one where events are being dropped, and the user's experience of that is
    // "a plugin stopped working" with nothing to explain it.
    let near = RouterReport {
        // At the threshold exactly: the comparison is `>= ninety percent`, so one below it is not near.
        distinct_names: MAX_DISTINCT_NAMES * 9 / 10 + 1,
        max_distinct_names: MAX_DISTINCT_NAMES,
        wildcard_rules: 0,
        max_wildcard_rules: MAX_WILDCARD_RULES,
        subscriptions: 0,
        subscribers: 0,
    };
    assert!(near.is_near_a_bound());

    let far = RouterReport {
        distinct_names: 10,
        ..near
    };
    assert!(!far.is_near_a_bound());

    let wildcards = RouterReport {
        distinct_names: 0,
        max_distinct_names: MAX_DISTINCT_NAMES,
        wildcard_rules: MAX_WILDCARD_RULES * 9 / 10 + 1,
        max_wildcard_rules: MAX_WILDCARD_RULES,
        subscriptions: 0,
        subscribers: 0,
    };
    assert!(wildcards.is_near_a_bound());
}

#[test]
fn the_registry_debug_does_not_dump_every_name() {
    // A registry holding a thousand peer-chosen names must not print them all into a log.
    let mut registry = registry();
    for index in 0..50 {
        let _ = registry.route(&format!("_synra.noise.{index}"));
    }
    let debug = format!("{registry:?}");
    assert!(!debug.contains("_synra.noise"), "{debug}");
    assert!(debug.contains("distinct_names"), "{debug}");
}

#[test]
fn an_empty_registry_is_the_default() {
    assert_eq!(EventRegistry::default().distinct_names(), 0);
    assert_eq!(EventRegistry::default().wildcard_rules(), 0);
}

#[test]
fn router_errors_explain_themselves() {
    let errors = [
        RouterError::Duplicate {
            plugin: "p".to_owned(),
            rule: "r".to_owned(),
        },
        RouterError::BadRule {
            rule: "r".to_owned(),
        },
        RouterError::TooManyWildcards { limit: 64 },
        RouterError::OutOfNumbers,
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

#[test]
fn a_registration_carries_its_own_key() {
    let registration = Registration {
        plugin: PluginId::parse("@synra-plugin/chat").expect("a valid id"),
        rules: rules(&["device.ping"]),
    };
    assert_eq!(registration.key().as_str(), "@synra-plugin/chat");
}

#[test]
fn an_error_converts_to_the_safe_outcome() {
    // A routing error other than the bound is not something routing can produce, and reporting "nobody" drops the
    // event rather than delivering it somewhere it does not belong.
    assert!(matches!(
        RouteOutcome::from(RouterError::OutOfNumbers),
        RouteOutcome::Nobody
    ));
    assert!(matches!(
        RouteOutcome::from(RouterError::Unknown { distinct: 7 }),
        RouteOutcome::Unknown { distinct: 7 }
    ));
}
