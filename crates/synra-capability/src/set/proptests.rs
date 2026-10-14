//! The capability set's property tests.

use super::*;
use proptest::prelude::*;

use crate::capability::Capability;
use crate::domain::Domain;

/// Capabilities the grammar accepts, across several domains.
fn arbitrary_capability_text() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!["log", "device", "network", "fs", "ui", "platform"]),
        prop::sample::select(vec![
            "debug", "info", "list", "send", "fetch", "read", "write", "page", "open-url",
            "*", "**",
        ]),
        proptest::option::of(prop::sample::select(vec![
            "@a", "@b", "api.x.com", "api.y.com", "/data/**", "/cache/*", "page",
        ])),
    )
        .prop_map(|(domain, second, qualifier)| match qualifier {
            Some(qualifier) => format!("{domain}:{second}:{qualifier}"),
            None => format!("{domain}:{second}"),
        })
}

proptest! {
    /// The hard requirement from the design document: the answer does not depend on insertion
    /// order. A set built in one order and the same set built in another must agree on every
    /// query.
    #[test]
    fn contains_does_not_depend_on_insertion_order(
        capabilities in proptest::collection::vec(arbitrary_capability_text(), 1..12),
        queries in proptest::collection::vec(arbitrary_capability_text(), 1..12),
    ) {
        let ordered = CapabilitySet::parse_all(capabilities.iter().map(String::as_str)).expect("valid");
        let shuffled = CapabilitySet::parse_all(capabilities.iter().rev().map(String::as_str)).expect("valid");

        for query in &queries {
            let query = Capability::parse(query).expect("the generator makes valid capabilities");
            prop_assert_eq!(
                ordered.contains(&query),
                shuffled.contains(&query),
                "order changed the answer for {}",
                query,
            );
        }
    }

    /// Two sets with the same contents agree on everything, however they were built.
    ///
    /// The queries are the *members themselves* plus a probe per domain, rather than arbitrary
    /// generated strings: an arbitrary string is very likely to be one the grammar accepts but no
    /// generated capability covers, so every query would compare `false == false` and the property
    /// would pass without exercising anything.
    #[test]
    fn equal_contents_imply_equal_answers(
        capabilities in proptest::collection::vec(arbitrary_capability_text(), 1..10),
    ) {
        let mut a = CapabilitySet::new();
        let mut b = CapabilitySet::new();
        for text in &capabilities {
            a.insert_str(text).expect("valid");
        }
        // The same contents, inserted in reverse.
        for text in capabilities.iter().rev() {
            b.insert_str(text).expect("valid");
        }

        let members: Vec<Capability> = a.iter().cloned().collect();
        for query in &members {
            prop_assert!(a.contains(query));
            prop_assert!(b.contains(query), "the same contents disagreed about {query}");
        }

        // And a probe in each domain, which is the fast-negative path.
        for domain in Domain::ALL {
            let probe = Capability::parse(&format!("{domain}:list")).expect("valid");
            prop_assert_eq!(a.contains(&probe), b.contains(&probe));
        }
    }

    /// A pattern in the set covers everything it matches, and nothing else. This is the property
    /// the authorisation model rests on: the set must not grant more than it was given.
    #[test]
    fn a_set_grants_exactly_its_own_members(
        capabilities in proptest::collection::vec(arbitrary_capability_text(), 1..8),
        query in arbitrary_capability_text(),
    ) {
        let mut set = CapabilitySet::new();
        let mut members = Vec::new();
        for text in &capabilities {
            if set.insert_str(text).is_ok() {
                members.push(Capability::parse(text).expect("valid"));
            }
        }

        let query = Capability::parse(&query).expect("valid");
        // Membership is the disjunction over `matches`, so the two must agree.
        let expected = members.iter().any(|member| member.matches(&query));
        prop_assert_eq!(set.contains(&query), expected);
    }

    /// Building a set is total: arbitrary strings either insert or are refused, and the domain
    /// mask always agrees with the contents. A mask that disagreed would be a fast negative that
    /// wrongly refuses a capability the plugin holds.
    #[test]
    fn the_domain_mask_agrees_with_the_contents(
        capabilities in proptest::collection::vec(arbitrary_capability_text(), 0..12)
    ) {
        let mut set = CapabilitySet::new();
        for text in &capabilities {
            let _ = set.insert_str(text);
        }

        for capability in set.iter() {
            prop_assert!(
                set.domains().has(capability.domain()),
                "the mask is missing {}",
                capability.domain(),
            );
        }

        // And a domain with no capabilities is refused without examining anything.
        for domain in Domain::ALL {
            if !set.domains().has(*domain) {
                let probe = Capability::parse(&format!("{domain}:list")).expect("valid");
                prop_assert!(!set.contains(&probe));
            }
        }
    }
}
