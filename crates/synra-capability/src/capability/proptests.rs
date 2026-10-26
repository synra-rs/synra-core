//! The capability property tests.

use proptest::prelude::*;

use crate::domain::Domain;

use super::Capability;

fn arbitrary_domain() -> impl Strategy<Value = &'static str> {
    prop::sample::select(
        Domain::ALL.iter().copied().map(Domain::as_str).collect::<Vec<_>>(),
    )
}

fn arbitrary_prefix() -> impl Strategy<Value = &'static str> {
    // A fixed word list rather than `"[a-z][a-z0-9-]{0,10}"`.
    //
    // Proptest's regex strategy has a shrink heuristic for a class that starts with `[a-z]`: it
    // offers the *uppercase* equivalent as a smaller value, so a minimised counterexample comes
    // back as `A` — which is not in the class and is not a valid prefix. The property would then
    // fail for a reason that has nothing to do with what it checks. A word list cannot be shrunk
    // into something outside the grammar.
    prop::sample::select(vec![
        "debug", "info", "list", "send", "fetch", "read", "write", "page", "open-url", "a",
    ])
}

/// A qualifier that is only valid after a prefix has been consumed.
///
/// The generator always emits a prefix when it emits a qualifier, because a qualifier's position
/// depends on there being a prefix before it: `log:api.x.com` is a *prefix* position, and a
/// hostname is not a prefix name. Two separately-drawn parts would produce that combination and the
/// property would fail on a string the grammar rightly refuses.
fn arbitrary_qualifier_segment() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "api.x.com",
        "api.y.com",
        "/data/**",
        "/cache/*",
        "@a",
        "page",
        "POST",
        "_plugin.@acme/chat.*",
    ])
}

/// Builds a capability that the grammar should accept.
fn arbitrary_capability() -> impl Strategy<Value = String> {
    (
        arbitrary_domain(),
        arbitrary_prefix(),
        proptest::option::of(arbitrary_qualifier_segment()),
        proptest::option::of(arbitrary_qualifier_segment()),
    )
        .prop_map(|(domain, prefix, first, second)| {
            let mut text = format!("{domain}:{prefix}");
            for qualifier in [first, second].into_iter().flatten() {
                text.push(':');
                text.push_str(qualifier);
            }
            text
        })
}


proptest! {
    /// Anything the generator builds parses, and survives a trip through `Display`. A capability
    /// that changed spelling on the way to storage would compare unequal to the grant the user
    /// approved.
    #[test]
    fn generated_capabilities_parse_and_round_trip(text in arbitrary_capability()) {
        let capability = Capability::parse(&text).expect("the generator makes valid capabilities");
        prop_assert_eq!(capability.as_str(), text.as_str());
        prop_assert_eq!(
            Capability::parse(&capability.to_string()).expect("re-parses"),
            capability,
        );
    }

    /// Parsing is total: arbitrary text either yields a capability or an error, and never panics.
    /// Capability strings come from plugin manifests, which are only semi-trusted.
    #[test]
    fn parsing_is_total(text in ".{0,300}") {
        if let Ok(capability) = Capability::parse(&text) {
            // Whatever parsed has a domain, which is what makes the bitmask a sound fast
            // negative.
            let _ = capability.domain();
            prop_assert!(Domain::ALL.contains(&capability.domain()));
        }
    }

    /// An exact capability matches itself and nothing else. This is the property the whole
    /// authorisation model rests on: if an exact grant matched a sibling, a plugin would hold a
    /// capability the user never approved.
    #[test]
    fn an_exact_capability_matches_only_itself(text in arbitrary_capability()) {
        let Ok(capability) = Capability::parse(&text) else {
            return Ok(());
        };
        prop_assume!(capability.is_exact());
        prop_assert!(capability.matches(&capability));
    }

    /// A pattern never matches a capability in another domain, whatever the rest says. The
    /// domain bitmask depends on this.
    #[test]
    fn matching_never_crosses_a_domain(
        pattern in arbitrary_capability(),
        candidate in arbitrary_capability(),
    ) {
        let (Ok(pattern), Ok(candidate)) = (Capability::parse(&pattern), Capability::parse(&candidate)) else {
            return Ok(());
        };
        if pattern.domain() != candidate.domain() {
            prop_assert!(!pattern.matches(&candidate));
        }
    }

    /// Matching is reflexive for patterns too: a pattern always covers itself, because its own
    /// literals match. A pattern that did not would be unusable as a grant.
    #[test]
    fn every_pattern_matches_itself(text in arbitrary_capability()) {
        let capability = Capability::parse(&text).expect("the generator makes valid capabilities");
        prop_assert!(capability.matches(&capability), "{} does not match itself", capability);
    }

    /// Matching is symmetric only for exact capabilities: two different patterns may each cover
    /// the other when they say the same thing.
    #[test]
    fn matching_an_exact_capability_is_a_subset_relation(
        pattern in arbitrary_capability(),
        candidate in arbitrary_capability(),
    ) {
        let (Ok(pattern), Ok(candidate)) = (Capability::parse(&pattern), Capability::parse(&candidate)) else {
            return Ok(());
        };
        prop_assume!(pattern.is_exact());
        // An exact pattern has no wildcards, so it can only match its own text.
        if pattern.matches(&candidate) {
            prop_assert_eq!(pattern.as_str(), candidate.as_str());
        }
    }
}
