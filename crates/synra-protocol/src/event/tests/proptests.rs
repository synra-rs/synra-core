use proptest::prelude::*;

use crate::ids::PluginId;

use super::super::EventName;

fn slug_text() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,20}".prop_map(|text| {
        let trimmed = text.trim_end_matches('-');
        if trimmed.is_empty() { "a".to_owned() } else { trimmed.to_owned() }
    })
}

fn logical_text() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z][a-z0-9]{0,8}", 1..4).prop_map(|parts| parts.join("."))
}

proptest! {
    /// Anything a constructor accepts parses back to itself and reports the owner it was given.
    #[test]
    fn plugin_events_name_their_owner(slug in slug_text(), logical in logical_text()) {
        let slug = PluginId::parse(&format!("@acme/{slug}")).expect("valid generated identity");
        let name = EventName::plugin(&slug, &logical).expect("builds");
        prop_assert!(name.is_plugin());
        prop_assert_eq!(name.plugin_scope().map(|(owner, _)| owner), Some(slug.as_str()));
        prop_assert_eq!(name.check_emittable_by(&slug), Ok(()));
    }

    /// A plugin can never emit under a namespace it does not own, whatever the names are.
    #[test]
    fn foreign_namespaces_are_always_refused(
        owner in slug_text(),
        other in slug_text(),
        logical in logical_text(),
    ) {
        prop_assume!(owner != other);
        let owner = PluginId::parse(&format!("@acme/{owner}")).expect("valid");
        let other = PluginId::parse(&format!("@acme/{other}")).expect("valid");
        let name = EventName::plugin(&owner, &logical).expect("builds");
        prop_assert!(name.check_emittable_by(&other).is_err());
    }

    /// Arbitrary text either parses or is rejected. It never panics, and a parsed name survives
    /// a trip through the wire format unchanged.
    #[test]
    fn parse_is_total_and_round_trips(text in ".{0,140}") {
        if let Ok(name) = EventName::parse(&text) {
            // The wire form is the input, unchanged.
            prop_assert_eq!(name.as_str(), text.as_str());

            let json = serde_json::to_string(&name).expect("serialises");
            let back: EventName = serde_json::from_str(&json).expect("deserialises");
            prop_assert_eq!(back, name);
        }
    }
}
