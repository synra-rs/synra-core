//! The session registry's property tests.

use super::*;
use proptest::prelude::*;

use std::collections::HashMap;

use synra_capability::CapabilitySet;
use synra_protocol::PluginId;

fn plugin(text: &str) -> PluginId {
    PluginId::parse(text).expect("a valid plugin id")
}

/// A plugin id from a small set, so a property test can collide them.
fn arbitrary_plugin() -> impl Strategy<Value = PluginId> {
    prop_oneof![
        Just("@synra-plugin/chat"),
        Just("@synra-plugin/notes"),
        Just("@synra-plugin/mail"),
    ]
    .prop_map(plugin)
}

proptest! {
    /// A session admits a call only for the plugin it was issued to. The property the whole design exists for: no
    /// sequence of operations makes one plugin's token authorize another plugin's call.
    #[test]
    fn a_session_never_admits_another_plugin(
        issued_to in arbitrary_plugin(),
        claimed in arbitrary_plugin(),
        nonce in any::<u128>(),
        now in 0u64..(SESSION_LIFETIME_MS * 2),
    ) {
        let registry = UiSessionRegistry::new();
        registry.issue_with(&issued_to, "1.0.0", CapabilitySet::new(), nonce, 0);

        let result = registry.validate(nonce, &claimed, "1.0.0", now);
        if issued_to == claimed {
            // The only case that may succeed, and only while unexpired.
            if now < SESSION_LIFETIME_MS {
                prop_assert!(result.is_ok(), "{:?}", result.err());
            }
            else {
                prop_assert!(
                    matches!(result, Err(SessionRefusal::Expired { .. })),
                    "{:?}",
                    result.err(),
                );
            }
        }
        else {
            prop_assert!(
                matches!(result, Err(SessionRefusal::WrongPlugin { .. })),
                "{} admitted a call from {}: {:?}",
                issued_to,
                claimed,
                result.map(|session| session.plugin_id().to_string()),
            );
        }
    }

    /// A revoked nonce is refused for every plugin and every time, and the refusal is the same one an unknown
    /// nonce gets. A different answer would let a plugin probe for which plugins are installed.
    #[test]
    fn a_revoked_nonce_is_indistinguishable_from_an_unknown_one(
        plugin_id in arbitrary_plugin(),
        nonce in any::<u128>(),
        now in 0u64..1_000_000,
    ) {
        let registry = UiSessionRegistry::new();
        registry.issue_with(&plugin_id, "1.0.0", CapabilitySet::new(), nonce, 0);
        prop_assert!(registry.revoke(nonce));

        let revoked = registry.validate(nonce, &plugin_id, "1.0.0", now).map(|_| ());
        let unknown = registry.validate(nonce.wrapping_add(1), &plugin_id, "1.0.0", now).map(|_| ());
        prop_assert_eq!(&revoked, &unknown);
        prop_assert_eq!(revoked, Err(SessionRefusal::Unknown));
    }

    /// Whatever sequence of issues, revocations and sweeps happens, a live session always validates for its own
    /// plugin. A session that a caller cannot use is a page that stops working for no reason.
    #[test]
    fn a_live_session_always_validates(
        operations in proptest::collection::vec((any::<bool>(), arbitrary_plugin(), any::<u128>()), 0..40),
    ) {
        let registry = UiSessionRegistry::new();
        // Track what the registry should hold, so the property is about agreement rather than about a hard-coded
        // expectation.
        let mut live: HashMap<u128, PluginId> = HashMap::new();
        let mut at = 0u64;

        for (is_issue, plugin_id, nonce) in operations {
            at += 1;
            if is_issue {
                registry.issue_with(&plugin_id, "1.0.0", CapabilitySet::new(), nonce, at);
                // Issuing replaces the plugin's previous session, so its other entries go.
                live.retain(|_, owner| *owner != plugin_id);
                live.insert(nonce, plugin_id);
            }
            else {
                registry.revoke(nonce);
                live.remove(&nonce);
            }
        }

        for (nonce, plugin_id) in &live {
            prop_assert!(
                registry.validate(*nonce, plugin_id, "1.0.0", at + 1).is_ok(),
                "{} could not use its own live session",
                plugin_id,
            );
        }
        prop_assert_eq!(registry.len(), live.len());
    }

    /// Issuing never leaves more than one session per plugin, whatever order the calls come in. Two live sessions
    /// for one plugin is two pages able to call, and the second is one the user cannot see.
    #[test]
    fn issuing_leaves_one_session_per_plugin(
        issues in proptest::collection::vec((arbitrary_plugin(), any::<u128>()), 1..30),
    ) {
        let registry = UiSessionRegistry::new();
        let mut at = 0u64;
        for (plugin_id, nonce) in issues {
            at += 1;
            registry.issue_with(&plugin_id, "1.0.0", CapabilitySet::new(), nonce, at);
        }

        let active = registry.active_plugins();
        let mut sorted: Vec<String> = active.iter().map(ToString::to_string).collect();
        sorted.sort();
        sorted.dedup();
        prop_assert_eq!(sorted.len(), active.len(), "a plugin holds more than one session");
    }
}
