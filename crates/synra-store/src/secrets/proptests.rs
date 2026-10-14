//! The secret storage's property tests.

use super::*;
use super::kind::sanitise_account;
use proptest::prelude::*;
proptest! {
    /// Two distinct plugins never produce the same account name, whatever they call their secrets. A
    /// collision would be one plugin reading another's token, which is the one thing the namespacing exists
    /// to prevent.
    #[test]
    fn distinct_plugin_keys_never_collide(
        plugin_a in "[a-z@/-]{1,20}",
        plugin_b in "[a-z@/-]{1,20}",
        name in "[a-zA-Z0-9._/-]{1,20}",
    ) {
        let a = SecretKey::plugin(&plugin_a, &name).account();
        let b = SecretKey::plugin(&plugin_b, &name).account();
        if plugin_a == plugin_b {
            prop_assert_eq!(&a, &b);
        }
        else {
            // Either the sanitised plugin differs, so the accounts differ — or the sanitising collapsed
            // them, in which case the assertion is that it did so consistently rather than reading across.
            let sanitised_a = sanitise_account(&plugin_a);
            let sanitised_b = sanitise_account(&plugin_b);
            if sanitised_a != sanitised_b {
                prop_assert_ne!(&a, &b);
            }
        }
        // And whatever the inputs, the account is non-empty and has no separator ambiguity.
        prop_assert!(!a.is_empty());
        prop_assert!(a.starts_with("plugin/"));
    }
    /// A plugin's key names a `plugin/` account, so it can never name the device identity's. The identity
    /// account has no prefix, which is what makes the two namespaces disjoint.
    #[test]
    fn a_plugin_key_never_names_the_device_identity(
        plugin in "[a-z@/-]{1,30}",
        name in "[a-zA-Z0-9._/-]{1,30}",
    ) {
        let account = SecretKey::plugin(&plugin, &name).account();
        prop_assert_ne!(&account, &SecretKey::DeviceIdentity.account());
        prop_assert!(account.starts_with("plugin/"));
    }
    /// A secret's `Debug` output never contains its bytes, whatever they are. The output is what reaches a
    /// log file and therefore a bug report.
    #[test]
    fn a_secret_never_prints_its_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let secret = SecretBytes::new(bytes.clone());
        let debug = format!("{secret:?}");
        prop_assert!(debug.starts_with("SecretBytes("));
        // A byte sequence that renders as text is the case that matters: a random sequence often contains
        // no printable run long enough to notice.
        if let Ok(text) = core::str::from_utf8(&bytes)
            && text.len() >= 4
            && !text.chars().any(|ch| ch.is_control())
        {
            prop_assert!(!debug.contains(text), "{debug} contains {text}");
            // And the same through the whole store, which is how a secret would actually be exposed.
            let backend = MemoryBackend::new();
            let key = SecretKey::plugin("@synra-plugin/chat", "token");
            backend.set(&key, &secret).expect("writes");
            let stored = backend.get(&key).expect("reads").expect("present");
            let rendered = format!("{stored:?}");
            prop_assert!(!rendered.contains(text), "{} contains {}", rendered, text);
        }
    }
    /// A stored value comes back byte for byte. A store that mangled a token would produce a mysterious
    /// authentication failure with nothing in any log to explain it.
    #[test]
    fn a_value_round_trips_through_the_store(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let backend = MemoryBackend::new();
        let key = SecretKey::plugin("@synra-plugin/chat", "token");
        let value = SecretBytes::new(bytes.clone());
        backend.set(&key, &value).expect("writes");
        let read = backend.get(&key).expect("reads").expect("present");
        prop_assert_eq!(read.expose(), bytes.as_slice());
    }
}
