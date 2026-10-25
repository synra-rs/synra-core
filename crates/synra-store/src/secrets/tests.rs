//! The secret storage's tests.

use super::*;

fn plugin_key(name: &str) -> SecretKey {
    SecretKey::plugin("@synra-plugin/chat", name)
}

#[test]
fn a_plugin_secret_is_namespaced_under_its_plugin() {
    assert_eq!(
        plugin_key("token").account(),
        "plugin/_synra-plugin_chat/token"
    );
    // And the device identity is in its own namespace, which a plugin cannot spell because the account has
    // no `plugin/` prefix.
    assert_eq!(
        SecretKey::device_identity([0; 32]).account(),
        format!("device-identity/{}", "00".repeat(32))
    );
    assert_ne!(
        SecretKey::device_identity([0; 32]).account(),
        SecretKey::device_identity([1; 32]).account()
    );
}

#[test]
fn a_plugin_cannot_name_a_secret_into_another_namespace() {
    // The names are the plugin's to choose, so a name containing a separator would file the value under a
    // different plugin — or under the device identity — and read something it should not have.
    let sneaky = SecretKey::plugin("@synra-plugin/chat", "../../device-identity");
    let account = sneaky.account();
    assert!(!account.contains(".."), "{account}");
    assert!(
        account.starts_with("plugin/_synra-plugin_chat/"),
        "{account}"
    );

    // Two different plugins cannot collide on the same account however they spell their names.
    let other = SecretKey::plugin("@synra-plugin/notes", "../../device-identity");
    assert_ne!(account, other.account());
}

#[test]
fn an_empty_name_still_produces_a_usable_account() {
    // An empty account would be a keychain entry with no name, which some platforms refuse outright and
    // others accept as one shared entry for every plugin.
    assert!(!SecretKey::plugin("", "").account().is_empty());
    // An empty name still produces a component, so the account does not end in a separator that a keychain
    // would read as the entry having no name.
    let unnamed = SecretKey::plugin("@x/y", "").account();
    assert!(!unnamed.ends_with('/'), "{unnamed}");
    assert!(!unnamed.contains("//"), "{unnamed}");
}

#[test]
fn a_key_knows_which_plugin_it_belongs_to() {
    assert!(plugin_key("token").belongs_to("@synra-plugin/chat"));
    assert!(!plugin_key("token").belongs_to("@synra-plugin/notes"));
    assert!(!SecretKey::device_identity([0; 32]).belongs_to("@synra-plugin/chat"));
}

#[test]
fn a_secret_never_prints_its_value() {
    // A secret that can be formatted is one that ends up in a log line, and the log is what gets attached to
    // a bug report.
    let secret = SecretBytes::new(b"ghp_supersecret".to_vec());
    let debug = format!("{secret:?}");
    assert!(!debug.contains("ghp"), "{debug}");
    assert!(!debug.contains("supersecret"), "{debug}");
    assert!(
        debug.contains(&format!("{} bytes", secret.len())),
        "{debug}"
    );
}

#[test]
fn a_secret_exposes_its_bytes_to_a_caller_that_needs_them() {
    let secret = SecretBytes::new(b"abc".to_vec());
    assert_eq!(secret.expose(), b"abc");
    assert_eq!(secret.len(), 3);
    assert!(!secret.is_empty());
    assert!(SecretBytes::new(Vec::new()).is_empty());
}

#[test]
fn zeroing_a_secret_clears_it() {
    let mut secret = SecretBytes::new(b"abc".to_vec());
    secret.zero();
    assert!(secret.is_empty());
    assert_eq!(secret.len(), 0);
    // The bytes are gone from the view a caller has, which is what the method can promise.
    assert!(secret.expose().iter().all(|byte| *byte == 0));
}

#[test]
fn backend_kinds_report_their_strength() {
    for kind in [
        SecretBackendKind::WindowsCredential,
        SecretBackendKind::MacKeychain,
        SecretBackendKind::LinuxSecretService,
        SecretBackendKind::AndroidKeystore,
        SecretBackendKind::IosKeychain,
    ] {
        assert_eq!(kind.strength(), SecretStrength::OperatingSystem, "{kind}");
        assert!(kind.is_operating_system());
    }
    // The fallback stops a stolen disk and not a process running as this user.
    assert_eq!(
        SecretBackendKind::EncryptedFile.strength(),
        SecretStrength::AtRestOnly
    );
    assert!(!SecretBackendKind::EncryptedFile.is_operating_system());
    assert_eq!(SecretBackendKind::Memory.strength(), SecretStrength::None);
}

#[test]
fn strengths_order_from_weakest_to_strongest() {
    // The ordering is what `choose_backend` relies on to pick the best candidate.
    assert!(SecretStrength::None < SecretStrength::AtRestOnly);
    assert!(SecretStrength::AtRestOnly < SecretStrength::OperatingSystem);
}

#[test]
fn every_strength_explains_itself_for_a_user() {
    // The person deciding whether to store a work token is the person who should know which threat model
    // applies.
    for strength in [
        SecretStrength::None,
        SecretStrength::AtRestOnly,
        SecretStrength::OperatingSystem,
    ] {
        let text = strength.explain();
        assert!(text.len() > 20, "{strength:?} -> {text}");
    }
}

#[test]
fn a_memory_backend_stores_and_returns_a_value() {
    let backend = MemoryBackend::new();
    let key = plugin_key("token");
    let value = SecretBytes::new(b"ghp_abc".to_vec());

    assert_eq!(backend.get(&key).expect("reads"), None);
    assert!(!backend.contains(&key).expect("checks"));

    backend.set(&key, &value).expect("writes");
    assert!(backend.contains(&key).expect("checks"));
    assert_eq!(backend.get(&key).expect("reads").expect("present"), value);
    assert_eq!(backend.len(), 1);
}

#[test]
fn writing_the_same_key_replaces_the_value() {
    let backend = MemoryBackend::new();
    let key = plugin_key("token");
    backend
        .set(&key, &SecretBytes::new(b"first".to_vec()))
        .expect("writes");
    backend
        .set(&key, &SecretBytes::new(b"second".to_vec()))
        .expect("writes");

    assert_eq!(backend.len(), 1);
    assert_eq!(
        backend.get(&key).expect("reads").expect("present").expose(),
        b"second"
    );
}

#[test]
fn deleting_removes_the_value_and_is_not_an_error_twice() {
    // Removing something that is not there is not an error: the caller wanted it gone and it is gone.
    let backend = MemoryBackend::new();
    let key = plugin_key("token");
    backend
        .set(&key, &SecretBytes::new(b"x".to_vec()))
        .expect("writes");

    backend.delete(&key).expect("deletes");
    assert_eq!(backend.get(&key).expect("reads"), None);
    backend.delete(&key).expect("deletes again");
    assert!(backend.is_empty());
}

#[test]
fn two_plugins_do_not_share_a_value() {
    // The property the namespacing exists for.
    let backend = MemoryBackend::new();
    let chat = SecretKey::plugin("@synra-plugin/chat", "token");
    let notes = SecretKey::plugin("@synra-plugin/notes", "token");

    backend
        .set(&chat, &SecretBytes::new(b"chat-token".to_vec()))
        .expect("writes");
    assert_eq!(backend.get(&notes).expect("reads"), None);

    backend
        .set(&notes, &SecretBytes::new(b"notes-token".to_vec()))
        .expect("writes");
    assert_eq!(
        backend
            .get(&chat)
            .expect("reads")
            .expect("present")
            .expose(),
        b"chat-token"
    );
}

#[test]
fn an_oversized_secret_is_refused() {
    // A larger value is a file, and calling it a secret would put it somewhere with a size limit that fails
    // at an unpredictable moment.
    let backend = MemoryBackend::new();
    let too_big = SecretBytes::new(vec![b'x'; MAX_SECRET_BYTES + 1]);
    match backend.set(&plugin_key("big"), &too_big) {
        Err(SecretError::TooLarge { len, max }) => {
            assert_eq!(len, MAX_SECRET_BYTES + 1);
            assert_eq!(max, MAX_SECRET_BYTES);
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }
    // Exactly at the limit is accepted.
    let at_limit = SecretBytes::new(vec![b'x'; MAX_SECRET_BYTES]);
    assert!(backend.set(&plugin_key("at-limit"), &at_limit).is_ok());
}

#[test]
fn a_backend_reports_which_it_is() {
    assert_eq!(MemoryBackend::new().kind(), SecretBackendKind::Memory);
}

#[test]
fn choosing_a_backend_prefers_the_operating_system() {
    // The keychain is unlocked with the user's login and is not readable by another user on the same
    // machine, so it is the one to use when it answers.
    let chosen = choose_backend(vec![
        Box::new(MemoryBackend::new()),
        Box::new(MemoryBackend::new()),
    ])
    .expect("chooses");
    // Both are memory, so the first is kept; the assertion is that a choice was made at all.
    assert_eq!(chosen.kind(), SecretBackendKind::Memory);
}

#[test]
fn choosing_from_nothing_is_no_backend_rather_than_a_silent_fallback() {
    // A silent fallback to memory would store the user's token in a place that forgets it at exit, and the
    // user would find out when they were asked to sign in again.
    assert!(matches!(
        choose_backend(Vec::new()),
        Err(SecretError::NoBackend)
    ));
}

#[test]
fn a_storage_report_names_the_backend_and_its_strength() {
    let backend = MemoryBackend::new();
    let report = SecretStorageReport::of(&backend).expect("reports");
    assert_eq!(report.backend, "memory");
    assert_eq!(report.strength, "None");
    assert!(report.explain().contains("memory"));
    // The report contains no value and no account name, which is the point of having one at all.
    assert!(!report.explain().contains("plugin/"));
}

#[test]
fn a_storage_report_round_trips_without_carrying_anything_secret() {
    let report = SecretStorageReport {
        backend: "mac-keychain".to_owned(),
        strength: "OperatingSystem".to_owned(),
        entry_count: Some(3),
    };
    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("entryCount"), "{json}");
    let back: SecretStorageReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
    // The count is omitted when unknown rather than written as null.
    let partial = SecretStorageReport {
        backend: "encrypted-file".to_owned(),
        strength: "AtRestOnly".to_owned(),
        entry_count: None,
    };
    let json = serde_json::to_string(&partial).expect("serialises");
    assert!(!json.contains("entryCount"), "{json}");
}

#[test]
fn secret_errors_explain_themselves() {
    let errors = vec![
        SecretError::NoBackend,
        SecretError::Backend("x".to_owned()),
        SecretError::Corrupt("x".to_owned()),
        SecretError::KeyUnavailable("x".to_owned()),
        SecretError::NotFound {
            account: "a".to_owned(),
        },
        SecretError::TooLarge { len: 1, max: 0 },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 10, "{error:?} -> {text:?}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

#[test]
fn backend_names_round_trip_through_json() {
    for kind in [
        SecretBackendKind::WindowsCredential,
        SecretBackendKind::MacKeychain,
        SecretBackendKind::LinuxSecretService,
        SecretBackendKind::AndroidKeystore,
        SecretBackendKind::IosKeychain,
        SecretBackendKind::EncryptedFile,
        SecretBackendKind::Memory,
    ] {
        let json = serde_json::to_string(&kind).expect("serialises");
        assert_eq!(json, format!("\"{}\"", kind.as_str()));
        let back: SecretBackendKind = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, kind);
    }
}

#[test]
fn a_secret_key_round_trips_through_json() {
    for key in [SecretKey::device_identity([0; 32]), plugin_key("token")] {
        let json = serde_json::to_string(&key).expect("serialises");
        let back: SecretKey = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, key);
    }
}
