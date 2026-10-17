//! The consent decision: one row per declared capability, and what "trusted" means.

use super::*;

const MANIFEST: &str = r#"{
    "id": "@acme/chat",
    "version": "1.2.3",
    "title": "Chat",
    "publisher": { "id": "@acme" },
    "sdk": { "min": "0.1.0" },
    "wit": "synra:plugin@0.1.0",
    "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } },
    "capabilities": [{ "cap": "log:*" }, { "cap": "device:list" }]
}"#;

fn manifest() -> Manifest {
    Manifest::from_json(MANIFEST).expect("the fixture is a manifest")
}

#[test]
fn every_declared_capability_gets_a_row() {
    // ★ A row per declaration rather than only the granted ones. An absent row means "no decision", and the loader
    // compares the digest of every decision on record against the manifest — a plugin with a decision missing one
    // capability would be a plugin whose decision was about a different document.
    let decision = decide(&manifest(), MANIFEST, &["log:*".to_owned()]).expect("a decision");

    assert_eq!(decision.rows().len(), 2);
    assert_eq!(
        decision.pairs(),
        vec![("log:*".to_owned(), true), ("device:list".to_owned(), false)],
        "the manifest's own order"
    );
    assert_eq!(decision.granted().collect::<Vec<_>>(), ["log:*"]);
    assert_eq!(decision.denied().collect::<Vec<_>>(), ["device:list"]);
}

#[test]
fn one_granted_capability_is_approval() {
    // ★ The rule the two hosts disagreed about. Partial consent **runs** the plugin with the subset: that is what the
    // capability gate is for, and the design's `Consent::is_partial` exists because it is a supported outcome.
    let decision = decide(&manifest(), MANIFEST, &["log:*".to_owned()]).expect("a decision");

    assert!(decision.trusted(), "one granted capability is approval");
}

#[test]
fn denying_everything_is_not_trust() {
    let decision = decide(&manifest(), MANIFEST, &[]).expect("a decision");

    assert!(decision.rows().iter().all(|row| !row.granted()));
    assert!(!decision.trusted(), "a full refusal is a refusal, not an approval");
    assert_eq!(decision.granted().count(), 0);
}

#[test]
fn a_grant_the_plugin_never_asked_for_is_refused() {
    match decide(&manifest(), MANIFEST, &["device:send".to_owned()]) {
        Err(ConsentError::UnknownCapability { capability }) => assert_eq!(capability, "device:send"),
        other => panic!("expected an unknown-capability refusal, got {other:?}"),
    }
}

#[test]
fn the_digest_is_of_the_text_the_decision_was_made_about() {
    // A capability added after signing — or after consent — makes this a different document, which is why the digest
    // travels with every row.
    let first = decide(&manifest(), MANIFEST, &[]).expect("a decision");
    let edited = MANIFEST.replace("\"log:*\"", "\"log:info\"");
    let second = decide(&Manifest::from_json(&edited).expect("a manifest"), &edited, &[]).expect("a decision");

    assert_eq!(first.digest(), manifest_digest(MANIFEST));
    assert_ne!(first.digest(), second.digest(), "an edited manifest is a different document");
}
