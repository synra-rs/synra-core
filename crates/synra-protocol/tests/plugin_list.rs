//! The plugin list a device answers with, as it appears on the wire.

// A test that cannot unwrap its own fixture reports its bug as a mystery, and the same allow is on the other integration
// tests in this workspace.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use synra_protocol::ids::PluginId;
use synra_protocol::session::{PluginList, PluginSummary};

/// Two entries: one complete, one that has nothing but its identifier.
fn list() -> PluginList {
    PluginList {
        plugins: vec![
            PluginSummary {
                plugin_id: PluginId::parse("@acme/hello").expect("an id"),
                version: Some("1.2.3".to_owned()),
                digest: Some("sha256-abc".to_owned()),
                active: true,
            },
            PluginSummary {
                plugin_id: PluginId::parse("@acme/quiet").expect("an id"),
                version: None,
                digest: None,
                active: false,
            },
        ],
    }
}

#[test]
fn a_plugin_list_round_trips() {
    let json = serde_json::to_string(&list()).expect("it serialises");
    let back: PluginList = serde_json::from_str(&json).expect("it deserialises");

    assert_eq!(back, list(), "what a peer sent is what this side reads");
}

#[test]
fn an_absent_version_or_digest_is_omitted_rather_than_sent_as_null() {
    // ★ "This device has no digest" and "it has one and did not say" are different facts, and `null` blurs them: a receiver
    // that treated a null digest as a digest would decide two devices hold the same bytes when one of them never said.
    let json = serde_json::to_string(&list()).expect("it serialises");

    assert!(!json.contains("null"), "no nulls on the wire: {json}");
    assert!(!json.contains("\"digest\":null"), "the digest is absent, not null: {json}");
}

#[test]
fn a_record_that_predates_a_field_still_decodes() {
    // ★ The `default` on both optional fields is what makes an older peer's answer readable. Without it, a device on an older
    // build would be one this one cannot ask — and the failure would look like a broken plugin list rather than a missing field.
    let older = r#"{"plugins":[{"pluginId":"@acme/hello","active":true}]}"#;

    let decoded: PluginList = serde_json::from_str(older).expect("it decodes");

    assert_eq!(decoded.plugins.len(), 1);
    assert_eq!(decoded.plugins[0].version, None);
    assert_eq!(decoded.plugins[0].digest, None);
}
