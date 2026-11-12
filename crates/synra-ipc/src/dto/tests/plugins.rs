use synra_protocol::{DeviceId, PluginId};

use super::super::{
    AuditEntryDto, CatalogItem, InstallSourceDto, PluginSnapshot, SyncFailure, SyncReport,
    UpdateInfo,
};
use super::plugin_id;

#[test]
fn a_plugin_snapshot_reports_its_state_rather_than_leaving_it_to_be_derived() {
    // A plugin that is enabled but faulted is a state the user has to be told about, and deriving it in the
    // interface would mean two implementations of the same rule.
    let plugin = PluginSnapshot {
        plugin_id: plugin_id(),
        data_path: "/tmp/synra/plugin-data/chat".to_owned(),
        local_source: false,
        title: "Chat".to_owned(),
        description: None,
        version: "1.0.0".to_owned(),
        publisher: "synra-official".to_owned(),
        enabled: true,
        state: "faulted".to_owned(),
        state_reason: None,
        hybrid: true,
        has_ui: true,
        health: None,
        requested: vec!["log:*".to_owned()],
        granted: vec!["log:*".to_owned()],
        denied: Vec::new(),
        update: None,
        update_checked_at_ms: Some(123),
    };
    assert!(plugin.enabled);
    assert_eq!(plugin.state, "faulted");
    assert!(
        plugin.has_ui,
        "the card cannot offer a page it was told the plugin lacks"
    );
    assert_eq!(
        serde_json::to_value(&plugin).expect("serialises")["updateCheckedAtMs"],
        123
    );

    let json = serde_json::to_string(&plugin).expect("serialises");
    let back: PluginSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, plugin);
}

#[test]
fn an_update_reports_whether_it_needs_new_consent() {
    // "An update is available" is a routine message; "this update wants a new permission" is a decision, and
    // the interface says different things for each.
    let routine = UpdateInfo {
        plugin_id: PluginId::parse("@acme/hello").expect("a plugin id"),
        version: "1.0.1".to_owned(),
        needs_new_consent: false,
        added_capabilities: Vec::new(),
    };
    assert!(!routine.needs_new_consent);

    let needing = UpdateInfo {
        plugin_id: PluginId::parse("@acme/hello").expect("a plugin id"),
        version: "2.0.0".to_owned(),
        needs_new_consent: true,
        added_capabilities: vec!["platform:simulate-keys".to_owned()],
    };
    assert!(needing.needs_new_consent);
    assert_eq!(needing.added_capabilities.len(), 1);
}

#[test]
fn a_catalog_item_carries_a_capability_count_rather_than_the_list() {
    // The catalogue response is a search result, and a result carrying every plugin's full permission list
    // would be the largest thing on the wire for the least read part of it.
    let item = CatalogItem {
        plugin_id: plugin_id(),
        title: "Chat".to_owned(),
        description: None,
        version: "1.0.0".to_owned(),
        publisher: "synra-official".to_owned(),
        capability_count: 7,
        installed: false,
    };
    let json = serde_json::to_string(&item).expect("serialises");
    assert!(json.contains("capabilityCount"), "{json}");
    assert!(!json.contains("capabilities"), "{json}");
}

#[test]
fn an_install_source_is_tagged() {
    for source in [
        InstallSourceDto::Path {
            path: "/tmp/x.synra".to_owned(),
        },
        InstallSourceDto::Registry {
            plugin_id: plugin_id(),
            version: None,
        },
    ] {
        let json = serde_json::to_string(&source).expect("serialises");
        assert!(json.contains("\"source\""), "{json}");
        let back: InstallSourceDto = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, source);
    }
}

#[test]
fn an_audit_entry_has_no_field_for_content() {
    // The design document forbids payloads in an audit record, and the absence of a field is what enforces it
    // rather than a rule someone has to remember.
    let entry = AuditEntryDto {
        at_ms: 1,
        capability: "platform:open-url".to_owned(),
        allowed: false,
        reason: Some("not granted".to_owned()),
        elapsed_ms: None,
        trace_id: None,
    };
    let json = serde_json::to_string(&entry).expect("serialises");
    // Quoted, so a *field* named for content is caught and a capability whose value happens to contain the
    // word — `platform:open-url` contains `url` — is not a false positive.
    for forbidden in [
        "\"payload\"",
        "\"content\"",
        "\"args\"",
        "\"body\"",
        "\"url\"",
        "\"text\"",
    ] {
        assert!(!json.contains(forbidden), "{forbidden} appeared in {json}");
    }
}

#[test]
fn a_sync_report_separates_updated_from_unchanged() {
    // The interface says different things for each: "3 devices updated" and "already up to date" are not the
    // same message.
    let report = SyncReport {
        updated: 2,
        unchanged: 1,
        failures: vec![SyncFailure {
            device_id: DeviceId::new(),
            error: crate::IpcError::unknown(synra_protocol::ErrorCode::DeviceOffline),
        }],
    };
    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("\"updated\":2"), "{json}");
    assert!(json.contains("\"unchanged\":1"), "{json}");
    let back: SyncReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}
