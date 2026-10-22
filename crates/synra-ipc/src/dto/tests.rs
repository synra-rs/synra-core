//! The interface shapes' tests.

use core::str::FromStr;

use synra_protocol::{DeviceId, IntentId, PluginId, TransferId};

use super::*;


/// A device id from a fixed string.
///
/// Fixed so a round-trip test compares the *same* value rather than two fresh ones: a test that generated a new
/// id on each side would fail while proving nothing. Built by parsing rather than from a raw UUID because the
/// newtypes keep their inner value private, which is the point of them.
fn fixed_device_id(text: &str) -> DeviceId {
    DeviceId::from_str(text).expect("a valid uuid")
}

/// A transfer id from a fixed string.
fn fixed_transfer_id(text: &str) -> TransferId {
    TransferId::from_str(text).expect("a valid uuid")
}

/// A plugin id.
///
/// The protocol validates a plugin id rather than accepting a bare string, so a test that wants one has to
/// build a valid one — which is the same constraint the manifest loader has.
fn plugin_id() -> PluginId {
    PluginId::parse("@synra-plugin/chat").expect("a valid plugin id")
}

/// A transfer id.
fn transfer_id() -> TransferId {
    TransferId::new()
}

/// An intent id.
fn intent_id() -> IntentId {
    IntentId::new()
}

fn card() -> DeviceCard {
    DeviceCard {
        device_id: DeviceId::new(),
        display_name: "My PC".to_owned(),
        platform: "linux".to_owned(),
        online: true,
        paired: true,
        blocked: false,
        last_seen_ms: 1_000,
        address: None,
        transfer: None,
    }
}

// ── Device cards ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_card_separates_online_from_paired() {
    // Different questions: a paired device that is offline is one the user can send to later, and an unpaired
    // device that is online is one they have to pair with first.
    let paired_offline = DeviceCard { online: false, paired: true, ..card() };
    assert!(paired_offline.paired && !paired_offline.online);

    let seen_online = DeviceCard { online: true, paired: false, ..card() };
    assert!(seen_online.online && !seen_online.paired);
}

#[test]
fn an_absent_address_is_omitted_rather_than_null() {
    let json = serde_json::to_string(&card()).expect("serialises");
    assert!(!json.contains("address"), "{json}");
    assert!(!json.contains("transfer"), "{json}");
}

#[test]
fn a_card_round_trips() {
    let card = DeviceCard {
        address: Some("192.168.1.5:32100".to_owned()),
        transfer: Some(TransferSummary {
            transfer_id: transfer_id(),
            direction: "send".to_owned(),
            progress: 0.25,
        }),
        ..card()
    };
    let json = serde_json::to_string(&card).expect("serialises");
    assert!(json.contains("lastSeenMs"), "{json}");
    let back: DeviceCard = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, card);
}

#[test]
fn a_devices_snapshot_carries_the_identity_too() {
    // So the screen does not need a second call, which is what the design document means by a snapshot being
    // everything the screen needs in one value.
    let snapshot = DevicesSnapshot {
        identity: IdentitySnapshot {
            device_id: DeviceId::new(),
            display_name: "Laptop".to_owned(),
            platform: "linux".to_owned(),
            kernel_version: "0.1.0".to_owned(),
            name_is_default: true,
        },
        devices: vec![card()],
        scanning: None,
    };
    let json = serde_json::to_string(&snapshot).expect("serialises");
    let back: DevicesSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, snapshot);
    // A device with no identity is one the interface cannot show a "this is you" marker for.
    assert_eq!(back.identity.device_id, snapshot.identity.device_id);
}

#[test]
fn scan_options_default_to_a_short_inclusive_scan() {
    let options = ScanOptions::default();
    assert!(!options.cached_only);
    assert!(!options.include_paired);
    assert_eq!(options.timeout_ms, None);
}

#[test]
fn scan_options_refuse_an_unknown_field() {
    // The boundary refuses unknown fields so a mistyped option is an error rather than a silently ignored
    // setting, which is the same rule the wire protocol's envelopes follow.
    let json = r#"{ "includePaired": true, "cachedOnly": false, "mystery": 1 }"#;
    assert!(serde_json::from_str::<ScanOptions>(json).is_err());
}

// ── Intents ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_intent_source_carries_only_what_its_kind_needs() {
    // A single struct with both text and paths optional would let the interface send a share with neither.
    let share = IntentSourceDto::Share { text: "hi".to_owned(), title: None };
    assert_eq!(share.kind(), "share");

    let files = IntentSourceDto::ShareFiles { paths: vec!["/a".to_owned()] };
    assert_eq!(files.kind(), "shareFiles");

    assert_eq!(IntentSourceDto::Clipboard.kind(), "clipboard");

    let action = IntentSourceDto::PluginAction {
        plugin_id: plugin_id(),
        action: "send".to_owned(),
        args: serde_json::json!({}),
    };
    assert_eq!(action.kind(), "pluginAction");
}

#[test]
fn an_intent_source_is_tagged_on_the_wire() {
    let json = serde_json::to_string(&IntentSourceDto::Clipboard).expect("serialises");
    assert!(json.contains("\"kind\":\"clipboard\""), "{json}");
    let back: IntentSourceDto = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, IntentSourceDto::Clipboard);
}

#[test]
fn an_absent_title_is_omitted() {
    let json = serde_json::to_string(&IntentSourceDto::Share {
        text: "hi".to_owned(),
        title: None,
    })
    .expect("serialises");
    assert!(!json.contains("title"), "{json}");
}

#[test]
fn every_intent_source_carries_something_the_user_would_not_want_logged() {
    // The kernel records the kind and never the content, and this is what the diagnostics screen uses to say
    // so. A source that reported `false` here would be one the interface might echo.
    for source in [
        IntentSourceDto::Share { text: "x".to_owned(), title: None },
        IntentSourceDto::ShareFiles { paths: vec!["/a".to_owned()] },
        IntentSourceDto::Clipboard,
        IntentSourceDto::PluginAction {
            plugin_id: plugin_id(),
            action: "x".to_owned(),
            args: serde_json::json!(null),
        },
    ] {
        assert!(source.carries_user_content(), "{:?}", source.kind());
    }
}

#[test]
fn a_decision_says_whether_it_accepts() {
    assert!(IntentDecisionDto::AcceptDefault.is_accepting());
    assert!(IntentDecisionDto::Accept { device_id: DeviceId::new() }.is_accepting());
    assert!(!IntentDecisionDto::Decline { reason: None }.is_accepting());
}

#[test]
fn a_decision_is_tagged_on_the_wire() {
    for decision in [
        IntentDecisionDto::AcceptDefault,
        IntentDecisionDto::Decline { reason: Some("no".to_owned()) },
    ] {
        let json = serde_json::to_string(&decision).expect("serialises");
        assert!(json.contains("\"decision\""), "{json}");
        let back: IntentDecisionDto = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, decision);
    }
}

#[test]
fn an_intent_snapshot_round_trips() {
    let snapshot = IntentSnapshot {
        intent_id: intent_id(),
        trace_id: synra_protocol::ids::TraceId::new(),
        state: "awaiting_decision".to_owned(),
        plugin_id: Some(plugin_id()),
        candidates: vec![IntentCandidate {
            plugin_id: plugin_id(),
            title: "Chat".to_owned(),
            device_id: DeviceId::new(),
            online: true,
        }],
        prompt: Some(IntentPrompt {
            message: "intent.confirm".to_owned(),
            params: serde_json::json!({ "title": "Chat" }),
            options: vec!["accept".to_owned(), "decline".to_owned()],
        }),
        error: None,
        retry: Some(IntentRetry { attempts: 2, max_attempts: 8, gave_up: false, next_at_ms: Some(90_000) }),
        started_at_ms: 1_000,
    };
    let json = serde_json::to_string(&snapshot).expect("serialises");
    let back: IntentSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, snapshot);
}

// ── Transfers ─────────────────────────────────────────────────────────────────────────────────

fn transfer(received: u64, total: u64) -> TransferSnapshot {
    TransferSnapshot {
        transfer_id: fixed_transfer_id("018f2b40-0000-7000-8000-000000000001"),
        peer_device: fixed_device_id("018f2b40-0000-7000-8000-000000000002"),
        peer_name: "My PC".to_owned(),
        direction: "send".to_owned(),
        kind: "attachment".to_owned(),
        state: "transferring".to_owned(),
        file_name: "report.pdf".to_owned(),
        received_bytes: received,
        total_bytes: total,
        blocks_done: 0,
        blocks_total: 0,
        abort_reason: None,
        started_at_ms: 0,
    }
}

#[test]
fn progress_is_a_fraction() {
    assert_eq!(transfer(0, 100).progress(), 0.0);
    assert_eq!(transfer(50, 100).progress(), 0.5);
    assert_eq!(transfer(100, 100).progress(), 1.0);
}

#[test]
fn progress_of_an_empty_transfer_is_zero_rather_than_nan() {
    // A `NaN` in a progress bar renders at whatever width the platform's arithmetic produces.
    assert_eq!(transfer(0, 0).progress(), 0.0);
    assert!(transfer(0, 0).progress().is_finite());
}

#[test]
fn progress_never_exceeds_one() {
    // A resumed transfer can report more received than the total it was created with, because the file changed
    // size on the sender. A progress of 1.4 would render outside its bar.
    assert_eq!(transfer(140, 100).progress(), 1.0);
}

#[test]
fn a_transfer_round_trips() {
    let json = serde_json::to_string(&transfer(1, 2)).expect("serialises");
    assert!(json.contains("transferId"), "{json}");
    assert!(json.contains("blocksTotal"), "{json}");
    let back: TransferSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, transfer(1, 2));
}

#[test]
fn a_send_request_round_trips() {
    let request = SendFileRequest {
        to: DeviceId::new(),
        path: "/tmp/x.pdf".to_owned(),
        context_id: Some("c1".to_owned()),
    };
    let json = serde_json::to_string(&request).expect("serialises");
    assert!(json.contains("contextId"), "{json}");
    let back: SendFileRequest = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, request);
}

// ── Plugins ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_plugin_snapshot_reports_its_state_rather_than_leaving_it_to_be_derived() {
    // A plugin that is enabled but faulted is a state the user has to be told about, and deriving it in the
    // interface would mean two implementations of the same rule.
    let plugin = PluginSnapshot {
        plugin_id: plugin_id(),
        data_path: "/tmp/synra/plugin-data/chat".to_owned(),
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
    };
    assert!(plugin.enabled);
    assert_eq!(plugin.state, "faulted");
    assert!(plugin.has_ui, "the card cannot offer a page it was told the plugin lacks");

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
        InstallSourceDto::Path { path: "/tmp/x.synra".to_owned() },
        InstallSourceDto::Registry { plugin_id: plugin_id(), version: None },
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
    for forbidden in ["\"payload\"", "\"content\"", "\"args\"", "\"body\"", "\"url\"", "\"text\""] {
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
            error: super::super::IpcError::unknown(synra_protocol::ErrorCode::DeviceOffline),
        }],
    };
    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("\"updated\":2"), "{json}");
    assert!(json.contains("\"unchanged\":1"), "{json}");
    let back: SyncReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}

// ── Configuration ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_patch_sets_and_unsets_keys() {
    let mut patch = ConfigPatch::default();
    patch.set.insert("ui.theme".to_owned(), serde_json::json!("dark"));
    patch.unset.push("ui.locale".to_owned());

    assert!(!patch.is_empty());
    assert_eq!(patch.len(), 2);
    assert_eq!(patch.has_conflict(), None);
}

#[test]
fn an_empty_patch_says_so() {
    // So the shell can refuse a no-op call rather than waking the kernel for it.
    assert!(ConfigPatch::default().is_empty());
    assert_eq!(ConfigPatch::default().len(), 0);
}

#[test]
fn a_key_that_is_both_set_and_unset_is_reported() {
    // Refused rather than resolved by precedence: the caller meant one of the two, and picking for them
    // produces a setting that is the opposite of what they asked for half the time.
    let mut patch = ConfigPatch::default();
    patch.set.insert("ui.theme".to_owned(), serde_json::json!("dark"));
    patch.unset.push("ui.theme".to_owned());
    assert_eq!(patch.has_conflict(), Some("ui.theme"));
}

#[test]
fn a_config_patch_round_trips() {
    let mut patch = ConfigPatch::default();
    patch.set.insert("a".to_owned(), serde_json::json!(1));
    patch.unset.push("b".to_owned());
    let json = serde_json::to_string(&patch).expect("serialises");
    let back: ConfigPatch = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, patch);
}

#[test]
fn a_config_snapshot_carries_which_keys_were_overridden() {
    // So the settings screen can mark a value the user changed from the default.
    let snapshot = ConfigSnapshot {
        values: serde_json::json!({ "ui.theme": "dark" }),
        overridden: vec!["ui.theme".to_owned()],
    };
    let json = serde_json::to_string(&snapshot).expect("serialises");
    assert!(json.contains("overridden"), "{json}");
    let back: ConfigSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, snapshot);
}

// ── Diagnostics ───────────────────────────────────────────────────────────────────────────────

#[test]
fn a_diagnostic_export_defaults_to_the_least_intrusive_bundle() {
    // The optional sections are the ones that name the plugins the user runs and the ones most likely to
    // contain something they did not intend to share.
    let options = DiagExportOptions::default();
    assert!(!options.include_audit);
    assert!(!options.include_debug_logs);
    assert_eq!(options.log_lines, None);
}

#[test]
fn a_diagnostic_export_refuses_an_unknown_field() {
    // A mistyped option would otherwise silently export the defaults, which is the sort of thing a user
    // discovers by reading the file they just sent.
    let json = r#"{ "includeAudit": true, "mystery": 1 }"#;
    assert!(serde_json::from_str::<DiagExportOptions>(json).is_err());
}

// ── Forbidden content ─────────────────────────────────────────────────────────────────────────

#[test]
fn no_snapshot_carries_a_field_named_for_content() {
    // The design document's rule, checked over the shapes rather than over one of them: a snapshot is a
    // picture, and a picture that includes the user's text is one that ends up in a diagnostic bundle.
    let snapshots: Vec<serde_json::Value> = vec![
        serde_json::to_value(DevicesSnapshot {
            identity: IdentitySnapshot {
                device_id: DeviceId::new(),
                display_name: "L".to_owned(),
                platform: "linux".to_owned(),
                kernel_version: "0".to_owned(),
                name_is_default: false,
            },
            devices: vec![card()],
            scanning: None,
        })
        .expect("serialises"),
        serde_json::to_value(IntentSnapshot {
            intent_id: intent_id(),
            trace_id: synra_protocol::ids::TraceId::new(),
            state: "pending".to_owned(),
            plugin_id: None,
            candidates: Vec::new(),
            prompt: None,
            error: None,
            retry: None,
            started_at_ms: 0,
        })
        .expect("serialises"),
        serde_json::to_value(transfer(0, 1)).expect("serialises"),
    ];

    for value in snapshots {
        let json = serde_json::to_string(&value).expect("serialises");
        for forbidden in ["\"payload\"", "\"body\"", "\"text\"", "\"content\""] {
            assert!(!json.contains(forbidden), "{forbidden} appeared in {json}");
        }
    }
}