use core::str::FromStr;

use synra_protocol::{DeviceId, IntentId, PluginId, TransferId};

use super::super::{KernelEvent, KernelEventEnvelope};
use crate::dto::{DeviceCard, IdentitySnapshot, ScanState};

fn card(id: &str) -> DeviceCard {
    DeviceCard {
        device_id: DeviceId::from_str(id).expect("a valid uuid"),
        display_name: "My PC".to_owned(),
        platform: "linux".to_owned(),
        online: true,
        paired: true,
        blocked: false,
        last_seen_ms: 0,
        address: None,
        transfer: None,
    }
}

#[test]
fn an_event_is_tagged_on_the_wire() {
    // `#[serde(tag = "type", content = "payload")]` is what makes the interface's switch possible: an externally
    // tagged enum would arrive as `{ "DeviceCardUpdated": { … } }`, and a variant name is not a stable wire
    // format.
    let event =
        KernelEvent::DeviceCardUpdated(Box::new(card("018f2b40-0000-7000-8000-000000000001")));
    let json = serde_json::to_string(&event).expect("serialises");
    assert!(json.contains("\"type\":\"deviceCardUpdated\""), "{json}");
    assert!(json.contains("\"payload\""), "{json}");

    let back: KernelEvent = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, event);
}

#[test]
fn an_event_with_no_payload_carries_only_its_type() {
    let event = KernelEvent::DeviceRemoved {
        device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001")
            .expect("a valid uuid"),
    };
    let json = serde_json::to_string(&event).expect("serialises");
    let back: KernelEvent = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, event);
}

#[test]
fn every_event_has_a_kind_for_a_log_line() {
    for event in [
        KernelEvent::DeviceCardUpdated(Box::new(card("018f2b40-0000-7000-8000-000000000001"))),
        KernelEvent::DeviceRemoved {
            device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001")
                .expect("a valid uuid"),
        },
        KernelEvent::ScanUpdated(Box::new(ScanState {
            scan_id: "s1".to_owned(),
            elapsed_ms: 100,
            total_ms: 2_500,
            found: 3,
        })),
        KernelEvent::PairingUpdated(Box::new(crate::PairingSnapshot::idle())),
        KernelEvent::TransferFinished {
            transfer_id: TransferId::new(),
        },
        KernelEvent::IntentFinished {
            intent_id: IntentId::new(),
        },
        KernelEvent::PluginInstallProgress {
            plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
            progress: 0.5,
            stage: "verifying".to_owned(),
        },
        KernelEvent::PluginHealthChanged {
            plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
            health: "degraded".to_owned(),
            explanation: "plugin.health.degraded".to_owned(),
        },
        KernelEvent::PluginConsentRequested {
            plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
            title: "Chat".to_owned(),
            capabilities: vec!["log:*".to_owned()],
            manifest_digest: "d".to_owned(),
        },
        KernelEvent::LogLine {
            level: "warn".to_owned(),
            line: "x".to_owned(),
        },
        KernelEvent::Notice {
            message: "notice.something".to_owned(),
            params: serde_json::json!({}),
        },
    ] {
        let kind = event.kind();
        assert!(!kind.is_empty(), "{event:?}");
        assert!(!kind.contains('_'), "{kind} is not camelCase");
        // The kind is what the wire tag says, which is what makes it usable as the switch key.
        let json = serde_json::to_value(&event).expect("serialises");
        assert_eq!(json["type"], kind, "{event:?}");
    }
}

#[test]
fn no_event_carries_a_delta() {
    // Every event today carries an absolute value, so applying one twice changes nothing. `is_delta` exists so a
    // future event carrying a delta has to say so rather than being mistaken for an idempotent one.
    let event = KernelEvent::PluginInstallProgress {
        plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
        progress: 0.5,
        stage: "downloading".to_owned(),
    };
    assert!(!event.is_delta());
    // The progress is a fraction rather than a byte count, which is what makes the repeat harmless.
    let json = serde_json::to_value(&event).expect("serialises");
    assert_eq!(json["payload"]["progress"], 0.5);
}

#[test]
fn an_event_an_older_interface_does_not_know_fails_to_parse() {
    // Which is the case the interface's `default` branch handles: it catches the parse failure, re-reads a
    // snapshot and keeps working. A kernel that added a variant must not break an interface that predates it.
    let json = r#"{ "type": "somethingNew", "payload": { "x": 1 } }"#;
    assert!(serde_json::from_str::<KernelEvent>(json).is_err());
}

#[test]
fn an_event_an_older_interface_does_not_know_still_has_a_readable_type() {
    // The interface reads the tag before it parses the payload, so an unknown type is a *known* unknown rather
    // than a syntax error — which is what lets the `default` branch tell "newer kernel" from "corrupt channel".
    let json: serde_json::Value =
        serde_json::from_str(r#"{ "type": "somethingNew" }"#).expect("valid json");
    assert_eq!(json["type"], "somethingNew");
}

// ── The envelope ──────────────────────────────────────────────────────────────────────────────

#[test]
fn the_envelope_flattens_the_event() {
    // `#[serde(flatten)]` so the interface reads `seq`, `at` and `type` from one object rather than nesting.
    let envelope = KernelEventEnvelope {
        seq: 1,
        at: 1_000,
        event: KernelEvent::DeviceRemoved {
            device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001")
                .expect("a valid uuid"),
        },
    };
    let json = serde_json::to_string(&envelope).expect("serialises");
    assert!(json.contains("\"seq\":1"), "{json}");
    assert!(json.contains("\"at\":1000"), "{json}");
    assert!(json.contains("\"type\":\"deviceRemoved\""), "{json}");

    let back: KernelEventEnvelope = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, envelope);
}

#[test]
fn a_scan_event_round_trips() {
    let event = KernelEvent::ScanUpdated(Box::new(ScanState {
        scan_id: "s1".to_owned(),
        elapsed_ms: 100,
        total_ms: 2_500,
        found: 3,
    }));
    let json = serde_json::to_string(&event).expect("serialises");
    let back: KernelEvent = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, event);
}

#[test]
fn an_identity_is_not_an_event() {
    // The identity is part of the devices snapshot, not a thing that changes on its own — and an event for it
    // would be a second way for the interface to learn the same fact.
    let snapshot = IdentitySnapshot {
        device_id: DeviceId::from_str("018f2b40-0000-7000-8000-000000000001")
            .expect("a valid uuid"),
        display_name: "Laptop".to_owned(),
        platform: "linux".to_owned(),
        kernel_version: "0".to_owned(),
        name_is_default: true,
    };
    let json = serde_json::to_string(&snapshot).expect("serialises");
    assert!(!json.contains("\"type\""), "{json}");
}
