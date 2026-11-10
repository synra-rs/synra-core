use synra_protocol::DeviceId;

use super::super::{DeviceCard, DevicesSnapshot, IdentitySnapshot, ScanOptions, TransferSummary};
use super::transfer_id;

pub(super) fn card() -> DeviceCard {
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
