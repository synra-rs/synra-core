use synra_protocol::DeviceId;

use super::super::{DevicesSnapshot, IdentitySnapshot, IntentSnapshot};
use super::devices::card;
use super::intent_id;
use super::transfers::transfer;

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
