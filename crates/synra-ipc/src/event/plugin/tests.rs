use super::{
    DeviceCard, DeviceId, PluginDeviceTarget, PluginDevicesChanged, PluginEvent,
    PluginEventEnvelope,
};

fn card() -> DeviceCard {
    DeviceCard {
        device_id: "019482b2-b6a0-77ab-8a5d-63cd6f04d4f1"
            .parse::<DeviceId>()
            .unwrap(),
        display_name: "Offline laptop".to_owned(),
        platform: "macos".to_owned(),
        online: false,
        paired: true,
        blocked: false,
        last_seen_ms: 15,
        address: Some("private address".to_owned()),
        transfer: None,
    }
}

#[test]
fn plugin_stream_uses_only_the_public_device_projection() {
    let target = PluginDeviceTarget::from_card(&card()).unwrap().unwrap();
    let envelope = PluginEventEnvelope {
        seq: 1,
        at: 20,
        event: PluginEvent::DevicesChanged(PluginDevicesChanged {
            devices: vec![target],
        }),
    };
    let json = serde_json::to_value(&envelope).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "seq": 1,
            "at": 20,
            "name": envelope.event.name(),
            "payload": {
                "devices": [{
                    "deviceId": "019482b2-b6a0-77ab-8a5d-63cd6f04d4f1",
                    "displayName": "Offline laptop",
                    "platform": "macos",
                    "online": false
                }]
            }
        })
    );
    assert_eq!(
        serde_json::from_value::<PluginEventEnvelope>(json).unwrap(),
        envelope
    );
}

#[test]
fn blocked_or_unpaired_devices_are_absent_even_when_online() {
    let blocked = DeviceCard {
        blocked: true,
        online: true,
        ..card()
    };
    let unpaired = DeviceCard {
        paired: false,
        online: true,
        ..card()
    };
    assert!(PluginDeviceTarget::from_card(&blocked).unwrap().is_none());
    assert!(PluginDeviceTarget::from_card(&unpaired).unwrap().is_none());
}

#[test]
fn custom_envelopes_preserve_the_full_topic_and_require_an_object() {
    let name = "_plugin.@acme/chat.note.created";
    let raw = serde_json::json!({"seq":7,"at":20,"name":name,"payload":{"text":"你好"}});
    let envelope: PluginEventEnvelope = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(envelope.event.name(), name);
    assert_eq!(serde_json::to_value(envelope).unwrap(), raw);
    for raw in [
        serde_json::json!({"name":"_synra.device.changed","payload":{}}),
        serde_json::json!({"name":"_plugin.@acme/chat.*","payload":{}}),
        serde_json::json!({"name":name,"payload":[]}),
    ] {
        assert!(serde_json::from_value::<PluginEvent>(raw).is_err());
    }
}
