//! Produce the actual projected envelope and Core subscription matching decisions for frontend tests.

use synra_ipc::event::{
    PluginDevicePlatform, PluginDeviceTarget, PluginDevicesChanged, PluginEvent,
    PluginEventEnvelope,
};
use synra_protocol::DeviceId;
use synra_protocol::inbound::HandlePattern;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let envelope = PluginEventEnvelope {
        seq: 1,
        at: 20,
        event: PluginEvent::DevicesChanged(PluginDevicesChanged {
            devices: vec![PluginDeviceTarget {
                device_id: "019482b2-b6a0-77ab-8a5d-63cd6f04d4f1".parse::<DeviceId>()?,
                display_name: "Offline laptop".to_owned(),
                platform: PluginDevicePlatform::Macos,
                online: false,
            }],
        }),
    };
    let cases = [
        ("device.changed", "device.changed"),
        ("device.*", "device.changed"),
        ("*.changed", "device.changed"),
        ("*.changed", "device.failed"),
        ("device.*", "device.link.changed"),
        ("device.*", "device."),
        ("_plugin.@acme/chat.*", "_plugin.@acme/chat.update"),
        ("_plugin.@acme/chat.*", "_plugin.@acme/notes.update"),
        ("device.**", "device.changed"),
        ("device..changed", "device.changed"),
        ("device.ch*", "device.changed"),
        ("*.*.*.*.*", "a.b.c.d.e"),
    ]
    .map(|(pattern, name)| {
        let parsed = HandlePattern::parse(pattern);
        serde_json::json!({
            "pattern": pattern,
            "name": name,
            "valid": parsed.is_ok(),
            "matches": parsed.is_ok_and(|value| value.matches(name)),
        })
    });
    let contract = serde_json::json!({ "envelope": envelope, "patterns": cases });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &contract)?;
    Ok(())
}
