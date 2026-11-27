//! Produce the actual projected envelope and Core subscription matching decisions for frontend tests.

use synra_ipc::event::{
    PluginDevicePlatform, PluginDeviceTarget, PluginDevicesChanged, PluginEvent,
    PluginEventEnvelope, PluginEventPoll, PluginEventRecovery,
};
use synra_ipc::{PluginTransferFailure, PluginTransferState, PluginTransferStatus};
use synra_protocol::inbound::HandlePattern;
use synra_protocol::{DeviceId, TransferId, session::TransferAbortReason};

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
        ("transfer.*", "transfer.progress"),
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
    let transfer = PluginEventEnvelope {
        seq: 2,
        at: 25,
        event: PluginEvent::TransferProgress(PluginTransferStatus {
            transfer_id: "b7f7f0c2-4a7e-4f1a-9a9a-2e2b6c1d0a11".parse::<TransferId>()?,
            state: PluginTransferState::Failed,
            received_bytes: 2,
            total_bytes: 4,
            blocks_done: 1,
            blocks_total: 2,
            revision: 3,
            ended_at_ms: Some(24),
            failure: Some(PluginTransferFailure::PeerAborted {
                reason: TransferAbortReason::TooLarge,
            }),
        }),
    };
    let recovery = PluginEventRecovery {
        seq: 7,
        events: vec![envelope.event.clone(), transfer.event.clone()],
    };
    let resync = PluginEventPoll::Reconcile { resync: true };
    let contract = serde_json::json!({ "envelope": envelope, "transfer": transfer, "recovery": recovery, "resync": resync, "patterns": cases });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &contract)?;
    Ok(())
}
