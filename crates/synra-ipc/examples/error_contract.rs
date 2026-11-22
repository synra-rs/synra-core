//! Emit actual serialized error contracts for host/JavaScript conformance tests.

use synra_ipc::IpcError;
use synra_protocol::error::SuggestedAction;
use synra_protocol::{ErrorCode, SynraError};

fn main() -> Result<(), serde_json::Error> {
    let policies: Vec<IpcError> = ErrorCode::all()
        .iter()
        .copied()
        .map(IpcError::unknown)
        .collect();
    let plugin_error = SynraError::new(ErrorCode::DeviceOffline, "the selected peer is offline")
        .with_trace("contract-trace")
        .with_details(serde_json::json!({"peer": "contract-peer", "attempts": [1, 2]}));
    let mut ipc_error = IpcError::from_synra_error(&plugin_error)
        .with_params(serde_json::json!({"field": "deviceId"}));
    ipc_error.actions = SuggestedAction::all();
    let contract = serde_json::json!({
        "policies": policies,
        "ipc": ipc_error,
        "plugin": plugin_error,
    });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &contract)
}
