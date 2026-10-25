//! Thin local-control adapter for the shared restricted pairing service.

use super::Runtime;
use synra_control::{PairingAction, Refusal};
use synra_core::peer_trust::PairingServiceError;
use synra_protocol::{DeviceId, ErrorCode};

impl Runtime {
    pub(super) fn pairing_action(
        &self,
        action: &PairingAction,
    ) -> Result<serde_json::Value, Refusal> {
        let service = self
            .host
            .lock()
            .pairing_service()
            .map_err(|error| super::refusals::refusal_of(&error))?;
        let timeout = synra_protocol::session::SessionTimeouts::default().pairing;
        match action {
            PairingAction::Invite => Ok(
                serde_json::json!({"invitation": service.invitation().map_err(|error| refusal(&error))?}),
            ),
            PairingAction::Listen { device, invitation } => {
                let id = self.pairing_target(device)?;
                let state = service
                    .listen(
                        id,
                        invitation,
                        std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                        timeout,
                    )
                    .map_err(|error| refusal(&error))?;
                encode(&state)
            }
            PairingAction::Connect { device, reply } => {
                let id = self.pairing_target(device)?;
                let found = self.host.lock().address_of(id);
                let address = found.ok_or_else(|| {
                    Refusal::new(
                        ErrorCode::DeviceOffline,
                        "the selected device has no discovery route",
                    )
                })?;
                let state = service
                    .connect(id, reply, address, timeout)
                    .map_err(|error| refusal(&error))?;
                encode(&state)
            }
            PairingAction::Status => encode(&service.snapshot()),
            PairingAction::Cancel { request_id } => {
                service
                    .cancel(*request_id)
                    .map_err(|error| refusal(&error))?;
                encode(&service.snapshot())
            }
        }
    }

    fn pairing_target(&self, device: &str) -> Result<DeviceId, Refusal> {
        if let Ok(id) = device.parse() {
            return Ok(id);
        }
        self.host
            .lock()
            .resolve(device)
            .map_err(|error| super::refusals::refusal_of(&error))
    }
}

fn encode(value: &impl serde::Serialize) -> Result<serde_json::Value, Refusal> {
    serde_json::to_value(value)
        .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))
}

fn refusal(error: &PairingServiceError) -> Refusal {
    Refusal::new(error.code(), error.to_string())
}
