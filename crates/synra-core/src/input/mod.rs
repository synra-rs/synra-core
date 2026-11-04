//! Leased, ordered pointer sessions over the existing peer link. Each session requires receiver consent.

mod controller;
mod queue;
mod receiver;
#[cfg(test)]
mod tests;
mod wire;

pub use controller::{ClientSnapshot, Controller};
pub use receiver::{Phase, Receiver, Snapshot};
pub use synra_platform::pointer::Command;

use crate::PeerLink;
use synra_protocol::ids::{DeviceId, PluginId};

/// The durable authorization and transport boundary supplied by a concrete host.
pub trait Policy: Send + Sync {
    /// Check pairing and the plugin's current local grants; return the authority revision.
    /// `receiving` requires platform:control-pointer, sending requires device:input and scoped device:send.
    /// # Errors
    /// Refuses unpaired, blocked, disabled, untrusted or ungranted operations.
    fn authorize(&self, peer: DeviceId, plugin: &PluginId, receiving: bool) -> Result<i64, String>;
    /// Open the existing peer handshake to the latest listening endpoint, outside every host lock.
    /// # Errors
    /// Refuses missing addresses, wrong peer identities and connection failures.
    fn connect(&self, peer: DeviceId) -> Result<PeerLink, String>;
    /// A local recorded name for the consent UI, never an incoming payload's claim.
    fn peer_name(&self, peer: DeviceId) -> String;
}

/// Monotonic receiver lease; every frame and heartbeat refreshes it.
pub const LEASE: std::time::Duration = std::time::Duration::from_secs(1);
/// How long the receiver waits for an explicit decision on a fresh request.
pub const CONSENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// The opening event, intercepted before ordinary plugin/transfer dispatch.
pub const OPEN_EVENT: &str = wire::OPEN;

/// Hand over a dedicated input link after the normal Hello and envelope source checks.
/// Returns false for ordinary traffic; unsupported hosts answer an input request with a refusal.
pub fn serve_if_requested(
    host: &crate::SharedHost,
    link: &mut PeerLink,
    request: &synra_protocol::envelope::Envelope,
) -> bool {
    if request.event.as_str() != wire::OPEN {
        return false;
    }
    let receiver = host.lock().input_receiver();
    if let Some(receiver) = receiver {
        receiver.serve(link, request);
    } else {
        let _ = wire::send(link, wire::ERROR, &"this host has no pointer receiver");
    }
    true
}
