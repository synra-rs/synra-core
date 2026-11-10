//! Binds the endpoints whose addresses peers see when the daemon advertises itself.

use std::sync::Arc;

use parking_lot::Mutex;
use synra_core::{DiscoveryService, Host, Identity, LocalPeer};

use crate::DaemonPlan;

pub(super) fn bind_transport(plan: &DaemonPlan, identity: &Identity) -> (Host, LocalPeer) {
    // ★ The peer registry is built after the transport port is known, because the announcement carries the port a peer
    // would *connect* to — and an announcement that named a port nothing is listening on would be a device that appears
    // in every list and cannot be reached.
    let local_peer = LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        synra_core::platform_of_os(std::env::consts::OS),
        env!("CARGO_PKG_VERSION"),
    );
    let mut host = Host::new(identity.clone(), local_peer.clone());

    // ★ The transport listener is what makes this device *reachable*. `dial` can only make outbound links, so without
    // this a device could send and never receive — and the announcement above would name a port nothing is listening on.
    // Bound here rather than in the library so the port is the one the announcement carries.
    match crate::transport::bind(&mut host, plan.listen_port) {
        Ok(address) => println!("transport on {address}"),
        Err(error) => {
            // A device can still run without accepting inbound connections.
            eprintln!("synra-daemon: nothing can connect to this device: {error}");
        }
    }
    (host, local_peer)
}

// ★ Discovery is bound *before* the control socket, and a failure is reported rather than fatal. A machine with no
// network, a firewall, and a sandbox all produce the same thing — and a kernel that could not start without discovery
// would be one that cannot run with its wireless switched off. What it means is that this device cannot be *found*;
// every other command still works.
pub(super) fn bind_discovery(
    plan: &DaemonPlan,
    local_peer: &LocalPeer,
) -> Option<Arc<Mutex<DiscoveryService>>> {
    match DiscoveryService::bind_on(
        local_peer.announcement(plan.listen_port),
        plan.discovery_port,
        synra_core::QUERY_INTERVAL,
    ) {
        Ok(service) => {
            match service.responder_address() {
                Ok(address) => println!("discovery on {address}"),
                Err(error) => eprintln!("synra-daemon: {error}"),
            }
            Some(Arc::new(Mutex::new(service)))
        }
        Err(error) => {
            // Not fatal, and said out loud: a user whose device cannot be found needs to know why, and "discovery is not
            // running" is the answer to that rather than a line in a log nobody reads.
            eprintln!("synra-daemon: discovery is not running: {error}");
            None
        }
    }
}
