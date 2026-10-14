use std::sync::Arc;

use parking_lot::Mutex;
use synra_protocol::ids::DeviceId;

use crate::link::PeerLink;

use super::Host;

/// A handle two threads can share, for the accept loop and the caller that drives it.
pub type SharedHost = Arc<Mutex<Host>>;

/// Wraps a host so the accept loop and a caller can share it.
#[must_use]
pub fn shared(host: Host) -> SharedHost {
    Arc::new(Mutex::new(host))
}

/// A stream and the host it belongs to, which is what a caller holds while two threads run.
///
/// # Why the pair travels together
///
/// Because an envelope has to be checked against the session it claims to belong to, and the link alone does not know
/// which host's sessions those are. A caller holding a link and a host separately is one that can pass the wrong pair.
#[derive(Debug)]
pub struct Attached {
    /// The connection.
    pub link: PeerLink,
    /// The device on the other end.
    pub device_id: DeviceId,
}
