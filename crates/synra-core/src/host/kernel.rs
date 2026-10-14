use std::net::{SocketAddr, TcpListener};

use synra_protocol::discovery::DeviceAnnouncement;
use synra_protocol::handshake::LinkToken;
use synra_protocol::ids::DeviceId;

use crate::discovery::{Absorbed, DiscoveryTable};
use crate::identity::Identity;
use crate::peer::{Flags, LocalPeer};
use crate::sessions::{SessionKey, SessionRegistry};

use super::HostError;

/// The kernel's view of its peers.
pub struct Host {
    /// This device.
    pub(super) identity: Identity,
    /// What this device announces and answers with.
    pub(super) local: LocalPeer,
    /// Who has been heard of.
    pub(super) discovery: DiscoveryTable,
    /// Who is being talked to.
    pub(super) sessions: SessionRegistry,
    /// The socket peers connect to, when this host is listening.
    pub(super) listener: Option<TcpListener>,
    /// Flags a handshake runs under.
    pub(super) flags: Flags,
    /// Envelopes sent, for a report.
    pub(super) sent: u64,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("device_id", &self.identity.device_id)
            .field("display_name", &self.identity.display_name)
            .field("candidates", &self.discovery.len())
            .field("sessions", &self.sessions.len())
            .field("listening", &self.listener.is_some())
            .finish()
    }
}

impl Host {
    /// A host that is not listening.
    #[must_use]
    pub fn new(identity: Identity, local: LocalPeer) -> Self {
        Self {
            discovery: DiscoveryTable::new(identity.device_id),
            identity,
            local,
            sessions: SessionRegistry::new(),
            listener: None,
            flags: Flags::production(),
            sent: 0,
        }
    }

    /// A host with chosen flags, for a test that must not depend on the clock.
    #[must_use]
    pub fn with_flags(identity: Identity, local: LocalPeer, flags: Flags) -> Self {
        let mut host = Self::new(identity, local);
        host.flags = flags;
        host
    }

    /// This device.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Replaces the flags a handshake runs under.
    ///
    /// # Why a host built with `no_timeout` needs this
    ///
    /// Because the timeouts are a property of the *connection*, and a test that wants to prove a production handshake
    /// completes has to be able to ask for one — while every other test in the module wants no waits at all, because a
    /// test that hangs on a timeout is a test nobody can read the failure of. The alternative was a second constructor and
    /// a helper for each, which is the same knob spelled twice.
    pub const fn set_flags(&mut self, flags: Flags) {
        self.flags = flags;
    }

    /// This device's identifier.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.identity.device_id
    }

    /// What this device announces to peers.
    #[must_use]
    pub const fn local_peer(&self) -> &LocalPeer {
        &self.local
    }

    /// Who has been heard of.
    #[must_use]
    pub const fn discovery(&self) -> &DiscoveryTable {
        &self.discovery
    }

    /// Who is being talked to.
    #[must_use]
    pub const fn sessions(&self) -> &SessionRegistry {
        &self.sessions
    }

    /// Envelopes sent from here.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// The address peers may reach this host on, when it is listening.
    ///
    /// # Errors
    ///
    /// [`HostError::Bind`] when the port cannot be read.
    pub fn listen_on(&mut self, address: SocketAddr) -> Result<SocketAddr, HostError> {
        let listener = TcpListener::bind(address).map_err(|error| HostError::Bind {
            address,
            why: error.to_string(),
        })?;
        let bound = listener.local_addr().map_err(|error| HostError::Bind {
            address,
            why: error.to_string(),
        })?;
        self.listener = Some(listener);
        Ok(bound)
    }

    /// Records an announcement that arrived as a datagram.
    ///
    /// The datagram is parsed by the protocol; what this decides is what to do with one, which is the part with
    /// decisions in it — whether the device is new, whether it moved, and whether the name may be shown.
    pub fn heard(&mut self, announcement: &DeviceAnnouncement, from: SocketAddr, now_ms: i64) -> Absorbed {
        self.discovery.absorb(announcement, from, now_ms)
    }

    /// Records that a frame arrived from a peer, moving its heartbeat deadline.
    ///
    /// # Errors
    ///
    /// [`crate::sessions::RegistryError`] when there is no session or its token does not match.
    pub fn record_inbound(
        &mut self,
        device_id: DeviceId,
        token: &LinkToken,
        now_ms: u64,
    ) -> Result<(), crate::sessions::RegistryError> {
        // The key comes from the session rather than being constructed here: `SessionKey` is opaque on purpose, so a
        // caller cannot name a session the registry never issued. A missing session is reported as a closure of the
        // device rather than as a made-up key.
        let Some(session) = self.sessions.live_for(device_id) else {
            return Err(crate::sessions::RegistryError::NoSuchSession(SessionKey::UNISSUED));
        };
        let key = session.key();
        self.sessions.record_frame_in(key, token, now_ms)
    }

    /// Records that a device completed a handshake.
    ///
    /// # Why this is public when `dial` and `accept` already record it
    ///
    /// Because they own the sockets, and a caller that drives a handshake through a path of its own — the daemon's
    /// accept loop, a test with two threads — has the identifier and the address but not the record. Reaching through
    /// [`Host::discovery`] would need a mutable borrow the caller may not hold, so the one call it needs is here, with
    /// the same rule `dial` and `accept` follow: the level rises, and the address recorded is the one the connection
    /// actually worked at.
    ///
    /// Returns whether the device was already known.
    pub fn handshaked(
        &mut self,
        device_id: DeviceId,
        address: SocketAddr,
        name: Option<&str>,
        now_ms: i64,
    ) -> bool {
        self.discovery.handshaked(device_id, address, name, now_ms)
    }

}
