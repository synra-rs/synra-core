use std::net::SocketAddr;

use synra_protocol::ids::DeviceId;

use crate::discovery::{Absorbed, Candidate};
use crate::sessions::{LinkState, RegistryEvent};

use super::{Host, HostError};

// The rest of `impl Host`, whose other parts are in `kernel` and `connections`.
impl Host {
    /// Resolves what a user typed to a device this kernel can reach.
    ///
    /// # The three ways it can fail, and why they are separate
    ///
    /// * **No match** — nothing known is called that. The user mistyped, or the device has never been seen.
    /// * **Ambiguous** — more than one device is called that. Picking one would send a message to a device the user did
    ///   not choose, and the sender would never know: the message would arrive, and it would look deliberate.
    /// * **Unreachable** — the device is known and this kernel has no address for it. A paired device whose row is in the
    ///   database but which has never been announced or connected to. There is nothing to dial.
    ///
    /// # Why an identifier wins over a name
    ///
    /// Because an identifier is unambiguous by construction, and a name is whatever the other device decided to call
    /// itself — including a name that is a valid identifier for a different device. Checking identifiers first means a
    /// user who pasted an id gets the device they pasted rather than a device that renamed itself to match.
    ///
    /// # Errors
    ///
    /// [`HostError::NoSuchDevice`], [`HostError::AmbiguousName`] or [`HostError::Unreachable`].
    pub fn resolve(&self, wanted: &str) -> Result<DeviceId, HostError> {
        let trimmed = wanted.trim();
        if trimmed.is_empty() {
            return Err(HostError::NoSuchDevice { wanted: wanted.to_owned() });
        }

        // Identifiers first: an exact match on the canonical form, then a case-insensitive one, because a user pasting a
        // UUID from a chat message may have a different case and there is nothing else it could mean.
        for candidate in self.discovery.iter() {
            if candidate.device_id.to_string().eq_ignore_ascii_case(trimmed) {
                return Ok(candidate.device_id);
            }
        }

        let matches: Vec<&Candidate> = self
            .discovery
            .iter()
            .filter(|candidate| candidate.display_name.eq_ignore_ascii_case(trimmed))
            .collect();

        match matches.as_slice() {
            [] => Err(HostError::NoSuchDevice { wanted: trimmed.to_owned() }),
            [only] => {
                // Known by name and there is no address to dial. Reported rather than dialled-and-failed: a connection
                // attempt to an address this kernel never had would be an error about the network, and the real answer is
                // that the device has not been seen.
                if only.address.port() == 0 {
                    return Err(HostError::Unreachable { device_id: only.device_id });
                }
                Ok(only.device_id)
            }
            many => Err(HostError::AmbiguousName {
                name: trimmed.to_owned(),
                matches: many.len(),
            }),
        }
    }

    /// The address this kernel would dial a device at.
    #[must_use]
    pub fn address_of(&self, device_id: DeviceId) -> Option<SocketAddr> {
        self.discovery.get(device_id).map(|candidate| candidate.address)
    }

    /// Records that a device said goodbye.
    ///
    /// # Why this is on the host rather than reached through the table
    ///
    /// Because a goodbye is a datagram, and a datagram's handling belongs where the socket can reach it. The table's own
    /// rule — that a goodbye ages the entry out rather than refreshing it — is unchanged; this is the way in.
    pub fn went_offline(&mut self, device_id: DeviceId, now_ms: i64) -> Absorbed {
        self.discovery.went_offline(device_id, now_ms)
    }

    /// Drops the candidates that have stopped being current, reporting what went.
    pub fn expire(&mut self, now_ms: i64) -> Vec<Candidate> {
        self.discovery.expire(now_ms)
    }

    /// Closes every session whose peer has been silent too long.
    pub fn sweep(&mut self, now_ms: u64) -> Vec<RegistryEvent> {
        self.sessions.sweep_expired(now_ms)
    }

    /// The devices the kernel would offer the user, in identifier order.
    #[must_use]
    pub fn usable(&self, now_ms: i64) -> Vec<&Candidate> {
        self.discovery.displayable(now_ms).collect()
    }

    /// A session's state, for a report.
    #[must_use]
    pub fn state_of(&self, device_id: DeviceId) -> Option<LinkState> {
        self.sessions.live_for(device_id).map(crate::sessions::PeerSession::state)
    }
}
