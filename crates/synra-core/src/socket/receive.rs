use super::{Absorbed, DiscoveryDatagram, DiscoverySocket, Host, SocketAddr, SocketError, limits};

/// A received announcement and the UDP return address of a query.
pub(crate) struct Received {
    pub(crate) absorbed: Absorbed,
    pub(crate) reply_to: Option<SocketAddr>,
}

impl DiscoverySocket {
    /// Receives one datagram and decides what it means.
    ///
    /// # The decisions, and where each one lives
    ///
    /// The **format** is the protocol's: [`DiscoveryDatagram::parse`] refuses anything that is not a Synra announcement,
    /// and validates the announcement it finds. The **self-check** is here, because "is this about me" needs this
    /// device's own identifier and the protocol has no business knowing it. What to **do** with a device is
    /// [`crate::discovery::DiscoveryTable`]'s, reached through the host.
    ///
    /// Returns `None` for a datagram about this device, which is the ordinary case rather than a problem: a device hears
    /// its own broadcasts, because that is what broadcasting means.
    ///
    /// # Errors
    ///
    /// [`SocketError::Receive`] when the socket fails, and [`SocketError::Malformed`] for a datagram that is not a Synra
    /// announcement. A receive that timed out is reported as `Receive`, because a caller that set a timeout asked for one
    /// and has to be able to tell it from a socket that broke.
    pub fn receive(&self, host: &mut Host, now_ms: i64) -> Result<Option<Absorbed>, SocketError> {
        self.receive_packet(host, now_ms)
            .map(|packet| packet.map(|packet| packet.absorbed))
    }

    /// Keeps the UDP source separate from the announced TCP listening address.
    pub(crate) fn receive_packet(
        &self,
        host: &mut Host,
        now_ms: i64,
    ) -> Result<Option<Received>, SocketError> {
        let mut buffer = [0u8; synra_protocol::discovery::MAX_DATAGRAM_LEN];
        let (read, from) =
            self.socket
                .recv_from(&mut buffer)
                .map_err(|error| SocketError::Receive {
                    why: error.to_string(),
                })?;
        let bytes = buffer.get(..read).ok_or_else(|| SocketError::Receive {
            why: "a receive reported more bytes than the buffer".to_owned(),
        })?;

        let datagram = DiscoveryDatagram::parse(bytes).map_err(|error| SocketError::Malformed {
            why: error.to_string(),
        })?;

        let reply_to =
            if matches!(datagram, DiscoveryDatagram::Query(_)) && !is_about(host, &datagram) {
                Some(from)
            } else {
                None
            };
        Ok(absorb(host, &datagram, from, now_ms).map(|absorbed| Received { absorbed, reply_to }))
    }

    /// Reads until a datagram about another device arrives, or the budget runs out.
    ///
    /// # Why the malformed datagrams are skipped here but reported by `receive`
    ///
    /// Because a scan is a bounded wait on a port anything may send to, and stopping it for a stray packet would make a
    /// scan fail because a printer answered. The caller that wants to count those is the one reading one datagram at a
    /// time; the caller that wants devices is this one.
    pub fn scan_until(
        &self,
        host: &mut Host,
        now_ms: i64,
        deadline: std::time::Instant,
    ) -> Vec<Absorbed> {
        let mut results = Vec::new();
        let interval = limits::SCAN_PASSIVE / 8;
        loop {
            if std::time::Instant::now() >= deadline {
                return results;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if self
                .set_read_timeout(Some(interval.min(remaining)))
                .is_err()
            {
                return results;
            }
            match self.receive(host, now_ms) {
                Ok(Some(absorbed)) => results.push(absorbed),
                // A datagram about this device, or nothing within the interval.
                Ok(None) => {}
                Err(SocketError::Receive { .. }) => {}
                // A stray packet on a well-known port is not a reason to stop looking.
                Err(_) => {}
            }
        }
    }
}

/// Applies a parsed datagram to a host.
///
/// # Why this is a free function
///
/// Because the decision it makes is testable without a socket at all: a datagram, a source address, and a host. The
/// socket's job is to get the bytes; whether a query from a known device is news is not a networking question.
#[must_use]
pub fn absorb(
    host: &mut Host,
    datagram: &DiscoveryDatagram,
    from: SocketAddr,
    now_ms: i64,
) -> Option<Absorbed> {
    match datagram {
        // A query and a response carry the same announcement, and both are news about a device. What differs is who has
        // to act: a query has to be *answered* by the caller, because the answer needs this device's own announcement,
        // which is the host's and not this function's.
        DiscoveryDatagram::Query(query) => Some(host.heard(&query.device, from, now_ms)),
        DiscoveryDatagram::Response(response) => Some(host.heard(&response.device, from, now_ms)),
        // A goodbye is not news about where a device is, and treating it as one would refresh the entry the device just
        // asked to have aged out — the opposite of what it said.
        DiscoveryDatagram::Offline(offline) => Some(host.went_offline(offline.device_id, now_ms)),
        // ★ `#[non_exhaustive]` means a wildcard arm is required even in the declaring crate, so a datagram kind added
        // later is *ignored* rather than failing to compile here — which is the property the attribute exists for: an
        // unknown announcement from a newer peer is not a reason for this one to stop.
        _ => None,
    }
}

/// Whether a datagram concerns this device.
#[must_use]
pub fn is_about(host: &Host, datagram: &DiscoveryDatagram) -> bool {
    datagram.device_id() == host.device_id()
}
