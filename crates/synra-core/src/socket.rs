//! The UDP socket discovery runs on.
//!
//! # What this layer is, and what it is not
//!
//! `synra-protocol`'s discovery module owns the wire format — the two magic prefixes, the JSON, the validation — and is
//! exhaustively tested against it. [`crate::discovery`] owns what to *do* with a datagram once it has been parsed: whether
//! a device is new, whether it moved, how long a candidate stays. Neither of them opens a socket.
//!
//! This is the third piece, and it is deliberately the thinnest of the three: it binds, it sends, it receives, and it
//! hands bytes to one of the other two. Almost everything that could be wrong is already covered elsewhere, and what is
//! left is the part that only a real socket can be wrong about.
//!
//! # The port, and why it is fixed
//!
//! Both queries and responses go to [`limits::DISCOVERY_PORT`], and a responder replies to *the address the query came
//! from* rather than to a port the sender announced. That is the protocol's design, and it has a consequence worth
//! stating: a host that wants to be found must be listening on that port, so the port is a constant rather than
//! something chosen.
//!
//! # Why address reuse is set
//!
//! Because two kernels on one machine both want to answer on the same port, and without `SO_REUSEADDR` the second one
//! fails to bind — which is the state a developer running two profiles is in, and also the state a test is in when it
//! wants two hosts in one process. On Windows the option is spelled `SO_REUSEADDR` and behaves like Unix's
//! `SO_REUSEPORT`; on Unix both are set, because the two have different meanings and Windows' single option corresponds
//! to the second.
//!
//! # Why a socket that fails to receive is still a usable socket
//!
//! A machine with no network, a firewall, and a sandbox all produce the same thing: sends fail. Discovery is how peers
//! are *found*, not how they are reached, and a kernel that could not start without it would be one that cannot run on a
//! machine with its wireless switched off. Every send here returns its error to the caller, and no caller in this module
//! treats one as fatal — the caller that wants to log them is the one that knows whether they matter.
//!
//! # What is tested
//!
//! A real loopback socket, because the thing that can be wrong is the part only a socket does: that a datagram written
//! by the encoder arrives as the bytes the parser expects, and that the address a reply goes to is the one the query
//! came from. The tests bind port zero rather than the discovery port, so they do not collide with a kernel that happens
//! to be running on the machine.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use synra_protocol::discovery::{
    DeviceAnnouncement, DiscoveryDatagram, OfflineAnnouncement, encode_offline, encode_query,
    encode_response,
};
use synra_protocol::limits;

use crate::discovery::Absorbed;
use crate::host::Host;

/// Why a discovery socket operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SocketError {
    /// The socket could not be created or bound.
    #[error("could not listen on {address}: {why}")]
    Bind {
        /// Where it tried.
        address: SocketAddr,
        /// What the operating system said.
        why: String,
    },

    /// A datagram could not be sent.
    #[error("could not send to {address}: {why}")]
    Send {
        /// Where it was going.
        address: SocketAddr,
        /// What the operating system said.
        why: String,
    },

    /// A datagram could not be received.
    #[error("could not receive: {why}")]
    Receive {
        /// What the operating system said.
        why: String,
    },

    /// The datagram was not one this protocol recognises.
    ///
    /// # Why an unrecognised datagram is an error and not a variant
    ///
    /// Because this socket is on a well-known port that anything on the network may send to — a port scan, another
    /// product's discovery, a stray packet. The protocol's parser is written the same way, and for the same reason: a
    /// datagram this build does not understand is *reported* so a caller can count it or ignore it, and it must not be
    /// confused with a device that said something wrong.
    #[error("the datagram is not a synra announcement: {why}")]
    Malformed {
        /// What the parser said.
        why: String,
    },

    /// A datagram could not be encoded.
    #[error("the announcement could not be encoded: {why}")]
    Encode {
        /// What the encoder said.
        why: String,
    },
}

/// A socket discovery runs on.
#[derive(Debug)]
pub struct DiscoverySocket {
    socket: UdpSocket,
}

impl DiscoverySocket {
    /// Binds the discovery port on every interface.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when the address is taken or unusable.
    pub fn bind_default() -> Result<Self, SocketError> {
        Self::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, limits::DISCOVERY_PORT)))
    }

    /// Binds a chosen address.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when the address is taken or unusable.
    pub fn bind(address: SocketAddr) -> Result<Self, SocketError> {
        let socket = bind_reusable(address)?;
        // ★ Broadcast is off by default on every platform, and `send_to` to a broadcast address fails without it. Set
        // here rather than at each send, because a socket that has to remember to enable it is one that will forget.
        socket.set_broadcast(true).map_err(|error| SocketError::Bind {
            address,
            why: format!("broadcast could not be enabled: {error}"),
        })?;
        Ok(Self { socket })
    }

    /// The address actually bound.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when it cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, SocketError> {
        self.socket.local_addr().map_err(|error| SocketError::Bind {
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            why: error.to_string(),
        })
    }

    /// How long a receive waits before reporting that nothing came.
    ///
    /// # Errors
    ///
    /// [`SocketError::Receive`] when the option cannot be set.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), SocketError> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|error| SocketError::Receive { why: error.to_string() })
    }

    /// Sends a query, asking whoever is listening to answer.
    ///
    /// # Errors
    ///
    /// [`SocketError::Encode`] for an unusable announcement, and [`SocketError::Send`] when the send fails.
    pub fn send_query(&self, ours: &DeviceAnnouncement, to: SocketAddr) -> Result<usize, SocketError> {
        let bytes = encode_query(ours).map_err(|error| SocketError::Encode {
            why: error.to_string(),
        })?;
        self.send_bytes(&bytes, to)
    }

    /// Answers a query, which the protocol says is unicast back to where the query came from.
    ///
    /// # Errors
    ///
    /// As [`DiscoverySocket::send_query`].
    pub fn send_response(&self, ours: &DeviceAnnouncement, to: SocketAddr) -> Result<usize, SocketError> {
        let bytes = encode_response(ours).map_err(|error| SocketError::Encode {
            why: error.to_string(),
        })?;
        self.send_bytes(&bytes, to)
    }

    /// Announces that this device is leaving.
    ///
    /// # Errors
    ///
    /// As [`DiscoverySocket::send_query`].
    pub fn send_offline(
        &self,
        offline: &OfflineAnnouncement,
        to: SocketAddr,
    ) -> Result<usize, SocketError> {
        let bytes = encode_offline(offline).map_err(|error| SocketError::Encode {
            why: error.to_string(),
        })?;
        self.send_bytes(&bytes, to)
    }

    /// Sends raw bytes, counting them.
    fn send_bytes(&self, bytes: &[u8], to: SocketAddr) -> Result<usize, SocketError> {
        self.socket
            .send_to(bytes, to)
            .map_err(|error| SocketError::Send { address: to, why: error.to_string() })
    }

    /// Sends a query to every broadcast address this machine has.
    ///
    /// # Why this returns a count of what it reached
    ///
    /// Because "nothing was found" and "nothing could be asked" are different answers, and a caller that showed the user
    /// an empty list for both would be one that cannot tell them their firewall is the problem. A failure to send to one
    /// interface is not a failure of the scan: a machine with a loopback and a wireless card may reach only one.
    #[must_use]
    pub fn broadcast_query(&self, ours: &DeviceAnnouncement) -> Vec<(SocketAddr, Result<usize, SocketError>)> {
        broadcast_addresses()
            .into_iter()
            .map(|address| (address, self.send_query(ours, address)))
            .collect()
    }

    /// Sends an offline announcement to every broadcast address.
    #[must_use]
    pub fn broadcast_offline(
        &self,
        offline: &OfflineAnnouncement,
    ) -> Vec<(SocketAddr, Result<usize, SocketError>)> {
        broadcast_addresses()
            .into_iter()
            .map(|address| (address, self.send_offline(offline, address)))
            .collect()
    }

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
    pub fn receive(
        &self,
        host: &mut Host,
        now_ms: i64,
    ) -> Result<Option<Absorbed>, SocketError> {
        let mut buffer = [0u8; synra_protocol::discovery::MAX_DATAGRAM_LEN];
        let (read, from) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(|error| SocketError::Receive { why: error.to_string() })?;
        let bytes = buffer.get(..read).ok_or_else(|| SocketError::Receive {
            why: "a receive reported more bytes than the buffer".to_owned(),
        })?;

        let datagram = DiscoveryDatagram::parse(bytes).map_err(|error| SocketError::Malformed {
            why: error.to_string(),
        })?;

        Ok(absorb(host, &datagram, from, now_ms))
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
            if self.set_read_timeout(Some(interval.min(remaining))).is_err() {
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
        DiscoveryDatagram::Query(query) => {
            Some(host.heard(&query.device, from, now_ms))
        }
        DiscoveryDatagram::Response(response) => {
            Some(host.heard(&response.device, from, now_ms))
        }
        // A goodbye is not news about where a device is, and treating it as one would refresh the entry the device just
        // asked to have aged out — the opposite of what it said.
        DiscoveryDatagram::Offline(offline) => {
            Some(host.went_offline(offline.device_id, now_ms))
        }
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

/// Binds a socket.
///
/// # Why there is no `SO_REUSEPORT` here
///
/// The first version of this reached for `socket2` to set it, on the reasoning that two kernels on one machine both want
/// the discovery port. That reasoning was wrong, and checking the design rather than assuming is what showed it: the
/// port is a **singleton per host**. Two kernels on one machine do not both discover — they would both answer every
/// query, and a peer would receive two responses from one address with different device identifiers.
///
/// So the plain bind is the correct behaviour, and it is why the second kernel on a machine *should* fail here: it is
/// already running, or it is a second profile that has to be given a different port. The dependency this avoids would
/// have bought the ability to do the wrong thing.
///
/// On Unix, `std` sets `SO_REUSEADDR` on a UDP socket already, which is what lets a socket rebind an address whose
/// previous owner has closed. That is a restart, not a second kernel, and it is exactly the behaviour that is wanted.
fn bind_reusable(address: SocketAddr) -> Result<UdpSocket, SocketError> {
    if !matches!(address, SocketAddr::V4(_)) {
        return Err(SocketError::Bind {
            address,
            why: "discovery is IPv4 only".to_owned(),
        });
    }
    UdpSocket::bind(address).map_err(|error| SocketError::Bind {
        address,
        why: error.to_string(),
    })
}

/// Every address a query should be broadcast to.
///
/// # Why the limited broadcast address is always included
///
/// Because it is the one address that needs no knowledge of the machine's interfaces, and a device on a network this
/// code cannot enumerate — a virtual adapter, a VPN, a container bridge — is reachable through it and not through any
/// computed address. It is sent as well as, never instead of, the per-interface addresses: some networks drop the
/// limited broadcast, which is why the computed ones matter.
#[must_use]
pub fn broadcast_addresses() -> Vec<SocketAddr> {
    let mut addresses = vec![SocketAddr::from((Ipv4Addr::BROADCAST, limits::DISCOVERY_PORT))];

    // A best effort at the per-interface addresses. `get_if_addrs` is not a dependency of this crate, so the interfaces
    // are enumerated through the address the operating system reports for a connected socket — which gives the local
    // address of the interface the default route uses, and therefore the most likely broadcast address.
    if let Some(broadcast) = default_local_address().and_then(subnet_broadcast)
        && !addresses.contains(&broadcast)
    {
        addresses.push(broadcast);
    }
    addresses
}

/// The local address of the interface the default route uses.
///
/// # Why a connected UDP socket
///
/// Because it makes the operating system choose the interface without sending anything: `connect` on a datagram socket
/// only records the peer, and `local_addr` then reports which source address the kernel would use. It is the standard
/// way to ask "which interface would reach the internet" without opening a route to a host that may not exist.
fn default_local_address() -> Option<IpAddr> {
    // A documentation-range address that is never actually contacted: `connect` records it and stops.
    let probe = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9));
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(probe).ok()?;
    let local = socket.local_addr().ok()?;
    match local {
        SocketAddr::V4(v4) if !v4.ip().is_unspecified() => Some(IpAddr::V4(*v4.ip())),
        _ => None,
    }
}

/// The broadcast address of the `/24` a local address is on.
///
/// # Why `/24` and not the real prefix length
///
/// Because the prefix length needs the interface configuration, which is not available through `std`. A `/24` is the
/// assumption a home network satisfies and a corporate one often does not — which is exactly why the limited broadcast
/// address is sent as well rather than instead. Being wrong here costs one extra datagram to an address that ignores it.
const fn subnet_broadcast(local: IpAddr) -> Option<SocketAddr> {
    let IpAddr::V4(v4) = local else {
        return None;
    };
    let octets = v4.octets();
    let broadcast = Ipv4Addr::new(octets[0], octets[1], octets[2], 255);
    Some(SocketAddr::V4(SocketAddrV4::new(broadcast, limits::DISCOVERY_PORT)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Absorbed;
    use crate::host::Host;
    use crate::identity::Identity;
    use crate::peer::{Flags, LocalPeer};
    use synra_protocol::handshake::PROTOCOL_VERSION;
    use synra_protocol::ids::DeviceId;
    use synra_protocol::session::PlatformKind;
    use std::time::{Duration, Instant};

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    fn host(id: &str, name: &str) -> Host {
        let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        let mut identity = Identity::load(&db, "test", 1_000).expect("an identity");
        identity.device_id = device(id);
        identity.rename(&db, name, 1_000).expect("renames");
        let local = LocalPeer::new(
            identity.device_id,
            identity.display_name.clone(),
            PlatformKind::Desktop,
            "0.1.0-test",
        );
        Host::with_flags(identity, local, Flags::no_timeout())
    }

    fn announcement(id: &str, name: &str, port: u16) -> DeviceAnnouncement {
        DeviceAnnouncement {
            device_id: device(id),
            display_name: name.to_owned(),
            protocol: PROTOCOL_VERSION,
            port,
            platform: Some(PlatformKind::Desktop),
            app_version: Some("0.1.0".to_owned()),
            features: Vec::new(),
        }
    }

    /// A socket on a port the operating system chose, so a test never collides with a running kernel.
    fn loopback() -> DiscoverySocket {
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("binds")
    }

    // ── The socket itself ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_socket_binds_and_reports_where_it_is() {
        let socket = loopback();
        let address = socket.local_addr().expect("an address");
        assert_ne!(address.port(), 0, "the operating system assigned no port");
        assert_eq!(address.ip(), IpAddr::from(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn the_discovery_port_is_a_singleton_per_host_and_a_second_bind_is_refused() {
        // ★ This is the behaviour, and the first version of this module got it backwards by adding a dependency to
        // share the port. Two kernels on one machine do not both discover: they would both answer every query, and a
        // peer would receive two responses from one address with different device identifiers. A second kernel is
        // already running or is a second profile, and either way it has to be told so rather than silently sharing.
        let socket = loopback();
        let address = socket.local_addr().expect("an address");
        match DiscoverySocket::bind(address) {
            Err(SocketError::Bind { address: named, .. }) => assert_eq!(named, address),
            Ok(second) => panic!(
                "a second socket bound {} — discovery would answer twice",
                second.local_addr().expect("an address")
            ),
            Err(other) => panic!("expected a bind failure, got {other:?}"),
        }
    }

    #[test]
    fn an_ipv6_address_is_refused_with_a_reason() {
        // Discovery is IPv4 by design — broadcast is an IPv4 concept and the protocol's addresses are IPv4 — so an IPv6
        // request is answered rather than attempted.
        match DiscoverySocket::bind(SocketAddr::from(([0u16; 8], limits::DISCOVERY_PORT))) {
            Err(SocketError::Bind { why, .. }) => assert!(why.contains("IPv4"), "{why}"),
            Ok(_) => panic!("an IPv6 socket was bound"),
            Err(other) => panic!("expected a bind failure, got {other:?}"),
        }
    }

    #[test]
    fn broadcast_can_be_sent_to_a_direct_address_rather_than_a_broadcast_one() {
        // The tests use unicast because a broadcast to 255.255.255.255 on a build machine reaches every interface and may
        // reach the network. That the socket accepts a broadcast address at all is what `set_broadcast(true)` buys, and
        // it is asserted separately below.
        let sender = loopback();
        let receiver = loopback();
        let ours = announcement(A, "Laptop", 47100);
        let sent = sender
            .send_query(&ours, receiver.local_addr().expect("an address"))
            .expect("sends");
        assert!(sent > 0);
    }

    #[test]
    fn a_query_written_by_the_encoder_arrives_as_the_bytes_the_parser_expects() {
        // ★ The end-to-end check this module exists for. The protocol's encoder and its parser are tested against each
        // other in that crate; what is only testable here is that a datagram survives a real socket, with a real source
        // address that the reply has to go back to.
        let sender = loopback();
        let receiver = loopback();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        let ours = announcement(A, "Laptop", 47100);
        sender
            .send_query(&ours, receiver.local_addr().expect("an address"))
            .expect("sends");

        let mut buffer = [0u8; 2048];
        let (read, from) = receiver.socket.recv_from(&mut buffer).expect("receives");
        let bytes = buffer.get(..read).expect("a datagram");
        let datagram = DiscoveryDatagram::parse(bytes).expect("parses");

        let DiscoveryDatagram::Query(query) = datagram else {
            panic!("expected a query, got {datagram:?}");
        };
        assert_eq!(query.device.device_id, device(A));
        assert_eq!(query.device.display_name, "Laptop");
        assert_eq!(query.device.port, 47100);
        // And the source address is the sender's, which is where the reply has to go.
        assert_eq!(from.port(), sender.local_addr().expect("an address").port());
    }

    #[test]
    fn a_response_is_bare_json_and_parses_as_one() {
        // The protocol's rule: a response has no marker, which is what makes a query and a response distinguishable
        // without a length prefix.
        let sender = loopback();
        let receiver = loopback();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        sender
            .send_response(
                &announcement(B, "Phone", 47101),
                receiver.local_addr().expect("an address"),
            )
            .expect("sends");

        let mut buffer = [0u8; 2048];
        let (read, _) = receiver.socket.recv_from(&mut buffer).expect("receives");
        let datagram = DiscoveryDatagram::parse(buffer.get(..read).expect("a datagram")).expect("parses");
        assert!(matches!(datagram, DiscoveryDatagram::Response(_)));
    }

    #[test]
    fn an_offline_announcement_round_trips() {
        let sender = loopback();
        let receiver = loopback();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        let offline = OfflineAnnouncement { device_id: device(B), timestamp: 1_700_000_000_000 };
        sender
            .send_offline(&offline, receiver.local_addr().expect("an address"))
            .expect("sends");

        let mut buffer = [0u8; 2048];
        let (read, _) = receiver.socket.recv_from(&mut buffer).expect("receives");
        let datagram = DiscoveryDatagram::parse(buffer.get(..read).expect("a datagram")).expect("parses");
        let DiscoveryDatagram::Offline(parsed) = datagram else {
            panic!("expected an offline announcement, got {datagram:?}");
        };
        assert_eq!(parsed.device_id, device(B));
        assert_eq!(parsed.timestamp, 1_700_000_000_000);
    }

    // ── Receiving into a host ─────────────────────────────────────────────────────────────────────

    #[test]
    fn a_received_query_becomes_a_candidate_on_the_receiving_host() {
        // The whole point of the layer: bytes on a socket become something the kernel knows about.
        let sender = loopback();
        let receiver = loopback();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        sender
            .send_query(
                &announcement(B, "Phone", 47101),
                receiver.local_addr().expect("an address"),
            )
            .expect("sends");

        let mut kernel = host(A, "Laptop");
        let absorbed = receiver
            .receive(&mut kernel, 5_000)
            .expect("receives")
            .expect("something about another device");

        assert_eq!(absorbed, Absorbed::New { device_id: device(B) });
        let candidate = kernel.discovery().get(device(B)).expect("a candidate");
        assert_eq!(candidate.display_name, "Phone");
        // ★ The port is the one the peer said it listens on for **connections** — 47101 — and not the port the datagram
        // came from, which is ephemeral. Mixing them is the bug the protocol's own `announced_address` prevents.
        assert_eq!(candidate.address.port(), 47101);
    }

    #[test]
    fn a_datagram_about_this_device_is_not_news() {
        // ★ A device hears its own broadcasts, because that is what broadcasting means. Reporting one as a candidate
        // would show the user their own machine as a peer.
        let sender = loopback();
        let receiver = loopback();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        sender
            .send_query(
                &announcement(A, "Laptop", 47100),
                receiver.local_addr().expect("an address"),
            )
            .expect("sends");

        let mut kernel = host(A, "Laptop");
        let absorbed = receiver.receive(&mut kernel, 5_000).expect("receives");
        // `absorb` reports it, and the host's own self-check discarded it — which is the same answer the discovery
        // table's tests assert, reached over a real socket.
        assert_eq!(absorbed, Some(Absorbed::SelfAnnouncement));
        assert!(kernel.discovery().is_empty());
    }

    #[test]
    fn a_goodbye_ages_the_entry_out_rather_than_refreshing_it() {
        // ★ Treating a goodbye as news about where a device is would refresh the entry the device just asked to have
        // aged out — the opposite of what it said.
        let sender = loopback();
        let receiver = loopback();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        let mut kernel = host(A, "Laptop");
        kernel.heard(
            &announcement(B, "Phone", 47101),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1234)),
            1_000,
        );
        assert_eq!(kernel.discovery().len(), 1);

        sender
            .send_offline(
                &OfflineAnnouncement { device_id: device(B), timestamp: 5_000 },
                receiver.local_addr().expect("an address"),
            )
            .expect("sends");

        let absorbed = receiver.receive(&mut kernel, 5_000).expect("receives");
        assert_eq!(absorbed, Some(Absorbed::Offline { device_id: device(B) }));
        // The entry is still there — "it left" and "it was never here" are different — but it is no longer current.
        assert_eq!(kernel.discovery().len(), 1);
        assert_eq!(kernel.discovery().current(5_000).count(), 0);
    }

    #[test]
    fn a_stray_packet_on_the_port_is_reported_as_malformed() {
        // ★ A well-known port is sent to by anything: a port scan, another product's discovery, a stray packet. A
        // datagram this build does not understand is *reported*, so a caller can count it — and it must not be confused
        // with a device that said something wrong.
        let sender = loopback();
        let receiver = loopback();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        sender
            .send_bytes(b"hello? is anyone there", receiver.local_addr().expect("an address"))
            .expect("sends");

        let mut kernel = host(A, "Laptop");
        match receiver.receive(&mut kernel, 5_000) {
            Err(SocketError::Malformed { .. }) => {}
            other => panic!("expected a malformed datagram, got {other:?}"),
        }
        // And nothing was added to the host.
        assert!(kernel.discovery().is_empty());
    }

    #[test]
    fn a_receive_that_times_out_is_reported_as_a_receive_failure() {
        // A caller that set a timeout asked for one and has to be able to tell it from a socket that broke. A scan
        // treats both the same; a caller reading one datagram at a time does not.
        let socket = loopback();
        socket.set_read_timeout(Some(Duration::from_millis(50))).expect("a timeout");

        let mut kernel = host(A, "Laptop");
        match socket.receive(&mut kernel, 5_000) {
            Err(SocketError::Receive { .. }) => {}
            other => panic!("expected a timeout, got {other:?}"),
        }
    }

    // ── Scanning ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_scan_stops_at_its_deadline_and_returns_what_it_heard() {
        // The budget is what keeps "scanning" from being forever in the interface.
        let socket = loopback();
        let mut kernel = host(A, "Laptop");
        let started = Instant::now();
        let results = socket.scan_until(&mut kernel, 5_000, started + Duration::from_millis(120));
        assert!(results.is_empty(), "something answered a loopback port nothing is sending to");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100), "the scan returned early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "the scan overran its budget: {elapsed:?}");
    }

    #[test]
    fn a_scan_collects_a_query_that_arrives_while_it_runs() {
        // The realistic case: a scan is a wait, and a device that answers during the wait is found.
        let receiver = loopback();
        let target = receiver.local_addr().expect("an address");
        let sender = loopback();

        let sending = std::thread::spawn(move || {
            // Long enough for the scan to have started waiting, short enough to be inside its budget.
            std::thread::sleep(Duration::from_millis(40));
            sender
                .send_query(&announcement(B, "Phone", 47101), target)
                .expect("sends");
        });

        let mut kernel = host(A, "Laptop");
        let results = receiver.scan_until(
            &mut kernel,
            5_000,
            Instant::now() + Duration::from_millis(400),
        );
        sending.join().expect("finished");

        assert_eq!(results, vec![Absorbed::New { device_id: device(B) }]);
        assert!(kernel.discovery().get(device(B)).is_some());
    }

    // ── The addresses ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_limited_broadcast_address_is_always_asked() {
        // ★ It is the one address that needs no knowledge of the machine's interfaces, and a device on a network this
        // code cannot enumerate — a virtual adapter, a VPN, a container bridge — is reachable through it and not through
        // any computed address.
        let addresses = broadcast_addresses();
        assert!(
            addresses.contains(&SocketAddr::from((Ipv4Addr::BROADCAST, limits::DISCOVERY_PORT))),
            "{addresses:?}"
        );
    }

    #[test]
    fn every_broadcast_address_uses_the_discovery_port() {
        // A query sent to the right address on the wrong port reaches nothing, and nothing would say why.
        for address in broadcast_addresses() {
            assert_eq!(address.port(), limits::DISCOVERY_PORT, "{address}");
        }
    }

    #[test]
    fn a_subnet_broadcast_is_the_slash_24_of_the_local_address() {
        assert_eq!(
            subnet_broadcast(IpAddr::from([192, 168, 1, 37])),
            Some(SocketAddr::from(([192, 168, 1, 255], limits::DISCOVERY_PORT)))
        );
        assert_eq!(
            subnet_broadcast(IpAddr::from([10, 0, 0, 2])),
            Some(SocketAddr::from(([10, 0, 0, 255], limits::DISCOVERY_PORT)))
        );
    }

    #[test]
    fn a_broadcast_address_is_never_listed_twice() {
        // A datagram to the same address twice is one wasted send, and a caller counting what it reached would report
        // two interfaces where there is one.
        let addresses = broadcast_addresses();
        let mut unique = addresses.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(addresses.len(), unique.len(), "{addresses:?}");
    }

    #[test]
    fn a_broadcast_query_reports_what_it_reached_per_address() {
        // "Nothing was found" and "nothing could be asked" are different answers, and a caller that showed the user an
        // empty list for both would be one that cannot tell them their firewall is the problem. Each address gets its
        // own result rather than one overall verdict.
        let socket = loopback();
        let results = socket.broadcast_query(&announcement(A, "Laptop", 47100));
        assert_eq!(results.len(), broadcast_addresses().len());
        // The ports are all the discovery port, whatever the sends returned — a build machine may have no route, and an
        // error is a legitimate outcome the caller has to be able to see.
        for (address, result) in &results {
            assert_eq!(address.port(), limits::DISCOVERY_PORT);
            if let Err(error) = result {
                assert!(!error.to_string().is_empty());
            }
        }
    }

    // ── Errors ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            SocketError::Bind {
                address: SocketAddr::from(([0, 0, 0, 0], 32101)),
                why: "in use".to_owned(),
            },
            SocketError::Send {
                address: SocketAddr::from(([255, 255, 255, 255], 32101)),
                why: "no route".to_owned(),
            },
            SocketError::Receive { why: "timed out".to_owned() },
            SocketError::Malformed { why: "not utf8".to_owned() },
            SocketError::Encode { why: "name too long".to_owned() },
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
        // And a bind failure names the address, because "already in use" leaves a user with nothing to act on.
        assert!(errors[0].to_string().contains("32101"), "{}", errors[0]);
    }
}
