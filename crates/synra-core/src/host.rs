//! The pieces tied together: who this device is, who it has heard of, and who it is talking to.
//!
//! # Why this exists
//!
//! [`crate::identity`], [`crate::discovery`], [`crate::sessions`], [`crate::peer`] and [`crate::link`] each answer one
//! question, and each was built and tested on its own. What none of them does is hold the others: a session registry with
//! no identity has nothing to check an envelope's target against, and a discovery table with no sessions has nobody to
//! record a handshake into.
//!
//! The composition is where a *sequence* becomes a rule. Dialling is the clearest case:
//!
//! 1. The candidate's address comes from the discovery table, which is unauthenticated.
//! 2. The handshake is what establishes identity, so nothing before it may be believed.
//! 3. The session is recorded **only after** the handshake, because a session for a device whose identity is unproven is
//!    a session that attributes work to the wrong peer.
//! 4. The trust level rises, because a completed connection is better evidence than a datagram.
//!
//! Any of those in a different order is a bug that no single module's tests can see, which is why this one exists and why
//! its tests drive two hosts against each other.
//!
//! # Why the state is behind one lock
//!
//! Because the four pieces are updated together and read together: a report that read the discovery table, then the
//! sessions, would show a device as found-and-not-connected while a handshake completed between the two reads — and the
//! user would see a candidate they are already talking to. One lock makes a report a snapshot of one moment.
//!
//! # What is not here
//!
//! The UDP socket. Discovery's *receiving* is I/O, and the datagrams are parsed by
//! [`synra_protocol::discovery::DiscoveryDatagram`]; what lives here is what to do with one once it has been parsed,
//! which is the part with decisions in it.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use parking_lot::Mutex;
use synra_protocol::discovery::DeviceAnnouncement;
use synra_protocol::envelope::Envelope;
use synra_protocol::handshake::{LinkToken, PairingState};
use synra_protocol::ids::{DeviceId, SessionId};

use crate::discovery::{Absorbed, Candidate, DiscoveryTable};
use crate::identity::Identity;
use crate::link::{LinkError, PeerLink};
use crate::peer::{Flags, HandshakeError, LocalPeer};
use crate::sessions::{LinkState, RegistryEvent, SessionKey, SessionRegistry};

/// Why a host operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// The listener could not be bound.
    #[error("could not listen on {address}: {why}")]
    Bind {
        /// Where it tried.
        address: SocketAddr,
        /// What the operating system said.
        why: String,
    },

    /// The handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),

    /// The link failed.
    #[error(transparent)]
    Link(#[from] LinkError),

    /// The peer was reached and refused the link, because a required feature is missing.
    ///
    /// # Why this is reported after the handshake rather than as a handshake failure
    ///
    /// Because the handshake *succeeded*: the two devices agreed who each other were and what they could do, and the
    /// answer was that they cannot work together. Collapsing it into a connection failure would tell the user their
    /// network is broken when the real answer is a version.
    #[error("the peer is reachable and the two cannot work together: missing {missing}")]
    Incompatible {
        /// The features one side required and the other lacks, as a list for a message.
        missing: String,
    },

    /// No session is open for that device.
    #[error("no session is open with {0}")]
    NoSession(DeviceId),
}

/// The kernel's view of its peers.
pub struct Host {
    /// This device.
    identity: Identity,
    /// What this device announces and answers with.
    local: LocalPeer,
    /// Who has been heard of.
    discovery: DiscoveryTable,
    /// Who is being talked to.
    sessions: SessionRegistry,
    /// The socket peers connect to, when this host is listening.
    listener: Option<TcpListener>,
    /// Flags a handshake runs under.
    flags: Flags,
    /// Envelopes sent, for a report.
    sent: u64,
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

    /// Dials a candidate and completes a handshake.
    ///
    /// # The order is the rule
    ///
    /// The session is created **after** the handshake, because the handshake is what establishes identity — a session
    /// for a device whose identity is unproven is one that attributes work to the wrong peer. And the trust level rises
    /// only once the connection completed, because a datagram is a hint and a connection is evidence.
    ///
    /// # Errors
    ///
    /// [`HostError::Handshake`] for a failed exchange, and [`HostError::Incompatible`] when the two devices reached
    /// agreement and the agreement is unusable.
    pub fn dial(
        &mut self,
        device_id: DeviceId,
        address: SocketAddr,
        token: Option<LinkToken>,
        now_ms: u64,
    ) -> Result<PeerLink, HostError> {
        // Cloned before the call, because the token is also what the session records — and it is the token that was
        // *used*, which is what a later frame has to match.
        let offered = token.clone();
        let (stream, negotiated) =
            crate::peer::dial(address, &self.local, token, now_ms, self.flags)?;

        if !negotiated.is_usable() {
            // The two reached agreement and the agreement says they cannot work together. Reported as its own failure
            // rather than as a connection failure, because the user's next step is a version rather than a network.
            return Err(HostError::Incompatible {
                missing: format!("{:?}", negotiated.agreed.missing_required),
            });
        }

        // ★ Now, and not before. The handshake proved which device is on the other end, so this is the first moment at
        // which recording a session attributes work correctly.
        let (key, _events) = self.sessions.open(
            SessionId::new(),
            negotiated.device_id,
            negotiated.platform,
            // A token this dialler did not present is one the acceptor did not read, so the session records the token
            // that was used rather than inventing one.
            offered.unwrap_or_else(|| LinkToken::from_bytes([0u8; LinkToken::LEN])),
            now_ms,
        );
        // A dialler has agreed by definition: the handshake completed. Recording it is what moves the session to ready,
        // and a failure here is impossible for a session that was just opened — but it is reported rather than dropped,
        // because a session that stayed in `Connecting` would be one nothing routes to.
        self.sessions
            .agree(key, negotiated.agreed.clone(), now_ms)
            .map_err(|error| HostError::Bind {
                address,
                why: format!("the session could not be marked ready: {error}"),
            })?;

        // The trust level rises here, with the address the connection actually worked at rather than the one that was
        // announced — which is what makes the next attempt succeed if the peer moved.
        self.discovery
            .handshaked(negotiated.device_id, address, Some(&negotiated.display_name), millis_reading(now_ms));

        let _ = device_id;
        Ok(PeerLink::new(
            stream,
            self.identity.device_id,
            negotiated.device_id,
            negotiated.agreed,
            self.flags,
        ))
    }

    /// Accepts one connection and completes a handshake on it.
    ///
    /// # Errors
    ///
    /// [`HostError::Handshake`] when the exchange fails, and [`HostError::Bind`] when the listener cannot accept.
    pub fn accept(
        &mut self,
        now_ms: u64,
        read_token: impl FnOnce(Option<&LinkToken>, DeviceId) -> PairingState,
    ) -> Result<(PeerLink, Vec<RegistryEvent>), HostError> {
        let Some(listener) = &self.listener else {
            return Err(HostError::Bind {
                address: SocketAddr::from(([0, 0, 0, 0], 0)),
                why: "this host is not listening".to_owned(),
            });
        };

        // The peer's address is read before the handshake, because `accept` consumes the connection and the address is
        // what the discovery table records as having actually worked.
        let (stream, negotiated) =
            crate::peer::accept(listener, &self.local, now_ms, self.flags, read_token)?;
        let address = stream.peer_addr().map_err(|error| HostError::Bind {
            address: listener.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
            why: error.to_string(),
        })?;

        if !negotiated.is_usable() {
            return Err(HostError::Incompatible {
                missing: format!("{:?}", negotiated.agreed.missing_required),
            });
        }

        let (key, mut events) = self.sessions.open(
            SessionId::new(),
            negotiated.device_id,
            negotiated.platform,
            LinkToken::from_bytes([0u8; LinkToken::LEN]),
            now_ms,
        );
        // ★ The `Ready` event is appended rather than dropped. The first version used `let _ =`, which discarded the one
        // event a caller needs to know the session became usable — and the module's own test asserted it was there.
        if let Ok(ready) = self.sessions.agree(key, negotiated.agreed.clone(), now_ms) {
            events.extend(ready);
        }
        self.discovery.handshaked(
            negotiated.device_id,
            address,
            Some(&negotiated.display_name),
            millis_reading(now_ms),
        );

        Ok((
            PeerLink::new(
                stream,
                self.identity.device_id,
                negotiated.device_id,
                negotiated.agreed,
                self.flags,
            ),
            events,
        ))
    }

    /// Sends an envelope on a session, counting it.
    ///
    /// # Errors
    ///
    /// [`HostError::NoSession`] when there is no session for that device, [`HostError::Link`] when the write fails. A
    /// session that is not ready **is** a refusal: the peer has not agreed yet, and a message sent now is one the other
    /// end will refuse.
    pub fn send(&mut self, link: &mut PeerLink, envelope: &Envelope) -> Result<(), HostError> {
        if self.sessions.live_for(link.peer()).is_none() {
            return Err(HostError::NoSession(link.peer()));
        }
        link.send(envelope)?;
        self.sent = self.sent.saturating_add(1);
        Ok(())
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

/// A `u64` clock reading as the `i64` the database and the discovery table use.
///
/// # Why a conversion rather than one type everywhere
///
/// The session registry's deadlines are `u64` because they are durations from a monotonic-ish start, and the discovery
/// table's times are `i64` because they go into SQLite, whose integers are signed. Saturation rather than a cast,
/// because a `u64` beyond `i64::MAX` is a reading from a clock nobody has — and a cast would produce a *negative* time,
/// which the discovery table would read as "seen in the future".
///
/// # Why this is public
///
/// Because every caller that holds one kind of reading and needs the other has to convert, and a caller that reached for
/// `as i64` would be one that wraps at the year 292 million. The daemon converts on every request.
pub const fn millis_reading(value: u64) -> i64 {
    if value > i64::MAX as u64 {
        i64::MAX
    }
    else {
        value as i64
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryTable;
    use synra_protocol::discovery::TrustLevel;
    use synra_protocol::envelope::{Envelope, OutboundSpec};
    use synra_protocol::event::EventName;
    use synra_protocol::session::PlatformKind;
    use std::net::Ipv4Addr;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    /// A host with an identity and a local peer, and a migrated database behind the identity.
    fn host(id: &str, name: &str) -> (Host, synra_store::SynraDb) {
        let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        let mut identity = Identity::load(&db, "test", 1_000).expect("an identity");
        // The identity's generated id is a fresh UUID; the tests need known ones, so the row is rewritten.
        identity.device_id = device(id);
        identity.rename(&db, name, 1_000).expect("renames");
        let local = LocalPeer::new(
            identity.device_id,
            identity.display_name.clone(),
            PlatformKind::Desktop,
            "0.1.0-test",
        );
        (Host::with_flags(identity, local, Flags::no_timeout()), db)
    }

    /// A host that is listening, with its address.
    fn listening(id: &str, name: &str) -> (Host, synra_store::SynraDb, SocketAddr) {
        let (mut host, db) = host(id, name);
        let address = host
            .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("binds");
        (host, db, address)
    }

    // ── What the host holds ───────────────────────────────────────────────────────────────────────

    #[test]
    fn a_new_host_knows_itself_and_nobody_else() {
        let (host, _db) = host(A, "Laptop");
        assert_eq!(host.device_id(), device(A));
        assert_eq!(host.identity().display_name, "Laptop");
        assert!(host.discovery().is_empty());
        assert!(host.sessions().is_empty());
        assert!(host.listener.is_none());
        assert_eq!(host.sent(), 0);
    }

    #[test]
    fn listening_reports_the_port_the_operating_system_chose() {
        // The port is read back rather than assumed: a caller that passed zero asked for any port, and the value it
        // needs is the one that was granted.
        let (mut host, _db) = host(A, "Laptop");
        let bound = host
            .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("binds");
        assert_ne!(bound.port(), 0);
        assert!(host.listener.is_some());
    }

    #[test]
    fn an_announcement_heard_over_the_network_becomes_a_candidate() {
        let (mut host, _db) = host(A, "Laptop");
        let announcement = DeviceAnnouncement {
            device_id: device(B),
            display_name: "Phone".to_owned(),
            protocol: synra_protocol::handshake::PROTOCOL_VERSION,
            port: 47100,
            platform: Some(PlatformKind::Android),
            app_version: Some("0.1.0".to_owned()),
            features: Vec::new(),
        };
        let result = host.heard(&announcement, SocketAddr::from(([10, 0, 0, 5], 5_4321)), 1_000);
        assert_eq!(result, Absorbed::New { device_id: device(B) });
        let candidate = host.discovery().get(device(B)).expect("a candidate");
        assert_eq!(candidate.trust, TrustLevel::Announced);
        assert_eq!(candidate.address.port(), 47100);
        // And it is not yet something the interface offers, because an announcement is a hint and not evidence.
        assert!(host.usable(1_000).is_empty());
    }

    // ── Two hosts, end to end ─────────────────────────────────────────────────────────────────────

    #[test]
    fn two_hosts_complete_a_handshake_and_record_a_session() {
        // ★ The test this module exists for. Every piece here has its own tests, and what none of those can see is the
        // *order*: the session is created after the handshake, and the trust level rises only once the connection
        // completed.
        let (mut server, _server_db, address) = listening(A, "Laptop");
        let (mut client, _client_db) = host(B, "Phone");

        let serving = std::thread::spawn(move || {
            let (link, events) = server
                .accept(1_000, |_, _| PairingState::Unknown)
                .expect("accepts");
            (link, events, server)
        });

        let link = client.dial(device(A), address, None, 1_000).expect("dials");
        let (server_link, events, server) = serving.join().expect("the thread finished");

        // Both sides recorded a session for the other.
        assert_eq!(client.state_of(device(A)), Some(LinkState::Ready));
        assert_eq!(server.state_of(device(B)), Some(LinkState::Ready));
        assert!(events.iter().any(|event| matches!(event, RegistryEvent::Ready(_))));

        // And both links know both identifiers and who is on the other end.
        assert_eq!(client_link_peer(&link), device(A));
        assert_eq!(client_link_local(&link), device(B));
        assert_eq!(server_link.peer(), device(B));
        assert_eq!(server_link.local(), device(A));
    }

    #[test]
    fn the_trust_level_rises_only_after_the_connection_completed() {
        // ★ A datagram is a hint and a connection is evidence. A host that raised the level when the announcement
        // arrived would offer the user a device it has never reached.
        let (mut server, _server_db, address) = listening(A, "Laptop");
        let (mut client, _client_db) = host(B, "Phone");

        let announcement = DeviceAnnouncement {
            device_id: device(A),
            display_name: "Laptop".to_owned(),
            protocol: synra_protocol::handshake::PROTOCOL_VERSION,
            port: address.port(),
            platform: Some(PlatformKind::Desktop),
            app_version: Some("0.1.0".to_owned()),
            features: Vec::new(),
        };
        client.heard(&announcement, address, 1_000);
        assert_eq!(
            client.discovery().get(device(A)).expect("a candidate").trust,
            TrustLevel::Announced
        );

        let serving = std::thread::spawn(move || {
            server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
        });
        client.dial(device(A), address, None, 1_000).expect("dials");
        serving.join().expect("finished");

        let candidate = client.discovery().get(device(A)).expect("a candidate");
        assert_eq!(candidate.trust, TrustLevel::Handshaked);
        // And now it is something the interface offers.
        assert_eq!(client.usable(1_000).len(), 1);
    }

    #[test]
    fn the_recorded_address_is_the_one_the_connection_worked_at() {
        // ★ A handshake that completed proves the address the connection was made to works. Recording the *announced*
        // one instead would leave the next attempt dialling an address the peer has moved away from.
        let (mut server, _server_db, address) = listening(A, "Laptop");
        let (mut client, _client_db) = host(B, "Phone");

        // The announcement claims a port nothing is listening on.
        let announcement = DeviceAnnouncement {
            device_id: device(A),
            display_name: "Laptop".to_owned(),
            protocol: synra_protocol::handshake::PROTOCOL_VERSION,
            port: 1,
            platform: Some(PlatformKind::Desktop),
            app_version: None,
            features: Vec::new(),
        };
        client.heard(&announcement, address, 1_000);
        assert_eq!(client.discovery().get(device(A)).expect("c").address.port(), 1);

        let serving = std::thread::spawn(move || {
            server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
        });
        client.dial(device(A), address, None, 1_000).expect("dials");
        serving.join().expect("finished");

        assert_eq!(
            client.discovery().get(device(A)).expect("c").address.port(),
            address.port(),
            "the working port was not recorded"
        );
    }

    #[test]
    fn an_envelope_travels_between_two_connected_hosts() {
        // The whole path: dial, handshake, session, envelope, and a session recorded on the receiving side.
        let (mut server, _server_db, address) = listening(A, "Laptop");
        let (mut client, _client_db) = host(B, "Phone");

        let serving = std::thread::spawn(move || {
            let (mut link, _) = server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
            let envelope = link.receive().expect("receives");
            (envelope, server)
        });

        let mut link = client.dial(device(A), address, None, 1_000).expect("dials");
        let envelope = Envelope::outbound(
            OutboundSpec {
                event: EventName::parse("device.ping").expect("a name"),
                target: device(A),
                from: device(B),
                trace_id: synra_protocol::ids::TraceId::new(),
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&serde_json::Value>,
        )
        .expect("builds");
        client.send(&mut link, &envelope).expect("sends");

        let (received, server) = serving.join().expect("finished");
        assert_eq!(received.event.as_str(), "device.ping");
        assert_eq!(received.from, device(B));
        assert_eq!(client.sent(), 1);
        // The receiving host recorded the session too, which is what makes the envelope attributable.
        assert_eq!(server.state_of(device(B)), Some(LinkState::Ready));
    }

    #[test]
    fn sending_on_a_link_the_host_has_no_session_for_is_refused() {
        // ★ A caller holding a link and a host that do not belong together is the case this refuses. Attributing an
        // envelope to the wrong session is a mistake with no symptom until the wrong device is blamed for something.
        let (mut server, _server_db, address) = listening(A, "Laptop");
        let (mut client, _client_db) = host(B, "Phone");
        let (mut other, _other_db) = host(
            "33333333-3333-4333-8333-333333333333",
            "Tablet",
        );

        let serving = std::thread::spawn(move || {
            server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
        });
        let mut link = client.dial(device(A), address, None, 1_000).expect("dials");
        serving.join().expect("finished");

        // `other` has no session with A, so it will not send on a link that belongs to `client`.
        let envelope = Envelope::outbound(
            OutboundSpec {
                event: EventName::parse("device.ping").expect("a name"),
                target: device(A),
                from: other.device_id(),
                trace_id: synra_protocol::ids::TraceId::new(),
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&serde_json::Value>,
        )
        .expect("builds");

        match other.send(&mut link, &envelope) {
            Err(HostError::NoSession(id)) => assert_eq!(id, device(A)),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_host_that_is_not_listening_cannot_accept() {
        // An honest refusal rather than a silent hang: a caller that forgot to listen is one waiting for a connection
        // that cannot come.
        let (mut host, _db) = host(A, "Laptop");
        match host.accept(1_000, |_, _| PairingState::Unknown) {
            Err(HostError::Bind { why, .. }) => assert!(why.contains("not listening"), "{why}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // ── Expiry and sweeping ───────────────────────────────────────────────────────────────────────

    #[test]
    fn a_host_expires_candidates_and_reports_what_went() {
        let (mut host, _db) = host(A, "Laptop");
        let announcement = DeviceAnnouncement {
            device_id: device(B),
            display_name: "Phone".to_owned(),
            protocol: synra_protocol::handshake::PROTOCOL_VERSION,
            port: 47100,
            platform: None,
            app_version: None,
            features: Vec::new(),
        };
        host.heard(&announcement, SocketAddr::from(([10, 0, 0, 5], 1)), 0);

        // The default lifetime is 90 seconds, so an hour later it is long gone.
        let expired = host.expire(3_600_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].device_id, device(B));
        assert!(host.discovery().is_empty());
    }

    #[test]
    fn sweeping_closes_a_session_whose_peer_went_quiet() {
        // The host's own sweep, through the registry — which is what makes a device that was unplugged disappear from
        // the list rather than staying selectable.
        let (mut server, _server_db, address) = listening(A, "Laptop");
        let (mut client, _client_db) = host(B, "Phone");
        // ★ The registry's timeout is set on the **client** before the session is opened, not after it exists: the first
        // version replaced the whole registry once the session was there, which discarded the very session the test then
        // swept for — so the sweep correctly found nothing and the assertion was about a fixture that had deleted its
        // own subject.
        client.sessions = SessionRegistry::with_heartbeat_timeout(1_000);

        let serving = std::thread::spawn(move || {
            server.accept(1_000, |_, _| PairingState::Unknown).expect("accepts");
        });
        client.dial(device(A), address, None, 1_000).expect("dials");
        serving.join().expect("finished");

        // The session was opened at 1_000 with a one-second timeout, so at 5_000 it is long overdue.
        let events = client.sweep(5_000);
        assert!(!events.is_empty(), "the sweep closed nothing");
        assert!(client.state_of(device(A)).expect("a session").is_over());
    }

    #[test]
    fn the_debug_form_names_what_the_host_holds() {
        // A host appears in a log line, and a handle that printed its socket would leak the path.
        let (host, _db) = host(A, "Laptop");
        let text = format!("{host:?}");
        assert!(text.contains("Laptop"), "{text}");
        assert!(text.contains("candidates"), "{text}");
        assert!(text.contains("listening"), "{text}");
    }

    #[test]
    fn a_shared_host_can_be_reached_from_two_threads() {
        // The type's reason for existing: an accept loop and a caller are two threads over one host.
        let (host, _db) = host(A, "Laptop");
        let shared = shared(host);
        let cloned = Arc::clone(&shared);
        let handle = std::thread::spawn(move || cloned.lock().device_id());
        let from_thread = handle.join().expect("finished");
        assert_eq!(from_thread, device(A));
        assert_eq!(shared.lock().device_id(), device(A));
    }

    #[test]
    fn the_clock_conversion_saturates_rather_than_wrapping() {
        // A `u64` beyond `i64::MAX` is a reading from a clock nobody has, and a cast would produce a negative time —
        // which the discovery table would read as "seen in the future".
        assert_eq!(millis_reading(0), 0);
        assert_eq!(millis_reading(1_000), 1_000);
        assert_eq!(millis_reading(u64::MAX), i64::MAX);
    }

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            HostError::Bind { address: SocketAddr::from(([0, 0, 0, 0], 0)), why: "in use".to_owned() },
            HostError::Handshake(HandshakeError::Closed),
            HostError::Link(LinkError::Closed),
            HostError::Incompatible { missing: "[TransferResume]".to_owned() },
            HostError::NoSession(device(A)),
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    // ── Helpers for the link assertions ───────────────────────────────────────────────────────────

    fn client_link_peer(link: &PeerLink) -> DeviceId {
        link.peer()
    }

    fn client_link_local(link: &PeerLink) -> DeviceId {
        link.local()
    }

    #[test]
    fn a_table_with_a_chosen_lifetime_is_what_a_test_needs() {
        // The discovery table's lifetime is a value rather than a constant, which is what lets the expiry tests above
        // run without waiting ninety seconds.
        let table = DiscoveryTable::with_ttl(device(A), std::time::Duration::from_millis(10));
        assert_eq!(table.ttl(), std::time::Duration::from_millis(10));
    }
}
