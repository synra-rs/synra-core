use std::net::{SocketAddr, TcpListener};

use synra_protocol::discovery::DeviceAnnouncement;
use synra_protocol::handshake::LinkToken;
use synra_protocol::ids::DeviceId;

use crate::discovery::{Absorbed, DiscoveryTable};
use crate::identity::{Identity, check_display_name};
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
    /// Where this host's numbers go, when anybody is keeping them.
    ///
    /// ★ Optional on the same terms the plugin host's recorder is: a host that keeps no numbers is a host, not a broken
    /// one, and a send that failed because a *metric* could not be written would be a message refused for a reason
    /// neither end can see or act on.
    pub(super) metrics: Option<std::sync::Arc<synra_observe::metrics::RingRecorder>>,
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
            metrics: None,
        }
    }

    /// A host with chosen flags, for a test that must not depend on the clock.
    #[must_use]
    pub fn with_flags(identity: Identity, local: LocalPeer, flags: Flags) -> Self {
        let mut host = Self::new(identity, local);
        host.flags = flags;
        host
    }

    /// Sends this host's numbers to a recorder.
    ///
    /// A builder rather than an argument on [`Host::new`], because the two places a host is built — the daemon and a
    /// hundred tests — should not each have to say where the numbers go when most of them keep none.
    #[must_use]
    pub fn with_metrics(mut self, metrics: std::sync::Arc<synra_observe::metrics::RingRecorder>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Counts one frame this host sent, by event.
    ///
    /// ★ Since 2026-10-19 the frame counters live on `PeerLink`, which records every frame — including the offer and
    /// pairing frames a dialled link writes outside this host. `Host::send` therefore does **not** call this, and a caller
    /// that did would double the frame; it remains for a host whose link has no recorder, and the shell's wiring test uses
    /// it to prove the recorder reached the host.
    pub fn count_frame_sent(&mut self, event: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "frames_sent_total",
                [("event".to_owned(), event.to_owned())],
            ));
        }
    }

    /// Counts one link this host opened.
    ///
    /// Recorded where the session opens rather than when it closes, because that is the event: a link that opened and
    /// then failed to be marked ready **did** open, and a count that hid it would make two different failures look
    /// like one.
    pub fn count_link_opened(&mut self) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "links_opened_total",
                Vec::new(),
            ));
        }
    }

    /// Counts one link the listener stopped serving, by why it ended.
    ///
    /// # Why this is recorded by the listener and not by the session registry
    ///
    /// Because the reason lives in the read loop: a `Bye` is `Closed`, a peer that went quiet is `TimedOut`, a frame the
    /// decoder refused is `protocol`, and the loop is the only place that knows which happened. The registry closes a
    /// session with a reason of its own, but that reason names the **session** lifecycle, not the wire's last moment.
    pub fn count_link_closed(&mut self, reason: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "links_closed_total",
                [("reason".to_owned(), reason.to_owned())],
            ));
        }
    }

    /// Counts one attempt to deliver a late answer, by outcome.
    ///
    /// # Why the counter is not named `reconnect_attempts_total`
    ///
    /// Because this device does not reconnect: it dials the origin of an answer once, retries a bounded number of times,
    /// and gives up. The design names a counter for a mechanism that does not exist yet; giving this one the truthful name
    /// keeps "the kernel retried a late answer" from being read as "the kernel keeps links alive".
    pub fn count_late_delivery(&mut self, outcome: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "late_delivery_attempts_total",
                [("outcome".to_owned(), outcome.to_owned())],
            ));
        }
    }

    /// Counts one frame this host received, by event.
    ///
    /// ★ A separate method rather than one with a direction: a device that talks more than it is told, and one that is
    /// told more than it talks, are two different situations. Since the frame counters moved onto `PeerLink` — which sees
    /// every frame, including the ones a dialled link writes outside this host — **nothing in production calls this**. It
    /// is kept because a host whose link has no recorder still needs a way to say "this frame arrived", and the shell's
    /// wiring test uses it; a caller that counts both this and the link would double the frame.
    pub fn count_frame_received(&mut self, event: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "frames_received_total",
                [("event".to_owned(), event.to_owned())],
            ));
        }
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

    /// What this device announces as its name.
    ///
    /// Read through the host rather than off the identity because the host holds its own copy: a caller that reads
    /// `identity.display_name` after a rename has proved nothing about the name that goes out on the wire.
    #[must_use]
    pub fn announced_name(&self) -> &str {
        &self.local.display_name
    }

    /// Applies a rename to every copy this host announces.
    ///
    /// # Why this exists rather than a setter the caller reaches for
    ///
    /// Because the host holds the name twice — in [`Identity`] and in [`LocalPeer`] — and the second is the one that
    /// goes into every handshake. A rename that updates only the first leaves two devices that disagree about each
    /// other's name until something restarts, which is the kind of fault that gets reported as "it only fixes itself
    /// when I reopen the app".
    ///
    /// # Errors
    ///
    /// [`HostError::Unnameable`] when [`check_display_name`] refuses it — which is the *same* check
    /// [`Identity::rename`] makes, not a stricter one. Two rules here would mean a name the identity accepts and the
    /// host refuses, so a rename would succeed and then leave the two copies disagreeing — the exact fault this method
    /// exists to remove.
    ///
    /// # Why the *checked* name is stored rather than the one handed in
    ///
    /// Because [`check_display_name`] trims before it validates, so `" padded "` is a name and its checked form is
    /// `"padded"`. [`Identity::rename`] stores the checked form; storing the original here would leave the two copies
    /// differing by exactly the whitespace — which is the fault this method exists to prevent, introduced by the fix
    /// for it.
    pub fn rename_self(&mut self, name: &str) -> Result<(), HostError> {
        let checked = check_display_name(name).map_err(|_| HostError::Unnameable {
            name: name.chars().take(24).collect(),
        })?;
        self.identity.display_name = checked.clone();
        self.local.display_name = checked;
        Ok(())
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
