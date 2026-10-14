//! The listening half of the session layer.
//!
//! # Why the daemon needs this at all
//!
//! [`synra_core::Host::dial`] makes an *outbound* link, and a device that can only dial is a device nobody can send to. The
//! announcement every device broadcasts carries a port, and that port is this: a TCP listener that accepts an inbound
//! connection, completes a handshake, and reads what arrives on it.
//!
//! # The shape of the loop, and why it is two phases
//!
//! Taking a connection and handshaking on it are wildly different lengths — a queue pop against a read with a six-second
//! timeout. So the loop **pops** under the host's lock, which is cheap, and hands the socket to a thread that handshakes on
//! it. A loop that did both would hold the host for as long as a peer took to say `Hello`, and a peer that connected and
//! then went silent would freeze `devices` for six seconds — the report a user runs *while* something is wrong.
//!
//! # Why an inbound message is only reported
//!
//! Because there is nowhere to put it yet: the event bus, the plugin host and the interface are all downstream of this, and
//! a message that arrived has to reach them. What this establishes is the part that can be established now — that a peer
//! can connect, that the handshake identifies it, that an envelope arrives and passes the link's checks, and that the
//! session is recorded. Reporting it is the honest end of that chain rather than pretending to deliver it.
//!
//! # Why the accept loop never stops on an error
//!
//! Because the errors it can see are all about *one* connection: a peer that disconnected mid-handshake, a port scan, a
//! malformed frame. A listener that exited on any of those would be one any process on the network could stop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use synra_core::host::Host;
use synra_core::link::{LinkError, PeerLink};

/// How long the accept loop waits between polls when nothing is waiting.
///
/// The listener is non-blocking so the loop can also check its stop flag. A blocking accept would be a thread that could
/// not be asked to stop, which is a thread that outlives its process's shutdown.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// What one accepted connection produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The device on the other end, when the handshake established one.
    ///
    /// `None` for a connection that failed before `Hello` — which is the ordinary shape of a port scan and of a peer that
    /// connected and went silent. A sentinel identifier would be one a caller could mistake for a real device, and a
    /// device whose identifier is all zeroes is not a device.
    pub peer: Option<synra_protocol::ids::DeviceId>,
    /// The event names that arrived, in order.
    ///
    /// Names rather than the envelopes, because an envelope holds a `RawValue` payload and a caller that is only reporting
    /// does not need it. The count is what a test asserts; the names are what a log line says.
    pub events: Vec<String>,
    /// How the session ended, when it ended badly.
    pub ended: Option<String>,
}

/// Serves inbound connections until asked to stop.
///
/// # Why the stop flag is shared rather than owned
///
/// Because the daemon's shutdown is a flag its `Ctrl-C` handler sets, and a listener that ignored it would keep a socket
/// bound until the process was killed — so a restart would fail to bind for as long as the old process lingered.
pub fn serve(host: &Arc<Mutex<Host>>, stop: &Arc<AtomicBool>) {
    // ★ Non-blocking, so the loop comes round often enough to notice the stop flag. Set once rather than per iteration:
    // it is a property of the socket, and re-setting it fifty times a second would be a syscall per poll for nothing.
    match host.lock().listen_nonblocking() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("synra-daemon: the transport listener could not become non-blocking: {error}");
            return;
        }
    }

    // ★ `stop` here is the daemon's "keep running" flag — `beating` is *set* to `false` when the loop should end, so the
    // condition is `load()` and not `!load()`. The first version had it inverted, and the loop therefore exited on its
    // first check and never accepted anything: a device that bound its port, announced it, and silently refused every
    // connection. The name is what misled me, and the parameter is now documented rather than renamed because every
    // other reader of the flag calls it the same thing.
    while stop.load(Ordering::Relaxed) {
        // ★ One critical section, and it is a queue pop. The guard is dropped before the thread is spawned, because the
        // handshake happens there — see the module docs for why the two cannot be one step.
        let taken = { host.lock().try_accept() };

        match taken {
            Ok(Some(stream)) => {
                let host = Arc::clone(host);
                // A thread per connection, because a link's lifetime is a peer's to decide. Nothing joins it: a link that
                // ended is one whose thread returns, and one that is still open is doing useful work.
                std::thread::spawn(move || {
                    let served = handle(&host, stream);
                    if let Some(ended) = &served.ended {
                        let who = served
                            .peer
                            .map_or_else(|| "an unidentified peer".to_owned(), |peer| peer.to_string());
                        eprintln!("synra-daemon: {who} disconnected: {ended}");
                    }
                });
            }
            // Nothing waiting, which is the ordinary case for a device on a quiet network.
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(error) => {
                eprintln!("synra-daemon: the transport listener could not accept: {error}");
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

/// Handshakes on a connection and reads what arrives.
///
/// # Why the token check is always `Unknown`
///
/// Because pairing is not written yet, and `Unknown` is the protocol's own word for "this device has no record of that
/// pairing" — which is the true answer for a build with no pairing table. It is deliberately **not** `Current`, because
/// claiming a pairing that does not exist would tell a peer its token is still good.
#[must_use]
pub fn handle(host: &Arc<Mutex<Host>>, stream: std::net::TcpStream) -> Served {
    handle_within(host, stream, synra_protocol::limits::HELLO_TIMEOUT)
}

/// Handshakes on a connection with a chosen deadline for the exchange.
///
/// # Why the deadline is set here rather than left to `Flags`
///
/// Because `Flags` governs the *dialling* side, and a listener has no flags of its own — an inbound connection is not
/// something this kernel initiated, so there is no caller to have chosen them. Without a deadline the reading half blocks
/// for ever, and a peer that connects and then says nothing holds a thread and a socket until the process ends. The
/// protocol's own handshake timeout is the right figure: it is how long every other part of the kernel believes a `Hello`
/// may take.
#[must_use]
pub fn handle_within(
    host: &Arc<Mutex<Host>>,
    stream: std::net::TcpStream,
    timeout: Duration,
) -> Served {
    // ★ Set on the stream before anything reads from it. A peer that connects and goes silent — a port scan, another
    // product's client — is bounded by this rather than by the process's lifetime.
    if let Err(error) = stream.set_read_timeout(Some(timeout)) {
        return Served { peer: None, events: Vec::new(), ended: Some(error.to_string()) };
    }
    let now = synra_u64(synra_store::sqlite::now_ms());

    // ★ One critical section for the handshake, and the link is taken **out** of the host with it. The read loop below
    // runs with no lock held at all: a peer that says nothing for an hour would otherwise hold the host for an hour, and
    // every `devices` and `send` in that time would wait behind it.
    let handshake = {
        let mut host = host.lock();
        host.complete_handshake(stream, now, |_, _| {
            synra_protocol::handshake::PairingState::Unknown
        })
    };

    let (mut link, _events) = match handshake {
        Ok(pair) => pair,
        Err(error) => {
            // A failed handshake has no peer to name, so the address is what identifies it in a log line. The peer's own
            // identifier is exactly what the handshake was establishing, and it is not known.
            return Served { peer: None, events: Vec::new(), ended: Some(error.to_string()) };
        }
    };

    let peer = link.peer();
    let mut events = Vec::new();
    loop {
        match link.receive() {
            Ok(envelope) => {
                events.push(envelope.event.as_str().to_owned());
                // ★ The message is dropped rather than delivered, and said out loud. There is no event bus wired to this
                // daemon yet, and a kernel that silently discarded what a peer sent would be one whose user is told a
                // message arrived when it did not.
                eprintln!(
                    "synra-daemon: {} sent {} ({} bytes of payload) — nothing is listening for events yet",
                    peer,
                    envelope.event.as_str(),
                    envelope.payload.as_ref().map_or(0, |payload| payload.get().len()),
                );
            }
            // A `Bye` is the ordinary end, and so is a peer that hung up. Neither is a fault, and both end the loop.
            Err(LinkError::Closed) => {
                return Served { peer: Some(peer), events, ended: None };
            }
            Err(error) => {
                return Served { peer: Some(peer), events, ended: Some(error.to_string()) };
            }
        }
    }
}

/// Binds the transport port for inbound connections.
///
/// # Errors
///
/// Whatever [`Host::listen_on`] reports, so the caller can decide whether it is fatal. The daemon does **not** treat it as
/// fatal: a device that cannot listen is one nobody can send to, which is worse than a device that cannot start only in
/// the sense that it is quieter.
pub fn bind(host: &mut Host, port: u16) -> Result<SocketAddr, synra_core::HostError> {
    host.listen_on(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)))
}

/// A reading as the `u64` the session registry counts in.
///
/// Saturating, because a negative reading is a clock before the epoch and a wrap would put a deadline in the distant
/// future — a session that never expires.
const fn synra_u64(value: i64) -> u64 {
    if value < 0 { 0 } else { value as u64 }
}

/// What a link reported, for a test that drives one without a daemon.
#[must_use]
pub const fn is_open(link: &PeerLink) -> bool {
    !link.peer().is_nil()
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_core::identity::Identity;
    use synra_core::peer::{Flags, LocalPeer};
    use synra_protocol::ids::DeviceId;
    use synra_protocol::session::PlatformKind;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    /// A host that is listening, with the port it got.
    ///
    /// # Why the listener is non-blocking here
    ///
    /// Because that is what makes [`Host::try_accept`] a *poll*, which is how the daemon runs it and how every test that
    /// drives a connection uses it. A blocking listener makes the first `try_accept` block until somebody connects — so a
    /// server thread waiting to accept and a client thread waiting for its `HelloAck` wait for each other, and the test
    /// hangs rather than failing. Two rounds were spent on that, and the arrangement is now the default rather than
    /// something each test has to remember.
    fn listening(id: &str, name: &str) -> (Arc<Mutex<Host>>, SocketAddr) {
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
        // `Flags::no_timeout` so a test never waits six seconds for a peer that is not coming.
        let mut host = Host::with_flags(identity, local, Flags::no_timeout());
        let address = bind(&mut host, 0).expect("binds");
        host.listen_nonblocking().expect("non-blocking");
        (Arc::new(Mutex::new(host)), address)
    }

    /// Takes a connection, waiting a bounded time for one to appear.
    ///
    /// # Why the wait is needed rather than an `expect`
    ///
    /// Because `TcpStream::connect` returns on this side once the handshake is under way, and the pending connection is
    /// not always visible to `accept` at that instant. A test that expected it immediately passed on an idle machine and
    /// failed when the rest of the suite was running — a flake, which is worse than a failure because it teaches people to
    /// re-run rather than to read.
    ///
    /// Returns `None` when nothing arrived before the deadline.
    fn accept_within(
        host: &Arc<Mutex<Host>>,
        timeout: Duration,
    ) -> Option<std::net::TcpStream> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // The guard is dropped at the end of this statement, so nothing is held across the sleep or the loop.
            let taken = host.lock().try_accept();
            match taken {
                Ok(Some(stream)) => return Some(stream),
                Ok(None) => {}
                Err(error) => panic!("the listener could not accept: {error}"),
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Two connected streams, as an established link would have.
    fn connected_pair() -> (std::net::TcpStream, std::net::TcpStream) {        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let address = listener.local_addr().expect("an address");
        let dialer = std::net::TcpStream::connect(address).expect("connects");
        let (accepted, _) = listener.accept().expect("accepts");
        (dialer, accepted)
    }

    /// A host that is not listening, for the dialling side of a test.
    fn client_host(id: &str, name: &str) -> (Host, synra_store::SynraDb) {
        let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        let mut identity = Identity::load(&db, "test", 1_000).expect("an identity");
        identity.device_id = device(id);
        identity.rename(&db, name, 1_000).expect("renames");
        let local = LocalPeer::new(
            identity.device_id,
            identity.display_name.clone(),
            PlatformKind::Android,
            "0.1.0-test",
        );
        (Host::with_flags(identity, local, Flags::no_timeout()), db)
    }

    /// The address a test dials.
    ///
    /// # Why the bound address is not dialled directly
    ///
    /// Because it is `0.0.0.0`, which means "every interface" to a listener and is not a destination — Windows refuses it
    /// with `WSAEADDRNOTAVAIL`. A real peer gets the address from an announcement or a discovery datagram's source, so the
    /// loopback form is what a test should use.
    fn dialable(address: SocketAddr) -> SocketAddr {
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, address.port()))
    }

    // ── Binding ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn binding_reports_the_port_the_operating_system_chose() {
        // The port is read back rather than assumed, because it is what the announcement carries — and a device that
        // announced a port nothing is listening on is one that appears in every list and cannot be reached.
        let (_host, address) = listening(A, "Laptop");
        assert_ne!(address.port(), 0);
        assert_eq!(address.ip(), std::net::IpAddr::from([0, 0, 0, 0]));
    }

    #[test]
    fn a_host_that_is_not_listening_cannot_be_polled() {
        let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        let identity = Identity::load(&db, "test", 1_000).expect("an identity");
        let local = LocalPeer::new(
            identity.device_id,
            identity.display_name.clone(),
            PlatformKind::Desktop,
            "0.1.0-test",
        );
        let host = Host::with_flags(identity, local, Flags::no_timeout());

        // An honest refusal rather than a silent `Ok(None)`: a loop that polled this would spin for ever and never say why.
        assert!(host.try_accept().is_err());
        assert!(host.listen_nonblocking().is_err());
    }

    #[test]
    fn a_non_blocking_listener_reports_nothing_waiting_rather_than_blocking() {
        // ★ "Nothing is waiting" is not a failure, and a loop that treated it as one would exit on its first quiet
        // moment. The assertion is that it returns — a blocking accept here would hang the test rather than fail it.
        let (host, _address) = listening(A, "Laptop");
        // Non-blocking, because that is what makes `try_accept` a *poll*. Without this the call blocks on an empty backlog
        // and the test hangs rather than failing — which is exactly what an earlier edit of this file did, by removing the
        // line and leaving a blocking accept behind.
        host.lock().listen_nonblocking().expect("non-blocking");
        assert!(host.lock().try_accept().expect("polls").is_none());
    }

    // ── A whole connection ────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_inbound_connection_is_handshaked_and_its_message_is_read() {
        // ★ The thing this module exists for: a device that can only dial is a device nobody can send to.
        //
        // ★ Both sides are on **production flags**, and that is not incidental — it is what makes this the daemon's
        // configuration rather than a test's. Every other test in this module uses `no_timeout` so that a wait never
        // happens, and an earlier version of this one mixed the two: a client with no deadline against a server that set
        // one. `handle_within` puts a deadline on the stream it is given, so a client that never times out and a server
        // that does will disagree about when the conversation is over.
        let (host, address) = listening(A, "Laptop");
        host.lock().set_flags(Flags::production());
        // ★ Non-blocking, as the real daemon runs it: a connection accepted from a non-blocking listener **inherits** that
        // mode on Windows, so every read on it fails with `WSAEWOULDBLOCK` and the message arrives as a transport failure.
        // `try_accept` sets the connection back to blocking, and this is what proves it.
        host.lock().listen_nonblocking().expect("non-blocking");

        let served = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                // ★ The guard is dropped **before** the handshake, and that is the whole reason this is two steps.
                // `host.lock().try_accept()` inside an `if let` keeps its guard alive for the entire block, and
                // `handle_within` locks the same host — so the second lock is one thread asking for a mutex it already
                // holds, which `parking_lot` does not grant.
                //
                // The symptom was not a deadlock report. The server sat in the handshake reading a `Hello` it would never
                // see, and the client timed out waiting for an answer it would never get — a failure that looks exactly
                // like a peer that connected and went silent.
                let taken = host.lock().try_accept();
                match taken {
                    Ok(Some(stream)) => {
                        return handle_within(&Arc::clone(&host), stream, Duration::from_secs(5));
                    }
                    Ok(None) => {}
                    Err(error) => panic!("the listener could not accept: {error}"),
                }
                assert!(std::time::Instant::now() < deadline, "no connection arrived");
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let (mut client, _db) = client_host(B, "Phone");
        client.set_flags(Flags::production());
        let mut link = client
            .dial(device(A), dialable(address), None, 1_000)
            .expect("dials");
        let envelope = synra_core::text_to(
            device(B),
            device(A),
            "hello over the wire",
            synra_protocol::ids::TraceId::new(),
            1_000,
        )
        .expect("builds");
        client.send(&mut link, &envelope).expect("sends");
        // Ended so the server's read loop returns rather than waiting out its own deadline.
        let _ = link.bye("test done");

        let served = served.join().expect("the acceptor finished");
        assert_eq!(served.peer, Some(device(B)));
        assert_eq!(served.events, vec![synra_protocol::event::builtin::CLIPBOARD_RECEIVED]);
        // And the `Bye` is the ordinary end rather than a fault, so nothing is recorded as having gone wrong.
        assert_eq!(served.ended, None, "{served:?}");
    }

    #[test]
    fn a_connection_that_is_not_a_synra_peer_is_reported_rather_than_hanging() {
        // ★ A port scan, another product's client, and a peer that changed its mind all look like this. The first version of
        // this test connected and said *nothing*, which proved the hazard rather than the fix — the reading half waited for
        // ever because nothing bounded it. What bounds it now is the deadline `handle_within` sets on the stream.
        let (host, address) = listening(A, "Laptop");

        let mut probe = std::net::TcpStream::connect(dialable(address)).expect("connects");
        // A **complete** frame the decoder refuses at once: a six-byte header — four of length, one of kind, one of flags —
        // whose kind `0xFF` is outside the protocol's closed set.
        use std::io::Write as _;
        probe.write_all(&[0, 0, 0, 0, 0xFF, 0x00]).expect("writes");
        probe.flush().expect("flushes");

        // A bounded wait, for the reasons the other connection tests give: the guard from `host.lock()` would otherwise
        // live to the end of the statement, and a pending connection is not always visible to `accept` the instant
        // `connect` returns — which made this test flake under load.
        let taken = accept_within(&host, Duration::from_secs(5)).expect("a connection");
        let served = handle_within(&Arc::clone(&host), taken, Duration::from_millis(500));

        assert!(served.ended.is_some(), "a non-peer should be reported: {served:?}");
        // And the peer is absent, because the handshake is what would have established it — which is exactly what a
        // sentinel identifier would have hidden.
        assert_eq!(served.peer, None);
        assert!(served.events.is_empty());
    }

    #[test]
    fn a_peer_that_connects_and_says_nothing_is_bounded_by_the_deadline() {
        // ★ The case that made the first version hang. Nothing on the network can be trusted to say something, so the
        // reading half has to be bounded by a clock rather than by the peer's manners.
        let (host, address) = listening(A, "Laptop");
        let probe = std::net::TcpStream::connect(dialable(address)).expect("connects");

        // ★ Two steps, not one chain. `host.lock().try_accept().expect(...)` holds the guard for the whole statement, and
        // `handle_within` below locks the same host — the same thread asking for a mutex it already holds, which
        // `parking_lot` does not grant. It shows up as a handshake that never finishes rather than as a deadlock report,
        // which is what makes it worth a sentence here.
        //
        // ★ And it *polls* rather than assuming the connection is there. A successful `connect` returns on this side as
        // soon as the handshake is under way, and the pending connection is not always visible to `accept` at that instant
        // — the first version of this expected it immediately and failed whenever the machine was busy running the rest
        // of the suite.
        let taken = accept_within(&host, Duration::from_secs(5)).expect("a connection");
        let started = std::time::Instant::now();
        let served = handle_within(&Arc::clone(&host), taken, Duration::from_millis(300));
        let elapsed = started.elapsed();

        assert!(served.ended.is_some(), "{served:?}");
        assert_eq!(served.peer, None);
        // It returned because of the deadline, not because the peer spoke — and not after the protocol's six seconds.
        assert!(elapsed < Duration::from_secs(3), "the deadline did not bound the read: {elapsed:?}");
        drop(probe);
    }

    #[test]
    fn a_link_is_reported_as_open_only_when_it_knows_its_peer() {
        // The predicate a caller uses to tell "there is a link" from "there is not". Asserted on a `PeerLink` built
        // directly rather than through a dial, because what it reads is the peer's identifier — and a full dial would test
        // `dial` again, which its own tests already do.
        let (_a, b) = connected_pair();
        let link = PeerLink::new(
            b,
            device(A),
            device(B),
            synra_protocol::handshake::Agreed { common: Vec::new(), missing_required: Vec::new() },
            Flags::no_timeout(),
        );
        assert!(is_open(&link));

        // And a link whose peer is the nil identifier is not open — which is what a connection that failed before `Hello`
        // would have if it were ever made into one.
        //
        // ★ The nil value is made with `from_uuid(Uuid::nil())`, and both obvious alternatives are wrong for reasons this
        // test proved by failing:
        //
        // * `DeviceId::default()` **generates a new identifier** — the protocol does not want to represent a device
        //   without one, so `default()` is a perfectly good peer and the assertion was backwards.
        // * `"00000000-…".parse::<DeviceId>()` is **refused** with `IdError::Nil`, for the same reason.
        //
        // A nil device id is a state the protocol goes out of its way not to produce, which is exactly why the sentinel is
        // the wrong shape for "no peer" — and why `Served::peer` is an `Option`.
        let (_c, d) = connected_pair();
        let unnamed = PeerLink::new(
            d,
            device(A),
            DeviceId::from_uuid(uuid::Uuid::nil()),
            synra_protocol::handshake::Agreed { common: Vec::new(), missing_required: Vec::new() },
            Flags::no_timeout(),
        );
        assert!(!is_open(&unnamed));
    }
}
