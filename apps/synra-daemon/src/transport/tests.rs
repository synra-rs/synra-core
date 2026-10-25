//! The listener's tests, which stayed with the host that can run them.
//!
//! # ★ Why these did not move with the code they test
//!
//! Because they drive a real connection through a real [`KernelHost`](crate::runtime::plugin_host::KernelHost) — this
//! host's implementation of the plugin boundary. A library-side copy would have had to invent a second host to test with,
//! and a listener tested against a host the library made up is a listener tested against nothing the product runs.
//!
//! # Why the imports are spelled out rather than `use super::*`
//!
//! Because they used to arrive through the module they lived in. `super` is now the shim that re-exports
//! [`synra_core::listener`], and a shim has no `std::sync::Arc` in it.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use synra_core::host::Host;
use synra_core::link::PeerLink;
use synra_core::listener::{bind, handle_within, handle_within_with, is_open};

#[test]
fn production_listener_does_not_hold_the_host_lock_while_waiting_for_authenticated_hello() {
    let (host, address, fixture) = listening(A, "Available registry");
    let incoming_host = Arc::clone(&host);
    let directory = fixture.root().to_path_buf();
    let worker = std::thread::spawn(move || {
        let socket = accept_within(&incoming_host, Duration::from_secs(3)).unwrap();
        handle_within(
            &incoming_host,
            socket,
            &directory,
            Duration::from_secs(3),
            &test_desk(),
            &test_router(),
            &synra_core::listener::no_answer(),
        )
    });
    let socket = std::net::TcpStream::connect(dialable(address)).unwrap();
    let client = synra_testkit::authentication::credentials_for(device(B)).unwrap();
    let server = synra_testkit::authentication::credentials_for(device(A)).unwrap();
    let raw = synra_net::authentication::AuthenticatedStream::connect(
        socket,
        &client,
        server.public_identity(),
        Duration::from_secs(3),
    )
    .unwrap();
    // Completing TLS proves the worker entered authentication, while withholding Hello keeps it there.
    let guard = host.try_lock();
    let registry_available = guard.is_some();
    drop(guard);
    drop(raw);
    let served = worker.join().unwrap();
    assert!(
        registry_available,
        "the registry was locked during a network wait"
    );
    assert!(served.peer.is_none());
}

#[test]
fn production_listener_rechecks_revocation_before_delivering_a_business_frame() {
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let (host, address, database) = listening_with(A, "Revocable", Some(Arc::clone(&recorder)));
    let data_dir = database.root().to_path_buf();
    let incoming_host = Arc::clone(&host);
    let worker = std::thread::spawn(move || {
        let socket = accept_within(&incoming_host, Duration::from_secs(3)).unwrap();
        handle_within(
            &incoming_host,
            socket,
            &data_dir,
            Duration::from_secs(3),
            &test_desk(),
            &test_router(),
            &synra_core::listener::no_answer(),
        )
    });
    let (mut client, _fixture) = client_host(B, "Client");
    let now = synra_core::reading_millis(synra_store::sqlite::now_ms());
    let mut link = client.dial(dialable(address), device(A), now).unwrap();
    database.unpair_device(B).unwrap();
    let message = synra_core::text_to(
        device(B),
        device(A),
        "must not dispatch",
        synra_protocol::TraceId::new(),
        now as i64,
    )
    .unwrap();
    let _ = link.send(&message);
    drop(link);
    let served = worker.join().unwrap();
    assert!(served.events.is_empty());
    assert!(served.ended.is_some());
    assert_eq!(
        recorder
            .snapshot()
            .get("links_closed_total{reason=authorization}"),
        Some(&synra_observe::metrics::Value::Counter(1))
    );
}

use synra_core::identity::Identity;

/// A desk for a test connection, with the protocol's own pairing window.
///
/// Fresh per call, so one test's prompt cannot appear in another's.
/// A router over an in-memory database and no plugins.
///
/// The connection tests are about the handshake, the transfer path and the pairing desk; a share arriving is not what
/// they exercise, so the plugins a real router would hold are absent. What matters is that routing has somewhere to
/// go — a connection handler with no router would have to drop a share silently, which is the defect this option
/// exists to remove.
fn test_router() -> Arc<crate::runtime::intent::Router> {
    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    let set = synra_core::dispatch::PluginSet::new(
        synra_plugin_host::Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new())),
        Arc::new(crate::runtime::plugin_host::KernelHost::new(
            Arc::new(Mutex::new(db)),
            "0.1.0-test",
        )),
    );
    Arc::new(crate::runtime::intent::Router::new(
        Arc::new(Mutex::new(set)),
        Arc::new(Mutex::new(synra_core::intent::Board::new())),
    ))
}

fn test_desk() -> Arc<synra_core::pairing::PairingDesk> {
    Arc::new(synra_core::pairing::PairingDesk::new(
        DeviceId::new(),
        synra_protocol::session::SessionTimeouts::default().pairing,
    ))
}
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
fn listening(
    id: &str,
    name: &str,
) -> (
    Arc<Mutex<Host>>,
    SocketAddr,
    synra_testkit::authentication::NetworkFixture,
) {
    listening_with(id, name, None)
}

/// The same host, with a recorder, for a test that asserts a metric rather than a return value.
fn listening_with(
    id: &str,
    name: &str,
    metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
) -> (
    Arc<Mutex<Host>>,
    SocketAddr,
    synra_testkit::authentication::NetworkFixture,
) {
    let (mut host, db) = client_host(id, name);
    if let Some(metrics) = metrics {
        host = host.with_metrics(metrics);
    }
    let address = bind(&mut host, 0).expect("bind");
    host.listen_nonblocking().expect("non-blocking");
    (Arc::new(Mutex::new(host)), address, db)
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
fn accept_within(host: &Arc<Mutex<Host>>, timeout: Duration) -> Option<std::net::TcpStream> {
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

/// A temporary directory that removes itself, for the inbox an inbound transfer needs.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "synra-transport-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temp directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Two connected streams, as an established link would have.
fn connected_pair() -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
    let address = listener.local_addr().expect("an address");
    let dialer = std::net::TcpStream::connect(address).expect("connects");
    let (accepted, _) = listener.accept().expect("accepts");
    (dialer, accepted)
}

/// A host that is not listening, for the dialling side of a test.
fn client_host(id: &str, name: &str) -> (Host, synra_testkit::authentication::NetworkFixture) {
    let other = if id == A { B } else { A };
    let db = synra_testkit::authentication::NetworkFixture::new(device(id), device(other), name)
        .unwrap();
    let identity = Identity::load(&db, "test", 1_000).unwrap();
    let local = LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        PlatformKind::Android,
        "0.1.0-test",
    );
    let network = synra_core::peer::authenticated::AuthenticatedPeer::new(
        Arc::clone(&db.shared_db),
        Arc::clone(&db.credentials),
        local.clone(),
    )
    .unwrap();
    let mut host = Host::with_flags(identity, local, Flags::no_timeout());
    host.configure_network(Ok(network));
    (host, db)
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
    let (_host, address, _network_database) = listening(A, "Laptop");
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
    let (host, _address, _network_database) = listening(A, "Laptop");
    // Non-blocking, because that is what makes `try_accept` a *poll*. Without this the call blocks on an empty backlog
    // and the test hangs rather than failing — which is exactly what an earlier edit of this file did, by removing the
    // line and leaving a blocking accept behind.
    host.lock().listen_nonblocking().expect("non-blocking");
    assert!(host.lock().try_accept().expect("polls").is_none());
}

// ── A whole connection ────────────────────────────────────────────────────────────────────────

#[test]
fn an_inbound_connection_is_handshaked_and_its_message_is_read() {
    let inbox = TempDir::new("inbox");
    // ★ The thing this module exists for: a device that can only dial is a device nobody can send to.
    //
    // ★ Both sides are on **production flags**, and that is not incidental — it is what makes this the daemon's
    // configuration rather than a test's. Every other test in this module uses `no_timeout` so that a wait never
    // happens, and an earlier version of this one mixed the two: a client with no deadline against a server that set
    // one. `handle_within` puts a deadline on the stream it is given, so a client that never times out and a server
    // that does will disagree about when the conversation is over.
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let (host, address, _network_database) =
        listening_with(A, "Laptop", Some(Arc::clone(&recorder)));
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
                    return handle_within(
                        &Arc::clone(&host),
                        stream,
                        inbox.path(),
                        Duration::from_secs(5),
                        &test_desk(),
                        &test_router(),
                        &synra_core::listener::no_answer(),
                    );
                }
                Ok(None) => {}
                Err(error) => panic!("the listener could not accept: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no connection arrived"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let (mut client, _db) = client_host(B, "Phone");
    client.set_flags(Flags::production());
    let mut link = client
        .dial(
            dialable(address),
            device(A),
            synra_core::reading_millis(synra_store::sqlite::now_ms()),
        )
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
    assert_eq!(
        served.events,
        vec![synra_protocol::event::builtin::CLIPBOARD_RECEIVED]
    );
    // And the `Bye` is the ordinary end rather than a fault, so nothing is recorded as having gone wrong.
    assert_eq!(served.ended, None, "{served:?}");
    // ★ And the close is counted with the wire's own reason. `closed` is the peer's `Bye`, not a fault and not the
    // listener's timeout: three different things a panel would otherwise show as one "link ended".
    assert_eq!(
        recorder.snapshot().get("links_closed_total{reason=closed}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the listener counted the end by its reason"
    );
}

#[test]
fn a_connection_that_is_not_a_synra_peer_is_reported_rather_than_hanging() {
    let inbox = TempDir::new("inbox");
    // ★ A port scan, another product's client, and a peer that changed its mind all look like this. The first version of
    // this test connected and said *nothing*, which proved the hazard rather than the fix — the reading half waited for
    // ever because nothing bounded it. What bounds it now is the deadline `handle_within` sets on the stream.
    let (host, address, _network_database) = listening(A, "Laptop");

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
    let served = handle_within(
        &Arc::clone(&host),
        taken,
        inbox.path(),
        Duration::from_millis(500),
        &test_desk(),
        &test_router(),
        &synra_core::listener::no_answer(),
    );

    assert!(
        served.ended.is_some(),
        "a non-peer should be reported: {served:?}"
    );
    // And the peer is absent, because the handshake is what would have established it — which is exactly what a
    // sentinel identifier would have hidden.
    assert_eq!(served.peer, None);
    assert!(served.events.is_empty());
}

#[test]
fn a_peer_that_connects_and_says_nothing_is_bounded_by_the_deadline() {
    let inbox = TempDir::new("inbox");
    // ★ The case that made the first version hang. Nothing on the network can be trusted to say something, so the
    // reading half has to be bounded by a clock rather than by the peer's manners.
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let (host, address, _network_database) =
        listening_with(A, "Laptop", Some(Arc::clone(&recorder)));
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
    let served = handle_within(
        &Arc::clone(&host),
        taken,
        inbox.path(),
        Duration::from_millis(300),
        &test_desk(),
        &test_router(),
        &synra_core::listener::no_answer(),
    );
    let elapsed = started.elapsed();

    assert!(served.ended.is_some(), "{served:?}");
    assert_eq!(served.peer, None);
    // It returned because of the deadline, not because the peer spoke — and not after the protocol's six seconds.
    assert!(
        elapsed < Duration::from_secs(3),
        "the deadline did not bound the read: {elapsed:?}"
    );
    // ★ And the counter says *why*: the handshake never completed, which is a different fact from a link that opened
    // and then timed out. `links_closed_total{reason}` exists so this distinction survives into a panel.
    assert_eq!(
        recorder
            .snapshot()
            .get("links_closed_total{reason=handshake}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "a peer that never handshakes ends as a handshake failure: {:?}",
        recorder.snapshot()
    );
    drop(probe);
}

#[test]
fn a_peer_that_handshakes_and_then_hangs_up_ends_as_closed() {
    // ★ The other half of the silent-peer case: one that *did* handshake and then went quiet. It is not a handshake
    // that never happened — the link was open — and the end is ordinary rather than a fault. (The read loop's own
    // patience is longer than this test's wait, so the ending observed here is the peer's hang-up.)
    let inbox = TempDir::new("inbox-quiet");
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let (host, address, _network_database) =
        listening_with(A, "Laptop", Some(Arc::clone(&recorder)));

    let served = std::thread::spawn(move || {
        let taken = accept_within(&host, Duration::from_secs(5)).expect("a connection");
        handle_within(
            &Arc::clone(&host),
            taken,
            inbox.path(),
            Duration::from_millis(300),
            &test_desk(),
            &test_router(),
            &synra_core::listener::no_answer(),
        )
    });

    let (mut client, _db) = client_host(B, "Phone");
    let link = client
        .dial(
            dialable(address),
            device(A),
            synra_core::reading_millis(synra_store::sqlite::now_ms()),
        )
        .expect("dials");
    // The handshake is done and the connection stays open with nothing on it; the server's read deadline is shorter.
    std::thread::sleep(Duration::from_millis(600));
    drop(link);

    let served = served.join().expect("the acceptor finished");
    assert_eq!(
        served.ended, None,
        "a quiet peer is not a fault: {served:?}"
    );
    assert_eq!(
        recorder.snapshot().get("links_closed_total{reason=closed}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "a handshaked peer that hangs up ends as closed: {:?}",
        recorder.snapshot()
    );
}

#[test]
fn a_kernel_event_is_answered_on_the_connection_that_asked() {
    // ★ The receiver half of remote dispatch. It used to be absent: an `INTENT_INVOKE` arrived, was counted, and was
    // dropped — the sender's intent stayed `dispatching` and the action never ran. The assertion is on the reply the
    // client actually receives, not on the callback having been called: a callback whose answer is thrown away would
    // pass the second and fail a user.
    let inbox = TempDir::new("inbox-intent");
    let (host, address, _network_database) = listening(A, "Laptop");
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let events: Arc<synra_core::listener::KernelEventCallback> = {
        let asked = Arc::clone(&asked);
        Arc::new(move |envelope: &synra_protocol::envelope::Envelope| {
            assert_eq!(envelope.event.as_str(), "_synra.intent.invoke");
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let event = synra_protocol::event::EventName::parse("_synra.intent.result")
                .expect("an event name");
            // Answered by the device the request was addressed to, on the connection it arrived on.
            let reply = synra_protocol::envelope::Envelope::reply_to(
                envelope,
                event,
                envelope.target,
                2_000,
                None::<&serde_json::Value>,
            )
            .expect("a reply");
            synra_core::listener::KernelEventOutcome::Reply(Box::new(reply))
        })
    };
    let progress: Arc<synra_core::listener::ProgressCallback> = Arc::new(|_event| {});
    let offer: Arc<synra_core::inbound::OfferCallback> = Arc::new(synra_core::inbound::auto_accept);
    let cancel: Arc<synra_core::listener::CancelCallback> = Arc::new(|_transfer| false);

    let served = std::thread::spawn(move || {
        let taken = accept_within(&host, Duration::from_secs(5)).expect("a connection");
        handle_within_with(
            &Arc::clone(&host),
            taken,
            inbox.path(),
            Duration::from_secs(2),
            &test_desk(),
            &test_router(),
            &synra_core::listener::no_answer(),
            &progress,
            &offer,
            &cancel,
            &events,
        )
    });

    let (mut client, _db) = client_host(B, "Phone");
    let mut link = client
        .dial(
            dialable(address),
            device(A),
            synra_core::reading_millis(synra_store::sqlite::now_ms()),
        )
        .expect("dials");
    link.set_read_timeout(Some(Duration::from_secs(2)));
    let invoke = synra_core::intent::remote::invoke(
        device(B),
        device(A),
        &synra_core::intent::remote::Invoke {
            plugin_id: synra_protocol::ids::PluginId::try_from("@acme/opener".to_owned())
                .expect("a plugin"),
            plugin_version: "1.0.0".to_owned(),
            action: "open".to_owned(),
            args: serde_json::json!({ "url": "https://example.com" }),
        },
        synra_protocol::ids::TraceId::new(),
        1_000,
    )
    .expect("an invocation");
    client.send(&mut link, &invoke).expect("sends");

    let reply = link.receive().expect("the answer");
    assert_eq!(reply.event.as_str(), "_synra.intent.result");
    // ★ The reply names the request it answers; without that the sender cannot tell which of its dispatches it belongs
    // to — and the whole round trip exists to give one dispatch its outcome.
    assert_eq!(reply.reply_to, Some(invoke.request_id));
    let _ = link.bye("done");

    let served = served.join().expect("the acceptor finished");
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        served
            .events
            .iter()
            .any(|event| event.contains("answered _synra.intent.invoke")),
        "{:?}",
        served.events
    );
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
        synra_protocol::handshake::Agreed {
            common: Vec::new(),
            missing_required: Vec::new(),
        },
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
        synra_protocol::handshake::Agreed {
            common: Vec::new(),
            missing_required: Vec::new(),
        },
        Flags::no_timeout(),
    );
    assert!(!is_open(&unnamed));
}
