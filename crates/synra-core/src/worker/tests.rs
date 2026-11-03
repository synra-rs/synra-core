use std::sync::Arc;
use std::sync::atomic::AtomicI64;

use parking_lot::Mutex;

use super::runner::heard_now;
use super::*;
use crate::identity::Identity;
use crate::peer::{Flags, LocalPeer};
use crate::supervisor::Cancellation;
use std::net::{Ipv4Addr, SocketAddr};
use synra_protocol::discovery::TrustLevel;
use synra_protocol::handshake::PROTOCOL_VERSION;
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

pub(super) const A: &str = "11111111-1111-4111-8111-111111111111";
pub(super) const B: &str = "22222222-2222-4222-8222-222222222222";

pub(super) fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

pub(super) fn host(id: &str, name: &str) -> Host {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db.create_identity_if_absent(
        &synra_store::IdentityRow::from_columns(Some(id), Some(name), Some("test"), Some(1_000))
            .expect("identity row"),
    )
    .expect("initial identity");
    let identity = Identity::load(&db, "test", 1_000).expect("an identity");
    let local = LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        PlatformKind::Desktop,
        "0.1.0-test",
    );
    Host::with_flags(identity, local, Flags::no_timeout())
}

pub(super) fn announcement(id: &str, name: &str, port: u16) -> DeviceAnnouncement {
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

/// A service with both sockets on ports the operating system chose.
///
/// # Why the responder is not on the well-known port
///
/// Because binding it would collide with a kernel that happens to be running on this machine, and because a test that
/// needed the discovery port free would fail for a reason that has nothing to do with what it asserts. The service
/// takes the address it is given; only `bind` uses the well-known port.
pub(super) fn service(id: &str, interval: Duration) -> DiscoveryService {
    DiscoveryService {
        responder: DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a responder"),
        querier: DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a querier"),
        ours: announcement(id, "Laptop", 47_100),
        next_query: Instant::now(),
        interval,
        broadcasting: false,
    }
}

#[test]
fn the_worker_returns_when_it_is_cancelled() {
    // ★ The loop stops when it is cancelled, which its own doc said it could not do.
    //
    // It read: "there is no stop flag ... the thread's work is *inbound*, so ending it early would only be to save a
    // thread on a process that is exiting anyway". That was true of a worker run by a bare `std::thread::spawn` on a
    // process that was going away. Under `supervisor::run_task` the worker is *given* a token and is required to honour
    // it — and a closure that ignores one leaves a thread running after the supervisor has recorded the task as
    // stopped, which is a shutdown report that lies about what is still running.
    //
    // The only wait is the loop's own poll interval, so this is about the token rather than about a timeout.
    let service = Arc::new(Mutex::new(service(A, Duration::from_secs(30))));
    let peers = Arc::new(Mutex::new(host(A, "Laptop")));
    let deadline = Arc::new(AtomicI64::new(0));
    let cancel = Cancellation::new();

    let worker = std::thread::spawn({
        let cancel = cancel.clone();
        move || run_recording(&service, &peers, &deadline, &cancel, || 0, |_| {})
    });

    cancel.cancel();

    assert!(
        worker.join().is_ok(),
        "the worker returned rather than looping for ever"
    );
}

// ── Tick ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_first_tick_broadcasts_because_a_kernel_that_just_started_has_nothing() {
    // ★ Due immediately rather than after an interval: a kernel that has just started has an empty table, and waiting
    // twenty seconds to ask is twenty seconds of being invisible.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    let ticked = service.tick(&mut kernel, 1_000, Instant::now(), 0);
    assert!(ticked.broadcast);
}

#[test]
fn a_second_tick_before_the_interval_does_not_broadcast() {
    // A broadcast every tick would be a broadcast ten times a second, which is a machine that floods its own network.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    let start = Instant::now();
    assert!(service.tick(&mut kernel, 1_000, start, 0).broadcast);
    assert!(
        !service
            .tick(&mut kernel, 1_001, start + Duration::from_millis(50), 0)
            .broadcast
    );
    assert!(
        service
            .tick(&mut kernel, 1_002, start + Duration::from_secs(61), 0)
            .broadcast
    );
}

#[test]
fn an_idle_tick_reports_no_trouble() {
    // The ordinary case: two sockets with nothing waiting, and a broadcast that may or may not be due. A tick that
    // reported an error here would make every quiet moment look like a fault.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    let ticked = service.tick(&mut kernel, 1_000, Instant::now(), 0);
    assert!(ticked.absorbed.is_empty());
    assert!(ticked.askers.is_empty());
    assert!(ticked.errors.is_empty(), "{:?}", ticked.errors);
}

// ── The two sockets ───────────────────────────────────────────────────────────────────────────

#[test]
fn the_responder_and_the_querier_are_different_sockets() {
    // ★ A reply is unicast back to **the address the query came from**. A device that queried from the well-known
    // port would have every answer arrive on the socket it shares with every other device on the machine — so the
    // two are separate, and this is the assertion that keeps them so.
    let service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let querier = service.querier_address().expect("an address");
    assert_ne!(responder.port(), querier.port());
    assert_ne!(responder.port(), 0);
    assert_ne!(querier.port(), 0);
}

#[test]
fn a_query_arriving_on_the_responder_becomes_a_candidate() {
    // The whole point: a device asks, and this kernel learns it exists. The answer is the caller's to send, because
    // it needs this device's own announcement.
    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");

    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    let candidate = kernel.discovery().get(device(B)).expect("a candidate");
    assert_eq!(candidate.display_name, "Phone");
    // The connection port, not the port the query came from.
    assert_eq!(candidate.address.port(), 47_101);
}

#[test]
fn an_answer_arriving_on_the_querier_becomes_a_candidate_too() {
    // ★ An answer is news about a device in exactly the way a query is. A service that only read the responder would
    // find only devices that happened to ask *it*, which is not discovery — it is waiting to be asked.
    let mut service = service(A, Duration::from_secs(60));
    let querier = service.querier_address().expect("an address");
    let mut kernel = host(A, "Laptop");

    let answerer =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an answerer");
    answerer
        .send_response(&announcement(B, "Phone", 47_101), querier)
        .expect("answers");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
}

#[test]
fn this_devices_own_broadcast_is_not_a_candidate() {
    // A device hears its own broadcast because that is what broadcasting means, and a table that counted it would
    // show the user their own machine as a peer.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    // Several ticks, because the querier is not connected to the responder and the broadcast goes to the broadcast
    // address rather than to this socket — so what is asserted is that nothing about this device ever appears.
    for i in 0..3 {
        service.tick(&mut kernel, 5_000 + i, Instant::now(), 0);
    }
    assert!(kernel.discovery().get(device(A)).is_none());
}

#[test]
fn a_datagram_that_is_not_an_announcement_ends_the_drain_without_a_fault() {
    // A well-known port is sent to by anything. A stray packet ends this pass and is not reported as a fault, because
    // a scan that failed because a printer answered would be one that fails on a real network.
    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");

    let stray = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a stray");
    stray
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("a real one first");
    // Then something that is not this protocol at all.
    let raw = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a raw socket");
    raw.send_to(b"not a synra datagram", responder)
        .expect("sends");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    // The good one was absorbed; the stray one stopped the drain rather than being reported.
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    assert!(ticked.errors.is_empty(), "{:?}", ticked.errors);
}

// ── Answering ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_timeout_on_a_read_is_not_reported_as_a_fault() {
    // ★ Windows reports a socket read timeout as `WSAETIMEDOUT` (10060) rather than as a would-block, so a drain that
    // treated it as an error would return before it had read anything — which is what made this look like a responder
    // that never answered. A quiet tick reports no trouble, and that is asserted rather than assumed.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    for i in 0..3 {
        let ticked = service.tick(&mut kernel, 5_000 + i, Instant::now(), 0);
        assert!(ticked.errors.is_empty(), "{:?}", ticked.errors);
    }
}

#[test]
fn an_answer_reaches_the_device_that_asked() {
    // ★ The answer goes back to the address the query came from, because that is what the protocol says and because a
    // device cannot be found otherwise: it broadcasts from wherever it broadcasts, and only that address can receive.
    let service = service(A, Duration::from_secs(60));
    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("a timeout");

    let sent = service
        .answer(asker.local_addr().expect("an address"))
        .expect("answers");
    assert!(sent > 0);

    // The asker reads it as a response carrying the answerer's own announcement.
    let mut kernel = host(B, "Phone");
    let absorbed = asker.receive(&mut kernel, 5_000).expect("receives");
    assert_eq!(
        absorbed,
        Some(Absorbed::New {
            device_id: device(A)
        })
    );
    let candidate = kernel.discovery().get(device(A)).expect("a candidate");
    assert_eq!(candidate.display_name, "Laptop");
    assert_eq!(candidate.address.port(), 47_100);
}

#[test]
fn a_goodbye_reaches_the_broadcast_addresses_and_reports_each() {
    // A device that is shutting down has no second chance, and every interface deserves its own attempt.
    let service = service(A, Duration::from_secs(60));
    let results = service.goodbye(1_700_000_000_000);
    assert_eq!(
        results.len(),
        1,
        "a loopback socket cannot broadcast on external interfaces"
    );
    for (address, result) in &results {
        assert_eq!(address.port(), synra_protocol::limits::DISCOVERY_PORT);
        if let Err(error) = result {
            assert!(!error.to_string().is_empty());
        }
    }
}

// ── The whole loop ────────────────────────────────────────────────────────────────────────────

#[test]
fn two_services_find_each_other_over_loopback() {
    // ★ The end-to-end test: two services, each with its own two sockets, and a query that one sends to the other's
    // responder. What is asserted is the round trip a real network does — a query arrives, a candidate is recorded,
    // and the answer carries the announcement back.
    let mut asker = service(A, Duration::from_secs(60));
    let mut answerer = service(B, Duration::from_secs(60));
    let answerer_responder = answerer.responder_address().expect("an address");
    let asker_querier = asker.querier_address().expect("an address");

    let mut asking = host(A, "Laptop");
    // The asker asks the answerer's responder from its own querier, which is what a real scan does.
    asker
        .querier
        .send_query(&announcement(A, "Laptop", 47_100), answerer_responder)
        .expect("asks");

    // The answerer hears the query and answers it.
    let mut answering = host(B, "Phone");
    let ticked = answerer.tick(&mut answering, 5_000, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(A)
        }]
    );

    // ★ The answer goes to the querier, not to the responder — which is the whole reason there are two sockets.
    answerer.answer(asker_querier).expect("answers");

    // And the asker learns about the answerer.
    let ticked = asker.tick(&mut asking, 5_001, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    assert!(asking.discovery().get(device(B)).is_some());
}

// ── What a caller sees ────────────────────────────────────────────────────────────────────────

#[test]
fn a_device_heard_over_the_network_is_not_visible_until_it_is_handshaked() {
    // ★ The protocol's own rule, reached through the service: an announced device is a *candidate*, and the interface
    // shows candidates under their own heading rather than among peers.
    let table = DiscoveryTable::new(device(A));
    assert!(!is_visible(&table, 0));

    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");
    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks");
    service.tick(&mut kernel, 5_000, Instant::now(), 0);

    assert_eq!(
        kernel
            .discovery()
            .get(device(B))
            .expect("a candidate")
            .trust,
        TrustLevel::Announced
    );
    assert!(
        !is_visible(kernel.discovery(), 5_000),
        "an announced device should not be visible"
    );
}

#[test]
fn the_callback_is_given_a_device_that_only_announced_itself() {
    // ★ The visibility rule and this are two different questions, and the callback used to answer the wrong one.
    //
    // `is_visible` is about a *screen*: an announced device is a candidate, shown under its own heading, not among
    // peers. The callback is about *memory*: it is "what did you hear", and the table both hosts write from it says
    // it holds a sighting of a device this kernel has not paired with. Fed from `usable`, which starts at
    // `Handshaked`, it was never told about a sighting.
    let mut service = service(A, Duration::from_secs(60));
    let responder = service.responder_address().expect("an address");
    let mut kernel = host(A, "Laptop");
    let asker =
        DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks");

    let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
    let heard = heard_now(&kernel, &ticked.absorbed);

    assert_eq!(heard.len(), 1, "the device that asked is what was heard");
    assert_eq!(heard[0].device_id, device(B));
    assert_eq!(
        heard[0].trust,
        TrustLevel::Announced,
        "and it is a sighting, not an identity"
    );
    // And the screen's rule is untouched: the same device is still not a peer.
    assert!(!is_visible(kernel.discovery(), 5_000));

    // Repeated announcements refresh presence even when the endpoint has not changed.
    asker
        .send_query(&announcement(B, "Phone", 47_101), responder)
        .expect("asks again");
    let again = service.tick(&mut kernel, 5_001, Instant::now(), 0);
    assert_eq!(
        again.absorbed,
        vec![Absorbed::Unchanged {
            device_id: device(B)
        }]
    );
    assert_eq!(heard_now(&kernel, &again.absorbed)[0].last_seen_ms, 5_001);
}

#[test]
fn a_service_debug_form_names_the_device_and_the_port() {
    // It appears in a log line, and a handle that printed a socket would leak the path.
    let service = service(A, Duration::from_secs(60));
    let text = format!("{service:?}");
    assert!(
        text.contains("Laptop") || text.contains("47100") || text.contains("47_100"),
        "{text}"
    );
    assert!(!text.contains("127.0.0.1"), "{text}");
}
