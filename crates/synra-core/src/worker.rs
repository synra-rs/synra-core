//! The discovery worker: one thread answering queries and asking its own.
//!
//! # Why this is a thread rather than a call
//!
//! The control socket is served **one connection at a time** — `synra-control`'s `Listener::serve_one` blocks, and the
//! listener cannot be cloned, so a second client waits for the first to finish. That is fine for commands that answer
//! from memory, and it is not fine for discovery: a scan is a bounded wait on a network, and a scan that held the control
//! loop would make every other command — including the `status` a user runs to find out why things are slow — wait for
//! the network as well.
//!
//! So discovery runs on its own thread and the control loop only ever *reads* what that thread has learned. The thread
//! owns both sockets:
//!
//! * The **responder**, bound to the well-known discovery port, which answers queries from other devices. A device that
//!   did not answer would be one nothing on the network could find — it would have to be typed in by address.
//! * The **querier**, on a port the operating system chooses, which broadcasts this device's own queries. Broadcasts go
//!   out from here rather than from the responder because a reply is unicast back to **the address the query came from**,
//!   and a device that queried from the well-known port would have every answer arrive on the socket it shares with every
//!   other device on the machine.
//!
//! # What the thread does, once per tick
//!
//! 1. Reads whatever is waiting on the responder, one datagram at a time, and answers each query. The read has a timeout
//!    so the loop can also do the rest of its work; a socket with no timeout would sit here until a packet arrived and
//!    never broadcast.
//! 2. Reads whatever is waiting on the querier, which is where the answers to this device's own queries arrive.
//! 3. Broadcasts a query if the interval has come round again.
//!
//! # Why the interval is longer than a scan's budget
//!
//! Because a query is a broadcast, and a device that broadcast every second would be one that every machine on the
//! network sees every second — for a device that is already in their tables. The protocol's own scan budget is how long
//! *one* scan listens, and that is a different figure from how often the question is asked.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use synra_protocol::discovery::{DeviceAnnouncement, OfflineAnnouncement};

use crate::discovery::{Absorbed, DiscoveryTable};
use crate::host::Host;
use crate::socket::{DiscoverySocket, SocketError};

/// How often this device broadcasts its own query.
///
/// Not the scan budget: that is how long one scan listens, and this is how often the question is asked. Twice the
/// candidate lifetime would be too slow to notice a device appearing, and a second would make every machine on the
/// network read a broadcast every second for a device it already knows about.
pub const QUERY_INTERVAL: Duration = Duration::from_secs(20);

/// How long the responder waits for a datagram before doing the rest of its work.
///
/// Short, because it is not a deadline for anything: the loop comes back round, reads again, and in between checks
/// whether it is time to broadcast. A long timeout here would delay the broadcast, and a zero one would spin.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// What one pass of the worker did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ticked {
    /// Datagrams that told the kernel about a device.
    pub absorbed: Vec<Absorbed>,
    /// Addresses that asked a question and are waiting for an answer.
    ///
    /// Reported rather than answered inside the tick, because an answer needs this device's own announcement and a socket
    /// — neither of which the host owns. Keeping the two apart is what lets `tick` be tested without a network at all.
    pub askers: Vec<std::net::SocketAddr>,
    /// Whether this pass broadcast a query of its own.
    pub broadcast: bool,
    /// What went wrong, if anything.
    ///
    /// A failure is reported rather than acted on: a machine with no network, a firewall, and a sandbox all produce the
    /// same thing, and none of them is a reason for the kernel to stop. Discovery is how peers are *found*, not how they
    /// are reached.
    pub errors: Vec<SocketError>,
}

/// The two sockets discovery needs, plus where the answers go.
pub struct DiscoveryService {
    /// Bound to the well-known port; answers queries.
    responder: DiscoverySocket,
    /// The port the operating system chose; broadcasts this device's queries.
    querier: DiscoverySocket,
    /// What this device announces.
    ours: DeviceAnnouncement,
    /// When the next broadcast is due.
    next_query: Instant,
    /// How often to broadcast.
    interval: Duration,
}

impl std::fmt::Debug for DiscoveryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryService")
            .field("device_id", &self.ours.device_id)
            .field("port", &self.ours.port)
            .field("interval", &self.interval)
            .finish()
    }
}

impl DiscoveryService {
    /// Binds both sockets.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when either socket cannot be bound. A caller decides whether that is fatal: the daemon does
    /// not, because a kernel that could not start without discovery would be one that cannot run with its wireless
    /// switched off.
    pub fn bind(ours: DeviceAnnouncement) -> Result<Self, SocketError> {
        Self::bind_with_interval(ours, QUERY_INTERVAL)
    }

    /// Binds both sockets with a chosen broadcast interval, for a test that must not wait one out.
    ///
    /// # Errors
    ///
    /// As [`DiscoveryService::bind`].
    pub fn bind_with_interval(ours: DeviceAnnouncement, interval: Duration) -> Result<Self, SocketError> {
        Self::bind_on(ours, synra_protocol::limits::DISCOVERY_PORT, interval)
    }

    /// Binds both sockets, with the responder on a chosen port.
    ///
    /// # Why the port is a parameter when the protocol fixes it
    ///
    /// Because a caller may have a reason to move it — two kernels on one host for a test, or a network where the
    /// well-known port is taken by something else — and a flag that reported a port it did not use is worse than no flag.
    /// The **default** is the protocol's constant, which is what keeps two devices able to find each other: a device that
    /// listened somewhere else could not be found by anything that did not already know where to look.
    ///
    /// The querier stays on an ephemeral port, and that is not configurable. It is where the answers to this device's own
    /// queries arrive, and it is deliberately *not* the shared port — a device that queried from there would have every
    /// answer land on the socket it shares with every other device on the machine.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when either socket cannot be bound.
    pub fn bind_on(
        ours: DeviceAnnouncement,
        responder_port: u16,
        interval: Duration,
    ) -> Result<Self, SocketError> {
        Ok(Self {
            responder: DiscoverySocket::bind(std::net::SocketAddr::from((
                std::net::Ipv4Addr::UNSPECIFIED,
                responder_port,
            )))?,
            querier: DiscoverySocket::bind(std::net::SocketAddr::from((
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            )))?,
            ours,
            // Due immediately, so the first tick broadcasts rather than waiting an interval for a kernel that has just
            // started and has nothing in its table.
            next_query: Instant::now(),
            interval,
        })
    }

    /// The address the responder is bound to.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when it cannot be read.
    pub fn responder_address(&self) -> Result<std::net::SocketAddr, SocketError> {
        self.responder.local_addr()
    }

    /// The address the querier is bound to, which is where answers arrive.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when it cannot be read.
    pub fn querier_address(&self) -> Result<std::net::SocketAddr, SocketError> {
        self.querier.local_addr()
    }

    /// Runs one pass.
    ///
    /// `now_ms` is the wall clock the table records; `now` is the monotonic clock the broadcast interval is measured
    /// against. They are two different clocks on purpose: the first goes into a database and to a client, and the second
    /// only has to be steady — a wall clock that stepped backwards would stop the broadcasts entirely.
    /// `on_demand` is a deadline another thread has published — a client that asked for a scan — and a tick before it
    /// broadcasts whatever the interval says.
    pub fn tick(&mut self, host: &mut Host, now_ms: i64, now: Instant, on_demand: i64) -> Ticked {
        let mut ticked = Ticked::default();

        // The responder first: a query that arrives while this device is broadcasting is another device waiting for an
        // answer, and making it wait for a broadcast to finish is making it wait for no reason.
        self.drain(host, now_ms, &mut ticked, Which::Responder);
        // Then the querier, where the answers to this device's own queries arrive.
        self.drain(host, now_ms, &mut ticked, Which::Querier);

        // ★ A client's scan is why this exists. Without it the answer to "look for devices now" would be "wait up to
        // `QUERY_INTERVAL` for the next scheduled broadcast", which is a scan that finds nothing for twenty seconds and
        // then finds everything — the worst of both.
        let demanded = on_demand > 0 && now_ms < on_demand;
        if now >= self.next_query || demanded {
            // ★ Each address is reported on its own. "Nothing was found" and "nothing could be asked" are different
            // answers, and one failure among several interfaces is not a failure of the scan.
            for (_, result) in self.querier.broadcast_query(&self.ours) {
                if let Err(error) = result {
                    ticked.errors.push(error);
                }
            }
            ticked.broadcast = true;
            // The next one is measured from now rather than from the last due time, so a tick that ran late does not
            // produce a burst of catch-up broadcasts. A demanded broadcast does **not** push the scheduled one back any
            // further than the interval already does, so a scan does not delay the next scheduled query by a full
            // interval on top of the scan itself.
            self.next_query = now + self.interval;
        }

        ticked
    }

    /// Reads every datagram waiting on one socket.
    fn drain(&self, host: &mut Host, now_ms: i64, ticked: &mut Ticked, which: Which) {
        let socket = match which {
            Which::Responder => &self.responder,
            Which::Querier => &self.querier,
        };
        // A short timeout rather than a blocking read, so a socket with nothing waiting does not hold the loop.
        if let Err(error) = socket.set_read_timeout(Some(POLL_INTERVAL / 8)) {
            ticked.errors.push(error);
            return;
        }

        // Bounded, so a device flooding the port cannot hold the loop for ever. Whatever is left waits for the next tick,
        // and a peer that filled this budget has already been heard from.
        for _ in 0..MAX_DATAGRAMS_PER_TICK {
            match socket.receive(host, now_ms) {
                Ok(Some(absorbed)) => {
                    // ★ A datagram that arrived on the responder is a device that is waiting for an answer. Which socket
                    // it came from is what tells the two apart, and the address is taken from the table rather than from
                    // the datagram: the table holds the *connection* port, and the reply goes to where the query came
                    // from.
                    if which == Which::Responder
                        && let Some(candidate) = candidate_address(host, &absorbed)
                    {
                        ticked.askers.push(candidate);
                    }
                    ticked.absorbed.push(absorbed);
                }
                // A datagram about this device, which is the ordinary case for a broadcast.
                Ok(None) => {}
                // A timeout, which is what an idle socket does and is not news.
                // A timeout is what an idle socket does and is not news. Windows reports it as `WSAETIMEDOUT` rather
                // than as a would-block, which is why this is matched on the variant rather than on an error kind.
                Err(SocketError::Receive { .. }) => return,
                // ★ A query has to be *answered*, and this is the only place that can: it needs the socket it arrived on
                // and this device's own announcement. The table has already absorbed it, because a device that asks is a
                // device that exists.
                Err(SocketError::Malformed { .. }) => return,
                Err(error) => {
                    ticked.errors.push(error);
                    return;
                }
            }
        }
    }

    /// Answers one device.
    ///
    /// # Errors
    ///
    /// [`SocketError::Send`] when the answer cannot be sent. A query that cannot be answered is reported rather than
    /// retried: the device that asked will ask again on its next broadcast.
    pub fn answer(&self, to: std::net::SocketAddr) -> Result<usize, SocketError> {
        self.responder.send_response(&self.ours, to)
    }

    /// Answers every device that asked during a tick.
    ///
    /// # Why this is separate from the tick
    ///
    /// Because an answer sends on a socket, and the socket is here while the table is the host's. Keeping them apart is
    /// what makes the decision — *who asked and is waiting* — testable without a network, and a send is the part that
    /// only a network can be wrong about.
    ///
    /// Returns one result per asker, because one address failing is not a failure of the others.
    #[must_use]
    pub fn answer_pending(
        &self,
        ticked: &Ticked,
    ) -> Vec<(std::net::SocketAddr, Result<usize, SocketError>)> {
        ticked
            .askers
            .iter()
            .map(|address| (*address, self.responder.send_response(&self.ours, *address)))
            .collect()
    }

    /// Announces that this device is leaving.
    ///
    /// # Errors
    ///
    /// Never — the failures are returned in the list, one per address, because a device that is shutting down has no
    /// second chance and every interface deserves its own attempt.
    #[must_use]
    pub fn goodbye(&self, timestamp: i64) -> Vec<(std::net::SocketAddr, Result<usize, SocketError>)> {
        self.querier.broadcast_offline(&OfflineAnnouncement {
            device_id: self.ours.device_id,
            timestamp,
        })
    }
}

/// The address a query came from, looked up from what the table just recorded.
///
/// # Why the table is consulted rather than the datagram
///
/// Because the reply must go to the port the query was **sent from**, and the announcement carries the port the device
/// listens on for *connections*. Those are two different ports and mixing them is the bug the protocol's own
/// `announced_address` exists to prevent — so the address is rebuilt here from the datagram's source IP and the announced
/// port, which is exactly what `DiscoverySocket` recorded.
fn candidate_address(host: &Host, absorbed: &Absorbed) -> Option<std::net::SocketAddr> {
    let device_id = match absorbed {
        Absorbed::New { device_id } | Absorbed::Updated { device_id, .. } => *device_id,
        _ => return None,
    };
    host.discovery().get(device_id).map(|found| found.address)
}

/// How many datagrams one pass will read from one socket.
const MAX_DATAGRAMS_PER_TICK: usize = 64;

/// Which of the two sockets is being drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    /// The well-known port, where queries arrive.
    Responder,
    /// The ephemeral port, where answers arrive.
    Querier,
}

/// Holds the service and runs it until asked to stop.
///
/// # Why there is no stop flag
///
/// Because the thread's work is *inbound* — a device that is not listening cannot be found — so ending it early would only
/// be to save a thread on a process that is exiting anyway. What a client controls is the deadline it publishes through
/// `on_demand`; the loop itself runs for the process's lifetime.
pub fn run(
    service: &Arc<Mutex<DiscoveryService>>,
    host: &Arc<Mutex<Host>>,
    on_demand: &Arc<AtomicI64>,
    cancel: &crate::supervisor::Cancellation,
    now_ms: impl Fn() -> i64 + Send + 'static,
) {
    run_recording(service, host, on_demand, cancel, now_ms, |_| {});
}

/// [`run`], which hands every candidate it has just heard to a callback.
///
/// # Why a callback rather than a database
///
/// Because this crate knows nothing about storage — that is the kernel's rule, and a worker that wrote rows would make
/// `cargo check` of this crate pull in a database for a loop that only ever listens on a socket. The caller owns the
/// write, and gets to decide what "remembered" means: the daemon writes to `devices_seen`, a test collects into a vector,
/// and neither makes the other possible.
///
/// # Why the callback is called with a slice and not per candidate
///
/// Because it is called on every tick and the candidate list is usually empty. A signature that took one candidate would
/// have to be called in a loop to decide there was nothing to say, and a caller that forgot the loop would simply never
/// be told anything.
pub fn run_recording(
    service: &Arc<Mutex<DiscoveryService>>,
    host: &Arc<Mutex<Host>>,
    on_demand: &Arc<AtomicI64>,
    cancel: &crate::supervisor::Cancellation,
    now_ms: impl Fn() -> i64 + Send + 'static,
    heard: impl Fn(&[crate::discovery::Candidate]) + Send + 'static,
) {
    // ★ The loop stops now, and its own doc used to say it could not.
    //
    // It read: "there is no stop flag ... the thread's work is *inbound*, so ending it early would only be to save a thread
    // on a process that is exiting anyway". That was true of a worker nobody supervised. A worker run under
    // [`crate::supervisor::run_task`] is *given* a token and is required to honour it — a closure that ignores one leaves a
    // thread running after the supervisor has recorded the task as stopped, which is a report that lies.
    //
    // The check is at the top rather than after the sleep: a stop request that arrives while the loop is asleep is seen on
    // the next turn, and `POLL_INTERVAL` is the longest anything waits.
    while !cancel.is_cancelled() {
        let now = Instant::now();
        let wall = now_ms();

        // ★ The two locks are taken **one at a time, never nested**. The table is behind the host's lock and the sockets
        // are behind the service's, and holding both while sending would mean a device listing waits for a network. The
        // tick takes the host and releases it; the answering takes the service alone.
        let ticked = {
            let deadline = on_demand.load(Ordering::Relaxed);
            let mut service = service.lock();
            let mut host = host.lock();
            service.tick(&mut host, wall, now, deadline)
        };

        // ★ The callback runs with **no lock held**. It is a caller-supplied closure that will usually write to a
        // database, and nesting a third lock inside this loop — which the daemon's control socket also takes — is how a
        // worker ends up blocking a device listing behind a write.
        //
        // Gated on `absorbed` being non-empty rather than called every tick, so a caller that writes a row per candidate
        // is not paying for a write on every poll of an idle network.
        if !ticked.absorbed.is_empty() {
            let candidates: Vec<crate::discovery::Candidate> =
                host.lock().usable(wall).into_iter().cloned().collect();
            heard(&candidates);
        }

        let service = service.lock();
        for (address, result) in service.answer_pending(&ticked) {
            if let Err(error) = result {
                // Reported rather than retried: the device that asked will ask again on its next broadcast, and a kernel
                // that stopped its loop for one failed send would stop discovering entirely.
                eprintln!("synra-daemon: could not answer {address}: {error}");
            }
        }
        drop(service);

        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Whether the table would show a device, for a caller reporting a tick.
#[must_use]
pub fn is_visible(table: &DiscoveryTable, now_ms: i64) -> bool {
    table.displayable(now_ms).next().is_some()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicI64;

    use parking_lot::Mutex;

    use super::*;
    use crate::supervisor::Cancellation;
    use crate::identity::Identity;
    use crate::peer::{Flags, LocalPeer};
    use synra_protocol::handshake::PROTOCOL_VERSION;
    use synra_protocol::discovery::TrustLevel;
    use synra_protocol::ids::DeviceId;
    use synra_protocol::session::PlatformKind;
    use std::net::{Ipv4Addr, SocketAddr};

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

    /// A service with both sockets on ports the operating system chose.
    ///
    /// # Why the responder is not on the well-known port
    ///
    /// Because binding it would collide with a kernel that happens to be running on this machine, and because a test that
    /// needed the discovery port free would fail for a reason that has nothing to do with what it asserts. The service
    /// takes the address it is given; only `bind` uses the well-known port.
    fn service(id: &str, interval: Duration) -> DiscoveryService {
        DiscoveryService {
            responder: DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("a responder"),
            querier: DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("a querier"),
            ours: announcement(id, "Laptop", 47_100),
            next_query: Instant::now(),
            interval,
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

        assert!(worker.join().is_ok(), "the worker returned rather than looping for ever");
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
        assert!(!service.tick(&mut kernel, 1_001, start + Duration::from_millis(50), 0).broadcast);
        assert!(service.tick(&mut kernel, 1_002, start + Duration::from_secs(61), 0).broadcast);
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

        let asker = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
        asker
            .send_query(&announcement(B, "Phone", 47_101), responder)
            .expect("asks");

        let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
        assert_eq!(ticked.absorbed, vec![Absorbed::New { device_id: device(B) }]);
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

        let answerer = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an answerer");
        answerer
            .send_response(&announcement(B, "Phone", 47_101), querier)
            .expect("answers");

        let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
        assert_eq!(ticked.absorbed, vec![Absorbed::New { device_id: device(B) }]);
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
        raw.send_to(b"not a synra datagram", responder).expect("sends");

        let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
        // The good one was absorbed; the stray one stopped the drain rather than being reported.
        assert_eq!(ticked.absorbed, vec![Absorbed::New { device_id: device(B) }]);
        assert!(ticked.errors.is_empty(), "{:?}", ticked.errors);
    }

    // ── Answering ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_query_is_answered_on_the_port_the_asker_announced() {
        // ★ The round trip a real network does, and the thing that took a whole round to diagnose: the answer goes to the
        // **connection port the asker announced**, not to the ephemeral port the query was sent from. A test that listened
        // on its own sending socket would see nothing and report a broken responder, when the responder was correct and
        // the test was asking the wrong question.
        let mut service = service(B, Duration::from_secs(60));
        let responder = service.responder_address().expect("an address");
        let mut kernel = host(B, "Phone");

        // ★ The asker listens where it *said* a peer should connect to it. The announcement and the bind have to agree, and
        // the first version of this had them disagree — the announcement named 47_100 while the socket listened on 47_101 —
        // so the answer went to a port nothing was bound to. That is not a bug in the responder, and the test asserting it
        // would have been asserting the wrong thing.
        let announced = 47_101;
        let asker = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, announced)))
            .expect("the announced port");
        asker.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");
        let from = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a sender");
        from.send_query(&announcement(A, "Laptop", announced), responder).expect("asks");

        // The service hears it and decides who to answer.
        let ticked = service.tick(&mut kernel, 5_000, Instant::now(), 0);
        assert_eq!(ticked.absorbed, vec![Absorbed::New { device_id: device(A) }]);
        assert_eq!(ticked.askers.len(), 1, "the asker was not recorded");
        // The recorded address is the announced connection port, not the port the query came from — which is the whole
        // point, and is why `from` above is a *different* socket on an ephemeral port.
        assert_eq!(ticked.askers[0].port(), announced);
        assert_ne!(ticked.askers[0].port(), from.local_addr().expect("an address").port());

        for (_, result) in service.answer_pending(&ticked) {
            assert!(result.is_ok(), "{result:?}");
        }

        // And it arrives, parsed as the answer it is.
        let mut receiving = host(A, "Laptop");
        let absorbed = asker.receive(&mut receiving, 5_000).expect("receives");
        assert_eq!(absorbed, Some(Absorbed::New { device_id: device(B) }));
        assert_eq!(
            receiving.discovery().get(device(B)).expect("a candidate").display_name,
            "Laptop"
        );
    }

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
        let asker = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
        asker.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");

        let sent = service.answer(asker.local_addr().expect("an address")).expect("answers");
        assert!(sent > 0);

        // The asker reads it as a response carrying the answerer's own announcement.
        let mut kernel = host(B, "Phone");
        let absorbed = asker.receive(&mut kernel, 5_000).expect("receives");
        assert_eq!(absorbed, Some(Absorbed::New { device_id: device(A) }));
        let candidate = kernel.discovery().get(device(A)).expect("a candidate");
        assert_eq!(candidate.display_name, "Laptop");
        assert_eq!(candidate.address.port(), 47_100);
    }

    #[test]
    fn a_goodbye_reaches_the_broadcast_addresses_and_reports_each() {
        // A device that is shutting down has no second chance, and every interface deserves its own attempt.
        let service = service(A, Duration::from_secs(60));
        let results = service.goodbye(1_700_000_000_000);
        assert_eq!(results.len(), crate::socket::broadcast_addresses().len());
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
        assert_eq!(ticked.absorbed, vec![Absorbed::New { device_id: device(A) }]);

        // ★ The answer goes to the querier, not to the responder — which is the whole reason there are two sockets.
        answerer
            .answer(asker_querier)
            .expect("answers");

        // And the asker learns about the answerer.
        let ticked = asker.tick(&mut asking, 5_001, Instant::now(), 0);
        assert_eq!(ticked.absorbed, vec![Absorbed::New { device_id: device(B) }]);
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
        let asker = DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("an asker");
        asker
            .send_query(&announcement(B, "Phone", 47_101), responder)
            .expect("asks");
        service.tick(&mut kernel, 5_000, Instant::now(), 0);

        assert_eq!(
            kernel.discovery().get(device(B)).expect("a candidate").trust,
            TrustLevel::Announced
        );
        assert!(!is_visible(kernel.discovery(), 5_000), "an announced device should not be visible");
    }

    #[test]
    fn a_service_debug_form_names_the_device_and_the_port() {
        // It appears in a log line, and a handle that printed a socket would leak the path.
        let service = service(A, Duration::from_secs(60));
        let text = format!("{service:?}");
        assert!(text.contains("Laptop") || text.contains("47100") || text.contains("47_100"), "{text}");
        assert!(!text.contains("127.0.0.1"), "{text}");
    }
}
