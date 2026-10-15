//! The listening half of the session layer.
//!
//! # Why a kernel needs this at all
//!
//! [`crate::Host::dial`] makes an *outbound* link, and a device that can only dial is a device nobody can send to. The
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
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
// The types this module's own API is expressed in, re-exported so a caller can name them without reaching past it.
pub use crate::inbound::{Decision, Inbox, PairingAnswer};
use crate::host::Host;
use crate::SessionError;
use crate::link::{LinkError, PeerLink};

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
/// # Why the cancellation is passed in rather than owned
///
/// Because a listener that ignored a stop request would keep a socket bound until the process was killed — so a restart
/// would fail to bind for as long as the old process lingered. Handing in the token is also what lets this run under
/// [`crate::supervisor::run_task`], whose contract is that the work returns once the token is cancelled.
pub fn serve(
    host: &Arc<Mutex<Host>>,
    cancel: &crate::supervisor::Cancellation,
    data_dir: &Path,
    desk: &Arc<crate::pairing::PairingDesk>,
    router: &Arc<crate::dispatch::orchestrate::Router>,
) {
    // Owned, because each connection is handed to its own thread and a thread cannot borrow the caller's stack.
    let data_dir = data_dir.to_path_buf();
    // Cloned per connection below, because the desk is shared: a prompt raised on one connection is answered by a user
    // who is not on that connection at all.
    let shared_desk = Arc::clone(desk);
    // Cloned per connection like the desk, and for the same reason: a share arriving on one connection is routed with the
    // kernel's plugins and intents, not with a per-connection copy of them.
    let shared_router = Arc::clone(router);
    // ★ Non-blocking, so the loop comes round often enough to notice the stop flag. Set once rather than per iteration:
    // it is a property of the socket, and re-setting it fifty times a second would be a syscall per poll for nothing.
    match host.lock().listen_nonblocking() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("synra-daemon: the transport listener could not become non-blocking: {error}");
            return;
        }
    }

    // ★ This was an `Arc<AtomicBool>` named `stop` that meant "keep running", and the name cost a round: the first
    // version wrote `while !stop.load(..)`, so the loop exited on its first check and never accepted anything — a device
    // that bound its port, announced it, and silently refused every connection. It is a token now, and a token is one-way,
    // so the polarity cannot be got wrong: `is_cancelled` is `false` until somebody asks.
    while !cancel.is_cancelled() {
        // ★ One critical section, and it is a queue pop. The guard is dropped before the thread is spawned, because the
        // handshake happens there — see the module docs for why the two cannot be one step.
        let taken = { host.lock().try_accept() };

        match taken {
            Ok(Some(stream)) => {
                let host = Arc::clone(host);
                // Each connection gets its own copy of the path, because a thread cannot borrow the loop's.
                let inbox_root = data_dir.clone();
                let desk = Arc::clone(&shared_desk);
                let router = Arc::clone(&shared_router);
                // A thread per connection, because a link's lifetime is a peer's to decide. Nothing joins it: a link that
                // ended is one whose thread returns, and one that is still open is doing useful work.
                std::thread::spawn(move || {
                    let served = handle(&host, stream, &inbox_root, &desk, &router);
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
pub fn handle(
    host: &Arc<Mutex<Host>>,
    stream: std::net::TcpStream,
    data_dir: &Path,
    desk: &Arc<crate::pairing::PairingDesk>,
    router: &Arc<crate::dispatch::orchestrate::Router>,
) -> Served {
    handle_within(host, stream, data_dir, synra_protocol::limits::HELLO_TIMEOUT, desk, router)
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
    data_dir: &Path,
    timeout: Duration,
    desk: &Arc<crate::pairing::PairingDesk>,
    router: &Arc<crate::dispatch::orchestrate::Router>,
) -> Served {
    // ★ Read before the handshake consumes the stream, and kept as text. It is the one fact about the requester this side
    // *observed* rather than was told: a prompt shows the name the device chose, and the address is what lets a user
    // recognise a machine they have never paired with. A socket that cannot report it yields an empty string, because a
    // prompt without an address is still a prompt and refusing to show one would be worse.
    let peer_address = stream.peer_addr().map(|address| address.to_string()).unwrap_or_default();
    // ★ Set on the stream before anything reads from it. A peer that connects and goes silent — a port scan, another
    // product's client — is bounded by this rather than by the process's lifetime.
    if let Err(error) = stream.set_read_timeout(Some(timeout)) {
        return Served { peer: None, events: Vec::new(), ended: Some(error.to_string()) };
    }
    let now = crate::reading_millis(synra_store::sqlite::now_ms());

    // ★ One critical section for the handshake, and the link is taken **out** of the host with it. The read loop below
    // runs with no lock held at all: a peer that says nothing for an hour would otherwise hold the host for an hour, and
    // every `devices` and `send` in that time would wait behind it.
    //
    // The pairing question is answered from the database, which is opened here rather than held: a connection is
    // handshaked once, and the alternative is threading a handle through the serve loop so that every connection shares
    // one. SQLite opens a file cheaply, and this keeps the answer next to the question.
    let pairing = synra_store::SynraDb::open(&data_dir.join(synra_store::DB_FILE_NAME));
    let handshake = {
        let mut host = host.lock();
        host.complete_handshake(stream, now, |presented, device_id| match &pairing {
            Ok(db) => crate::inbound::pairing_state_for(db, device_id, presented),
            Err(error) => {
                // Named rather than silent. A daemon that cannot open its own database would otherwise refuse every peer
                // with no way for a user to tell that apart from "nobody has paired with us".
                eprintln!("synra-daemon: the pairing record could not be opened: {error}");
                synra_protocol::handshake::PairingState::Stale
            }
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
    // ★ The connection's transfer state: a proposal is remembered here, and the blocks that follow it are written into the
    // file it named. Without this the loop below would see a block as an unexpected frame and close the link — which is
    // what it did before, and why `send --file` could not work.
    let mut inbox = Inbox::new(data_dir);
    // ★ The shared desk, not a per-connection state. A prompt raised on this connection is answered by a user who is not
    // on it at all, and a per-connection state would make that answer invisible here — the dialer would wait out its own
    // thirty-second window for a decision the user had already made.
    loop {
        match inbox.absorb(&mut link, synra_store::sqlite::now_ms(), PATIENCE, desk, &peer_address) {
            Ok(decision) => match decision {
                Decision::Delivered { event, share } => {
                    // ★ Recorded as well as reported. A message this kernel received has arrived, and a log that looked
                    // the same whether it arrived or was lost in the network would be one a user cannot investigate with.
                    events.push(event.clone());
                    // ★ And routed, which is what a share is *for*.
                    //
                    // This used to end at the line below: a peer's shared text was reported and dropped, so a share could
                    // arrive and nothing would ask a plugin whether it could handle it. The design calls this routing the
                    // kernel's most central orchestration, and until here the inbound half of it did not exist.
                    match share {
                        Some(item) => {
                            match router.route(&item, synra_store::sqlite::now_ms()) {
                                // \u2605 The typed report rather than a JSON lookup. The value is a `Routed` now,
                                // and walking it as JSON would have been the library's shape leaking into a log line.
                                Ok(routed) => eprintln!(
                                    "synra-daemon: {peer} shared something — {} plugin(s) offered",
                                    routed.report.offered
                                ),
                                // A routing failure is reported and does not end the link: the message arrived, and
                                // closing the connection would take down a transfer for a reason the peer cannot see.
                                Err(refusal) => eprintln!(
                                    "synra-daemon: {peer}'s share could not be routed: {refusal}"
                                ),
                            }
                        }
                        // Not a share, so there is still no event bus to deliver it to — and saying so is the honest
                        // answer rather than an empty one.
                        None => eprintln!(
                            "synra-daemon: {peer} sent {event} — nothing is wired up to deliver it",
                        ),
                    }
                }
                Decision::Ignored => {}
                Decision::Pairing { answer, request } => {
                    events.push("pairing request".to_owned());
                    // ★ One of two things, and the difference is the whole reason the desk is shared. A refusal the desk
                    // produced itself — a second request from the same device, or one that could not be read — goes back
                    // immediately. A request that is on the desk blocks *this* thread on the channel until a user decides,
                    // wherever that user is: the answer arrives through the desk, not through this connection.
                    let answered = match answer {
                        Some(PairingAnswer::Now(response)) => Some(response),
                        Some(PairingAnswer::Waiting(_)) => {
                            println!("{peer} is asking to pair");
                            answer
                                .as_ref()
                                .and_then(PairingAnswer::take_waiter)
                                .map(|waiter| {
                                    waiter.wait(synra_protocol::session::SessionTimeouts::default().pairing)
                                })
                        }
                        None => None,
                    };

                    if let Some(answered) = answered {
                        // ★ A failure to answer is reported and does not end the link. The peer asked a question this
                        // kernel could not reply to; closing the connection would take any transfer on it down for a
                        // reason the user cannot see, and the dialer's own timeout already covers giving up.
                        match synra_protocol::event::EventName::parse(
                            synra_protocol::event::events::PAIR_RESPONSE,
                        ) {
                            Ok(event) => {
                                match synra_protocol::envelope::Envelope::reply_to(
                                    &request,
                                    event,
                                    link.local(),
                                    synra_store::sqlite::now_ms(),
                                    Some(&answered),
                                ) {
                                    Ok(reply) => {
                                        if let Err(error) = link.send(&reply) {
                                            eprintln!(
                                                "synra-daemon: the pairing answer could not be sent: {error}"
                                            );
                                        }
                                        else {
                                            eprintln!(
                                                "synra-daemon: {peer} asked to pair, and was answered"
                                            );
                                        }
                                    }
                                    Err(error) => eprintln!(
                                        "synra-daemon: the pairing answer could not be built: {error}"
                                    ),
                                }
                            }
                            Err(error) => {
                                eprintln!("synra-daemon: the pairing event name is invalid: {error}");
                            }
                        }
                    }
                }
                // Nothing arrived and the wait is over. The connection ends quietly: a peer that has gone silent has not
                // done anything wrong, and `Served::ended` is for faults.
                Decision::Idle => {
                    return Served { peer: Some(peer), events, ended: None };
                }
                Decision::Accepted { transfer_id, file_name } => {
                    events.push(format!("accepted {transfer_id}"));
                    println!("receiving {file_name} from {peer}");
                }
                Decision::Stored { index, duplicate } => {
                    // Per-block logging would be enormous for a real file, so only the interesting case is said: a block
                    // that arrived twice is a resumption working, and one that is logged is one a developer can see.
                    if duplicate {
                        eprintln!("synra-daemon: {peer} re-sent block {index}, which was already held");
                    }
                }
                Decision::Finished { path, byte_length } => {
                    events.push("finished".to_owned());
                    println!("received {byte_length} bytes into {}", path.display());
                }
                Decision::Failed { why } => {
                    events.push("failed".to_owned());
                    eprintln!("synra-daemon: a transfer from {peer} failed: {why}");
                }
            },
            // A `Bye` is the ordinary end, and so is a peer that hung up. Neither is a fault, and both end the loop.
            Err(SessionError::Link(LinkError::Closed)) => {
                return Served { peer: Some(peer), events, ended: None };
            }
            Err(error) => {
                return Served { peer: Some(peer), events, ended: Some(error.to_string()) };
            }
        }
    }
}

/// The deadline one inbound message is read under.
///
/// A peer that says nothing must not hold a thread for ever, and the protocol's own handshake timeout is the figure every
/// other part of the kernel uses for "how long may a peer take to speak".
const PATIENCE: Duration = synra_protocol::limits::HELLO_TIMEOUT;

/// Binds the transport port for inbound connections.
///
/// # Errors
///
/// Whatever [`Host::listen_on`] reports, so the caller can decide whether it is fatal. The daemon does **not** treat it as
/// fatal: a device that cannot listen is one nobody can send to, which is worse than a device that cannot start only in
/// the sense that it is quieter.
pub fn bind(host: &mut Host, port: u16) -> Result<SocketAddr, crate::HostError> {
    host.listen_on(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)))
}

/// What a link reported, for a test that drives one without a daemon.
#[must_use]
pub const fn is_open(link: &PeerLink) -> bool {
    !link.peer().is_nil()
}
