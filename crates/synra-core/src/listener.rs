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
use synra_protocol::envelope::Envelope;

/// How long the accept loop waits between polls when nothing is waiting.
///
/// The listener is non-blocking so the loop can also check its stop flag. A blocking accept would be a thread that could
/// not be asked to stop, which is a thread that outlives its process's shutdown.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// What one accepted connection produced.
#[derive(Debug, Clone, PartialEq, Eq)]
/// A transfer that finished and whose file was verified.
///
/// ★ **Why the listener hands these back rather than only logging them.**
///
/// `Decision::Finished` is where a received file stops being bytes, and until this existed the only thing the listener
/// could do with a plugin bundle was print a line — the kernel received one and forgot it. `SyncRecord` grew the fields
/// for a record in round 133, migration v10 gave it a table in round 135, and round 136 wrote the conversion between
/// them; all three have had no production caller, and this is why: the place a transfer finishes had nothing to write
/// **to**. This is the value that travels from that place to a caller that has a database.
pub struct FinishedTransfer {
    /// Which transfer it was.
    ///
    /// `None` only for a completion that arrived with no proposal this listener saw, which is a protocol violation rather
    /// than a transfer — and a row named by a made-up identifier would be worse than no row. The shell uses this to close
    /// the progress row it opened when the proposal was accepted.
    pub transfer_id: Option<synra_protocol::ids::TransferId>,
    /// Where the file landed.
    pub path: std::path::PathBuf,
    /// How large it was.
    pub byte_length: u64,
    /// Which plugin it is a bundle for, when it is one.
    pub bundle: Option<synra_protocol::ids::PluginId>,
    /// The digest this device verified the file against.
    pub digest: String,
    /// The version the sender declared, when this arrived as a plugin bundle.
    pub version: Option<String>,
    /// Which round this belonged to, when the sender named one.
    pub sync_session_id: Option<synra_protocol::ids::SessionId>,
    /// Which device it came from.
    ///
    /// Carried per transfer rather than read off `Served::peer` by the caller: `peer` is a fact about the *connection*
    /// and this is a fact about the *file*, and a caller writing history would otherwise need to hold both pieces
    /// together to know who sent what.
    pub peer: synra_protocol::ids::DeviceId,
}

/// One step of an inbound transfer, for a reporter that keeps a row in an interface.
///
/// The peer is here rather than inside `progress` because it is a fact about the connection, not about the bytes — the
/// receiver writes to a path and knows nothing about who is on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundProgressEvent {
    /// Who is sending.
    pub peer: synra_protocol::ids::DeviceId,
    /// How far the transfer has got.
    pub progress: crate::session::InboundProgress,
    /// The transfer ended without a file: the peer aborted, or a block was refused.
    ///
    /// ★ The last event of a failed transfer is still an event. Without it a reporter that opened a row for
    /// [`InboundProgress`] would keep it for ever — the sender's abort would be a row that says "arriving" until the
    /// process ends.
    pub aborted: bool,
}

/// What the listener does with each step of an inbound transfer.
///
/// `Send + Sync` for the same reason [`FinishedCallback`] is: the connections that call it live on their own threads, and
/// one callback is shared by all of them.
pub type ProgressCallback = dyn Fn(&InboundProgressEvent) + Send + Sync;

/// Whether the host wants the transfer in progress given up.
///
/// ★ Asked between messages, never from another thread: the connection's own loop is the only writer to its link, and a
/// command that could send an abort from outside would be a second writer to one socket.
pub type CancelCallback = dyn Fn(&str) -> bool + Send + Sync;

/// A cancel callback for a host that does not offer one.
fn no_cancel() -> Arc<CancelCallback> {
    Arc::new(|_: &str| false)
}

/// What a host did with a kernel event that arrived on a link.
#[derive(Debug)]
#[non_exhaustive]
pub enum KernelEventOutcome {
    /// The host does not handle this event.
    Ignored,
    /// The host handled it, and there is nothing to send back.
    Handled,
    /// The answer to send back on the same link.
    Reply(Box<Envelope>),
    /// The event was understood and refused, with a sentence for the log.
    Refused(String),
}

/// Answers a kernel event (`INTENT_INVOKE`, `INTENT_CANCEL`) that arrived on a link.
///
/// # Why a callback rather than code here
///
/// Because running an action needs the plugin set and the intent board, which belong to the host; the listener owns the
/// connection, not the runtime. The callback is the same seam `FinishedCallback` uses, and it exists for the same reason:
/// a reply belongs on the connection that asked, so the answer has to be produced **while the link is still open**.
pub type KernelEventCallback = dyn Fn(&Envelope) -> KernelEventOutcome + Send + Sync;

/// A kernel-event callback for a host that runs no kernel events.
#[must_use]
pub fn no_kernel_events() -> Arc<KernelEventCallback> {
    Arc::new(|_event: &Envelope| KernelEventOutcome::Ignored)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// What one connection did, handed back to whoever served it.
///
/// `events` is the count a test asserts and `finished` is the value a caller writes down; `ended` is how a session
/// that went wrong ended, and is `None` for the ordinary case of a peer that hung up.
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
    /// Every transfer that finished and verified on this connection, in order.
    pub finished: Vec<FinishedTransfer>,
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
    on_finished: &FinishedCallback,
    on_kernel_events: &Arc<KernelEventCallback>,
) {
    // A listener that nobody asked to observe has the same behaviour it always had; only the callbacks differ.
    let on_progress: Arc<ProgressCallback> = Arc::new(|_event: &InboundProgressEvent| {});
    let offer: Arc<crate::inbound::OfferCallback> = Arc::new(crate::inbound::auto_accept);
    let should_cancel = no_cancel();
    serve_with(
        host,
        cancel,
        data_dir,
        desk,
        router,
        on_finished,
        &on_progress,
        &offer,
        &should_cancel,
        on_kernel_events,
    );
}

/// Serves inbound connections, reporting each step of an inbound transfer.
///
/// The same loop as [`serve`], with the reporter it was missing: `on_progress` sees the proposal accepted and every block
/// that lands, which is what lets an interface show a transfer **arriving** rather than only one it started.
// The ten are the listener's settings, its two observers, the question a host is asked about each transfer, and whether
// the host wants the one in progress given up. The `serve` wrapper exists because most callers need none of the last
// three.
#[allow(clippy::too_many_arguments)]
pub fn serve_with(
    host: &Arc<Mutex<Host>>,
    cancel: &crate::supervisor::Cancellation,
    data_dir: &Path,
    desk: &Arc<crate::pairing::PairingDesk>,
    router: &Arc<crate::dispatch::orchestrate::Router>,
    on_finished: &FinishedCallback,
    on_progress: &Arc<ProgressCallback>,
    offer: &Arc<crate::inbound::OfferCallback>,
    should_cancel: &Arc<CancelCallback>,
    on_kernel_events: &Arc<KernelEventCallback>,
) {
    // Owned, because each connection is handed to its own thread and a thread cannot borrow the caller's stack.
    let data_dir = data_dir.to_path_buf();
    // Cloned per connection below, because the desk is shared: a prompt raised on one connection is answered by a user
    // who is not on that connection at all.
    let shared_desk = Arc::clone(desk);
    let shared_offer = Arc::clone(offer);
    // Cloned per connection like the desk, and for the same reason: a share arriving on one connection is routed with the
    // kernel's plugins and intents, not with a per-connection copy of them.
    let shared_router = Arc::clone(router);
    let shared_cancel = Arc::clone(should_cancel);
    let shared_kernel_events = Arc::clone(on_kernel_events);
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
                let offer = Arc::clone(&shared_offer);
                let router = Arc::clone(&shared_router);
                let should_cancel = Arc::clone(&shared_cancel);
                let kernel_events = Arc::clone(&shared_kernel_events);
                // A thread per connection, because a link's lifetime is a peer's to decide. Nothing joins it: a link that
                // ended is one whose thread returns, and one that is still open is doing useful work.
                // ★ The callback is cloned per connection, and it has to be `Send + Sync + 'static`: the thread below
                // owns it, so a borrow cannot reach it. This is what makes the value that `Decision::Finished` produces
                // reach somebody who can write it down — until now the connection thread looked at `Served` and threw
                // it away, and a received bundle became a line on stderr and nothing else.
                let on_finished = Arc::clone(on_finished);
                let on_progress = Arc::clone(on_progress);
                std::thread::spawn(move || {
                    // ★ The callback goes **into** the handler rather than being applied to its result, and that is
                    // the correction of a mistake from round 148: applied here, it ran after the link was gone — so
                    // the side that installed a bundle could not tell the sender so, and the result the sender is
                    // waiting for could never be sent. A reply belongs on the connection that asked.
                    let served = handle_with(
                        &host,
                        stream,
                        &inbox_root,
                        &desk,
                        &router,
                        &on_finished,
                        &on_progress,
                        &offer,
                        &should_cancel,
                        &kernel_events,
                    );
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
    on_finished: &FinishedCallback,
) -> Served {
    let on_progress: Arc<ProgressCallback> = Arc::new(|_event: &InboundProgressEvent| {});
    let offer: Arc<crate::inbound::OfferCallback> = Arc::new(crate::inbound::auto_accept);
    handle_with(
        host,
        stream,
        data_dir,
        desk,
        router,
        on_finished,
        &on_progress,
        &offer,
        &no_cancel(),
        &no_kernel_events(),
    )
}

/// Handles one connection, reporting each step of an inbound transfer.
// The nine are the connection, where it writes, the shared pairing desk, the router, the two observers, and the question a
// host is asked about the transfer. The wrappers below hide most of them.
#[allow(clippy::too_many_arguments)]
pub fn handle_with(
    host: &Arc<Mutex<Host>>,
    stream: std::net::TcpStream,
    data_dir: &Path,
    desk: &Arc<crate::pairing::PairingDesk>,
    router: &Arc<crate::dispatch::orchestrate::Router>,
    on_finished: &FinishedCallback,
    on_progress: &Arc<ProgressCallback>,
    offer: &Arc<crate::inbound::OfferCallback>,
    should_cancel: &Arc<CancelCallback>,
    on_kernel_events: &Arc<KernelEventCallback>,
) -> Served {
    handle_within_with(
        host,
        stream,
        data_dir,
        synra_protocol::limits::HELLO_TIMEOUT,
        desk,
        router,
        on_finished,
        on_progress,
        offer,
        should_cancel,
        on_kernel_events,
    )
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
    on_finished: &FinishedCallback,
) -> Served {
    let on_progress: Arc<ProgressCallback> = Arc::new(|_event: &InboundProgressEvent| {});
    let offer: Arc<crate::inbound::OfferCallback> = Arc::new(crate::inbound::auto_accept);
    handle_within_with(
        host,
        stream,
        data_dir,
        timeout,
        desk,
        router,
        on_finished,
        &on_progress,
        &offer,
        &no_cancel(),
        &no_kernel_events(),
    )
}

/// Handles one connection, reporting each step of an inbound transfer, with a chosen handshake deadline.
// The eight are the connection, where it writes, its deadline, the shared pairing desk, the router, and the two
// observers. A struct would rename them without making the call site shorter, and the two `handle` wrappers that hide
// most of them exist precisely because most callers need neither observer.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn handle_within_with(
    host: &Arc<Mutex<Host>>,
    stream: std::net::TcpStream,
    data_dir: &Path,
    timeout: Duration,
    desk: &Arc<crate::pairing::PairingDesk>,
    router: &Arc<crate::dispatch::orchestrate::Router>,
    on_finished: &FinishedCallback,
    on_progress: &Arc<ProgressCallback>,
    offer: &Arc<crate::inbound::OfferCallback>,
    should_cancel: &Arc<CancelCallback>,
    on_kernel_events: &Arc<KernelEventCallback>,
) -> Served {
    // ★ Read before the handshake consumes the stream, and kept as text. It is the one fact about the requester this side
    // *observed* rather than was told: a prompt shows the name the device chose, and the address is what lets a user
    // recognise a machine they have never paired with. A socket that cannot report it yields an empty string, because a
    // prompt without an address is still a prompt and refusing to show one would be worse.
    let peer_address = stream.peer_addr().map(|address| address.to_string()).unwrap_or_default();
    // ★ Set on the stream before anything reads from it. A peer that connects and goes silent — a port scan, another
    // product's client — is bounded by this rather than by the process's lifetime.
    if let Err(error) = stream.set_read_timeout(Some(timeout)) {
        return Served { peer: None, events: Vec::new(), finished: Vec::new(), ended: Some(error.to_string()) };
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
            //
            // ★ Counted with a reason of its own: a port scan, a version mismatch and a peer that changed its mind all end
            // here, and none of them is a link that "closed" — there was never a link.
            host.lock().count_link_closed("handshake");
            return Served { peer: None, events: Vec::new(), finished: Vec::new(), ended: Some(error.to_string()) };
        }
    };

    let peer = link.peer();
    let mut events = Vec::new();
    // The transfers that finished on this connection, kept for the caller rather than only printed.
    let mut finished = Vec::new();
    // ★ The connection's transfer state: a proposal is remembered here, and the blocks that follow it are written into the
    // file it named. Without this the loop below would see a block as an unexpected frame and close the link — which is
    // what it did before, and why `send --file` could not work.
    let mut inbox = Inbox::new(data_dir);
    // The last step reported, so a completion can name the transfer it ends: `Decision::Finished` carries a path and a
    // size, not an identifier, and a consumer that wants to close the row it opened needs the identifier.
    let mut last_progress: Option<crate::session::InboundProgress> = None;
    // ★ The shared desk, not a per-connection state. A prompt raised on this connection is answered by a user who is not
    // on it at all, and a per-connection state would make that answer invisible here — the dialer would wait out its own
    // thirty-second window for a decision the user had already made.
    loop {
        // ★ Checked between messages, because the link belongs to this loop. A cancel that took effect only after the
        // next block would still write a block the user said they did not want; one that sent the abort from the command
        // thread would race this one for the same socket.
        if let Some(progress) = inbox.progress()
            && should_cancel(&progress.transfer_id.to_string())
        {
            match inbox.cancel(&mut link, synra_store::sqlite::now_ms()) {
                Ok(Some(cancelled)) => {
                    events.push(format!("cancelled {cancelled}"));
                    if let Some(progress) = last_progress.clone() {
                        on_progress(&InboundProgressEvent { peer, progress, aborted: true });
                    }
                }
                Ok(None) => {}
                Err(error) => eprintln!("synra-daemon: the cancel could not be sent: {error}"),
            }
        }
        match inbox.absorb_with(&mut link, synra_store::sqlite::now_ms(), PATIENCE, desk, &peer_address, offer.as_ref()) {
            Ok(decision) => match decision {
                Decision::Delivered { event, share, request } => {
                    // ★ `frames_received_total{event}` is recorded by the link's `receive_inbound`, not here. This branch
                    // sees only the frames a listener *delivered*; an answer on a dialled link — a pairing response, a
                    // plugin list — never reaches a listener, and those were invisible. The link is the one place every
                    // received frame passes, so the count lives there and this branch would double it.
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
                                // ★ The typed report rather than a JSON lookup. The value is a `Routed` now,
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
                        // ★ A kernel event that runs an action, or withdraws one. It is answered **here**, on the
                        // connection that asked, because the answer is a reply: a host that ran the action and sent the
                        // result on a second connection would be answering a question nobody is listening for.
                        None
                            if event == synra_protocol::event::events::INTENT_INVOKE
                                || event == synra_protocol::event::events::INTENT_CANCEL =>
                        {
                            let Some(envelope) = request else {
                                eprintln!(
                                    "synra-daemon: {peer} sent {event} without an envelope to answer"
                                );
                                continue;
                            };
                            answer_kernel_event(&mut link, &envelope, on_kernel_events, &mut events);
                        }
                        // ★ **A question this kernel can answer by itself.** "What plugins do you have" is a read of
                        // this device's own store — `plugins` joined to the active row of `plugin_versions` — and the
                        // answer is what the asker's plan compares. It is answered here rather than by a host callback
                        // because the kernel owns the tables: two hosts answering it separately would be two answers to
                        // one question, and the sync decision would inherit the difference.
                        None if event == synra_protocol::event::events::PLUGIN_LIST_REQUEST => {
                            let answer = match (&pairing, request) {
                                (Ok(db), Some(request)) => crate::plugin_sync::answer_plugin_list(
                                    db,
                                    &request,
                                    link.local(),
                                    synra_store::sqlite::now_ms(),
                                ),
                                (Ok(_), None) => {
                                    eprintln!(
                                        "synra-daemon: {peer} asked what plugins this device has, without an envelope to answer"
                                    );
                                    continue;
                                }
                                (Err(error), _) => {
                                    eprintln!(
                                        "synra-daemon: {peer} asked what plugins this device has, and the database could not be read: {error}"
                                    );
                                    continue;
                                }
                            };
                            match answer {
                                Ok(reply) => {
                                    if let Err(error) = link.send(&reply) {
                                        eprintln!(
                                            "synra-daemon: the plugin list could not be sent to {peer}: {error}"
                                        );
                                    }
                                }
                                // A failure to answer does not end the link, the same choice the pairing answer makes:
                                // the dialer's own deadline already covers giving up, and closing the connection would
                                // take a transfer down for a reason the peer cannot see.
                                Err(error) => eprintln!(
                                    "synra-daemon: the plugin list for {peer} could not be built: {error}"
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
                                match Envelope::reply_to(
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
                    // The ordinary, quiet end. Counted with its own reason so a panel can tell "the peer finished and
                    // hung up" from "the peer went silent" and from a fault.
                    host.lock().count_link_closed("idle");
                    return Served { peer: Some(peer), events, finished: finished.clone(), ended: None };
                }
                Decision::Accepted { transfer_id, file_name } => {
                    events.push(format!("accepted {transfer_id}"));
                    println!("receiving {file_name} from {peer}");
                    // ★ The proposal is the first moment a row can exist: the sender has declared a size, and the file is
                    // being created. A reporter that waited for the first block would show nothing for a slow link.
                    last_progress = inbox.progress();
                    if let Some(progress) = &last_progress {
                        on_progress(&InboundProgressEvent { peer, progress: progress.clone(), aborted: false });
                    }
                }
                Decision::Stored { index, duplicate } => {
                    // Per-block logging would be enormous for a real file, so only the interesting case is said: a block
                    // that arrived twice is a resumption working, and one that is logged is one a developer can see.
                    if duplicate {
                        eprintln!("synra-daemon: {peer} re-sent block {index}, which was already held");
                    }
                    last_progress = inbox.progress();
                    if let Some(progress) = &last_progress {
                        on_progress(&InboundProgressEvent { peer, progress: progress.clone(), aborted: false });
                    }
                }
                Decision::Finished {
                    path,
                    byte_length,
                    bundle,
                    digest,
                    version,
                    request_id,
                    sync_session_id,
                    trace_id,
                } => {
                    events.push("finished".to_owned());
                    // ★ The three facts travel together, and `bundle` is the one that says which of them this is.
                    // ★ 先造出来交给回调，再收进列表：回调的答案属于**这个**传输，而它已经被移走了就没有了。
                    let transfer = FinishedTransfer {
                        transfer_id: last_progress.as_ref().map(|progress| progress.transfer_id),
                        path: path.clone(),
                        byte_length,
                        bundle: bundle.clone(),
                        peer,
                        digest: digest.clone(),
                        version,
                        sync_session_id,
                    };
                    // ★ 收到、检查、装完 —— 现在告诉对端。第 133 轮的 `sync_result` 与第 134 轮的
                    // `apply_result` 等的就是这一行，而它只能在连接还活着的时候发。
                    if let Some(outcome) = on_finished(&transfer) {
                        let context = synra_protocol::envelope::ReplyContext {
                            request_id,
                            target: transfer.peer,
                            from: host.lock().device_id(),
                            trace_id,
                            ttl_ms: None,
                        };
                        if let Ok(reply) = crate::messaging::sync_result(
                            context,
                            &outcome,
                            synra_store::sqlite::now_ms(),
                        ) {
                            let _ = link.send(&reply);
                        }
                    }
                    finished.push(transfer);
                    // ★ A bundle is said out loud rather than printed as another file. The kernel does not install one
                    // yet, and a line that reads like every other received file is how "not installed yet" becomes
                    // "somebody will notice later" — the state this codebase keeps replacing with a sentence that says
                    // which half is missing.
                    match bundle {
                        Some(plugin_id) => println!(
                            "received {byte_length} bytes into {} — a plugin bundle for {plugin_id}, which this kernel does not install yet",
                            path.display()
                        ),
                        None => println!("received {byte_length} bytes into {}", path.display()),
                    }
                }
                Decision::Failed { why } => {
                    events.push("failed".to_owned());
                    eprintln!("synra-daemon: a transfer from {peer} failed: {why}");
                    // ★ The row this connection opened has to be closed, and a failure is still an event. Without this a
                    // peer's abort left the interface showing a transfer arriving for ever.
                    if let Some(progress) = &last_progress {
                        on_progress(&InboundProgressEvent {
                            peer,
                            progress: progress.clone(),
                            aborted: true,
                        });
                    }
                }
            },
            // A `Bye` is the ordinary end, and so is a peer that hung up. Neither is a fault, and both end the loop.
            Err(SessionError::Link(LinkError::Closed)) => {
                host.lock().count_link_closed("closed");
                return Served { peer: Some(peer), events, finished: finished.clone(), ended: None };
            }
            Err(error) => {
                host.lock().count_link_closed(close_reason(&error));
                return Served { peer: Some(peer), events, finished: Vec::new(), ended: Some(error.to_string()) };
            }
        }
    }
}

/// Answers one kernel event on the connection it arrived on.
///
/// # Why this is a function rather than an arm
///
/// Because the connection loop is long enough that adding four outcomes to one of its arms pushed it past the complexity
/// budget — and the budget is right: a reader of the loop should see "an intent event is answered here", not four branches
/// about what kind of answer it was.
fn answer_kernel_event(
    link: &mut PeerLink,
    envelope: &Envelope,
    on_kernel_events: &Arc<KernelEventCallback>,
    events: &mut Vec<String>,
) {
    let event = envelope.event.as_str();
    match on_kernel_events(envelope) {
        KernelEventOutcome::Handled => events.push(format!("handled {event}")),
        KernelEventOutcome::Reply(reply) => {
            events.push(format!("answered {event}"));
            if let Err(error) = link.send(&reply) {
                eprintln!("synra-daemon: the answer to {event} could not be sent: {error}");
            }
        }
        KernelEventOutcome::Refused(why) => {
            eprintln!("synra-daemon: {event} could not be handled: {why}");
        }
        // Not an error: an event this kernel does not run is one it must not guess at.
        KernelEventOutcome::Ignored => events.push(format!("unhandled {event}")),
    }
}

/// Why a connection ended, as the label of `links_closed_total`.
///
/// The vocabulary is the `LinkError`'s own: a timeout is not a transport failure, a peer's `Bye` is not a fault, and a frame
/// the decoder refused is the peer's protocol rather than the network.
const fn close_reason(error: &SessionError) -> &'static str {
    match error {
        SessionError::Link(LinkError::TimedOut) => "timeout",
        SessionError::Link(LinkError::Closed) => "closed",
        SessionError::Link(LinkError::Frame(_) | LinkError::Unexpected { .. } | LinkError::Envelope { .. }) => {
            "protocol"
        }
        SessionError::Link(LinkError::Transport { .. }) => "transport",
        SessionError::Transfer(_) => "transfer",
        _ => "protocol",
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

/// What the connection handler asks the host to do about a transfer that just finished.
///
/// ★ **Why the three arguments are named rather than written out three times.** The signature appeared in `serve`,
/// `handle` and `handle_within`, and clippy's `type_complexity` was right about it: three copies of a type nobody can
/// read is three places to change and one place to understand.
///
/// ★ **Why it returns an answer rather than nothing.** It is called while the connection is still open, and what it
/// returns is what the sender is told. `None` means "there is nothing to say" — an attachment is not a round of
/// synchronisation, so it has no result.
pub type FinishedCallback =
    Arc<dyn Fn(&FinishedTransfer) -> Option<crate::plugin_sync::SyncOutcome> + Send + Sync>;

/// A callback that answers nothing.
///
/// For a host with no opinion about what it received — a test, or a build that only wants the file on disk. It is a
/// named function rather than a closure written at each call site because the type is the unreadable part, and three
/// spellings of it would be three places to change.
#[must_use]
pub fn no_answer() -> FinishedCallback {
    Arc::new(|_| None)
}
