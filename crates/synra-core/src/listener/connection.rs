use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::host::Host;
use crate::inbound::Inbox;
use parking_lot::Mutex;

use super::traffic;
use super::types::no_cancel;
use super::types::no_kernel_events;
use super::{
    CancelCallback, FinishedCallback, InboundProgressEvent, KernelEventCallback, ProgressCallback,
    Served,
};

/// Authenticates an approved peer and reads business traffic with per-frame authorization checks.
///
/// The host must have persistent credentials configured. This wrapper chooses default transfer
/// callbacks; neither an unknown peer nor a legacy token can bypass the authenticated entry.
#[must_use]
pub fn handle(
    host: &Arc<Mutex<Host>>,
    stream: std::net::TcpStream,
    data_dir: &Path,
    router: &Arc<crate::dispatch::orchestrate::Router>,
    on_finished: &FinishedCallback,
) -> Served {
    let on_progress: Arc<ProgressCallback> = Arc::new(|_event: &InboundProgressEvent| {});
    let offer: Arc<crate::inbound::OfferCallback> = Arc::new(crate::inbound::auto_accept);
    handle_with(
        host,
        stream,
        data_dir,
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
    let peer_address = stream
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_default();
    // ★ Set on the stream before anything reads from it. A peer that connects and goes silent — a port scan, another
    // product's client — is bounded by this rather than by the process's lifetime.
    if let Err(error) = stream.set_read_timeout(Some(timeout)) {
        return Served {
            peer: None,
            events: Vec::new(),
            finished: Vec::new(),
            ended: Some(error.to_string()),
        };
    }
    let now = crate::reading_millis(synra_store::sqlite::now_ms());

    // Snapshot the credential configuration, perform TLS and Hello outside the host lock, then
    // record only the authenticated result. Each later frame retains its own authorization check.
    let (configuration, mut flags) = host.lock().dialling_parts();
    flags.timeout = Some(timeout.min(flags.timeout.unwrap_or(timeout)));
    // Authentication, database approval queries and Hello all run outside the host guard.
    let authenticated = configuration.accept_stream(stream, flags, now);
    // Hello establishes a connection, not the user's consent. Only answer_pairing may create a pairing row.
    let handshake = authenticated.and_then(|accepted| {
        let blocked = synra_store::SynraDb::open(&data_dir.join(synra_store::DB_FILE_NAME))
            .and_then(|db| db.paired_devices())
            .map_err(|error| crate::HostError::Authentication {
                why: error.to_string(),
            })?
            .iter()
            .any(|row| row.device_id == accepted.negotiated().device_id.to_string() && row.blocked);
        if blocked {
            return Err(crate::HostError::Authentication {
                why: "this peer is blocked".to_owned(),
            });
        }
        host.lock().adopt_with_events(accepted, now)
    });

    let (link, _events) = match handshake {
        Ok(pair) => pair,
        Err(error) => {
            // A failed handshake has no peer to name, so the address is what identifies it in a log line. The peer's own
            // identifier is exactly what the handshake was establishing, and it is not known.
            //
            // ★ Counted with a reason of its own: a port scan, a version mismatch and a peer that changed its mind all end
            // here, and none of them is a link that "closed" — there was never a link.
            host.lock().count_link_closed("handshake");
            return Served {
                peer: None,
                events: Vec::new(),
                finished: Vec::new(),
                ended: Some(error.to_string()),
            };
        }
    };

    let peer = link.peer();
    let events = Vec::new();
    // The transfers that finished on this connection, kept for the caller rather than only printed.
    let finished = Vec::new();
    // ★ The connection's transfer state: a proposal is remembered here, and the blocks that follow it are written into the
    // file it named. Without this the loop below would see a block as an unexpected frame and close the link — which is
    // what it did before, and why `send --file` could not work.
    let inbox = Inbox::new(data_dir);
    // The last step reported, so a completion can name the transfer it ends: `Decision::Finished` carries a path and a
    // size, not an identifier, and a consumer that wants to close the row it opened needs the identifier.
    let last_progress: Option<crate::session::InboundProgress> = None;
    // ★ The shared desk, not a per-connection state. A prompt raised on this connection is answered by a user who is not
    // on it at all, and a per-connection state would make that answer invisible here — the dialer would wait out its own
    // thirty-second window for a decision the user had already made.
    // ★ 配对的那张桌子：随连接线程带进来，但它属于整套 Host——另一个连接上的人也会改它。
    let desk = host.lock().pairing();

    traffic::run(
        host,
        link,
        peer,
        peer_address,
        data_dir,
        router,
        timeout,
        on_finished,
        on_progress,
        offer,
        should_cancel,
        on_kernel_events,
        events,
        finished,
        inbox,
        last_progress,
        desk,
    )
}
