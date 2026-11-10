use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::host::Host;
use crate::link::PeerLink;

use super::connection::handle_with;
use super::types::no_cancel;
use super::{
    CancelCallback, FinishedCallback, InboundProgressEvent, KernelEventCallback, POLL_INTERVAL,
    ProgressCallback,
};

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
            eprintln!(
                "synra-daemon: the transport listener could not become non-blocking: {error}"
            );
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
            // ★ An accepted socket is answered on its own thread: a handshake is IO, and the loop that accepts must
            // not be one handshake behind. Nothing about identity is checked here any more — the link is plaintext.
            Ok(Some(stream)) => {
                let host = Arc::clone(host);
                // Each connection gets its own copy of the path, because a thread cannot borrow the loop's.
                let inbox_root = data_dir.clone();
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
                        &router,
                        &on_finished,
                        &on_progress,
                        &offer,
                        &should_cancel,
                        &kernel_events,
                    );
                    if let Some(ended) = &served.ended {
                        let who = served.peer.map_or_else(
                            || "an unidentified peer".to_owned(),
                            |peer| peer.to_string(),
                        );
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
