//! Supervised workers for transport, discovery and recovered intents.

use std::sync::Arc;

use parking_lot::Mutex;
use synra_core::supervisor::{Supervisor, TaskId, run_task};
use synra_store::SynraDb;

use crate::runtime::{Runtime, intent::Router};

// ★ The transport listener runs on its own thread for the same reason discovery does: taking a connection is cheap but
// a handshake is not. Each accepted transport connection is handed to its own thread, so a peer that is slow to say
// `Hello` delays nothing — and since control connections are threaded too, neither listener can queue the other.
pub(super) fn start_transport(
    supervisor: &Arc<Supervisor>,
    runtime: &Runtime,
    history_db: Arc<Mutex<SynraDb>>,
    router: Arc<Router>,
) {
    if runtime.host.lock().listen_nonblocking().is_ok() {
        let peers = Arc::clone(&runtime.host);
        let data_dir = runtime.data_dir.clone();
        // The runtime's own desk, not a second one: a prompt raised by the transport must be the prompt a control command
        // answers, and two desks would mean a user answering a request the waiting connection never hears about.
        // ★ Cloned before the task closure: the closure owns what it captures, and the listener below still needs the
        // runtime. A `runtime.plugins` moved into the closure would make `serve_one(&runtime)` a use after move.
        let receive_plugins = Arc::clone(&runtime.plugins);
        let receive_plugins_dir = runtime.data_dir.join("plugins");
        let receive_board = Arc::clone(&runtime.board);
        let local_device = runtime.identity.device_id;
        let id = TaskId::new("transport.accept");
        // The token is the loop's stop condition, so cancelling the task *is* stopping the listener — there is no second
        // flag for the two to disagree about.
        if let Err(error) = run_task(supervisor, &id, move |token| {
            // ★ What a finished transfer means is the same in both hosts, so the work lives in the kernel: a history
            // row, a row saying what the peer holds, and the installed plugin row. The daemon owned that function and
            // the window had none, which is why a bundle arriving at the window was recorded as the peer's state and
            // never as this device's.
            let on_finished: synra_core::listener::FinishedCallback = {
                let history_db = Arc::clone(&history_db);
                let plugins = Arc::clone(&receive_plugins);
                let plugins_dir = receive_plugins_dir.clone();
                Arc::new(move |transfer: &synra_core::listener::FinishedTransfer| {
                    // ★ A bundle is a `.synra` package now, so receiving one is installing it. Same pipeline as the shell:
                    // the difference between the hosts is the `HostFacts`, not a second set of checks.
                    let mut db = history_db.lock();
                    if let Some(plugin_id) = &transfer.bundle {
                        let backend = plugins.lock().backend().clone();
                        match synra_core::install::from_package(
                            &mut db,
                            &backend,
                            &plugins_dir,
                            &transfer.path,
                            synra_store::sqlite::now_ms(),
                            synra_plugin_host::verify::HostFacts::headless(),
                        ) {
                            Ok(_) => synra_core::plugin_sync::record_received(&db, transfer),
                            Err(refusal) => Some(synra_core::plugin_sync::SyncOutcome::refused(
                                plugin_id.clone(),
                                synra_core::plugin_sync::SyncSessionId::new(
                                    transfer
                                        .sync_session_id
                                        .map_or_else(String::new, |session| session.to_string()),
                                ),
                                format!("{}: {}", refusal.stage, refusal.reason),
                            )),
                        }
                    } else {
                        synra_core::plugin_sync::record_received(&db, transfer)
                    }
                })
            };
            // ★ A kernel event is run here, on the connection that asked, because the answer is a reply. The listener owns the
            // link and this host owns the plugins and the board; the callback is the seam between them — and without it an
            // `INTENT_INVOKE` arrived, was counted and was dropped: the sender waited for an outcome that no side produced.
            let on_kernel_events: Arc<synra_core::listener::KernelEventCallback> = {
                let plugins = Arc::clone(&receive_plugins);
                let plugin_events = plugins.lock().event_service();
                let board = Arc::clone(&receive_board);
                let local = local_device;
                Arc::new(move |envelope: &synra_protocol::envelope::Envelope, peer: &synra_protocol::ids::DeviceId| {
                    let now = synra_store::sqlite::now_ms();
                    if envelope.event.is_plugin() {
                        return match synra_core::plugin_events::answer_remote_event(plugin_events.as_ref(), envelope, peer, local, now) {
                            Ok(receipt) => synra_core::listener::KernelEventOutcome::Receipt(Box::new(receipt)),
                            Err(error) => synra_core::listener::KernelEventOutcome::Refused(error.to_string()),
                        };
                    }
                    crate::runtime::intent::handle_event(&plugins, &board, local, envelope, now)
                })
            };
            synra_core::listener::serve(
                &peers,
                token,
                &data_dir,
                &router,
                &on_finished,
                &on_kernel_events,
            );
            Ok(())
        }) {
            eprintln!("synra-daemon: the transport listener did not start: {error}");
        }
    }
}

// ★ Discovery runs on its own thread and the control loop only reads what it learned. `serve_one` blocks and the
// listener cannot be cloned, so a scan inside a command would hold the control socket for its whole budget — and a
// user's `status`, run to find out why things are slow, would wait for the network too.
pub(super) fn start_discovery(supervisor: &Arc<Supervisor>, runtime: &Runtime) {
    if let Some(discovery) = &runtime.discovery {
        let service = Arc::clone(discovery);
        let peers = Arc::clone(&runtime.host);
        let deadline = Arc::clone(&runtime.scan_until_ms);
        // ★ Cloned into the closure because it outlives this function — it runs for the process's lifetime, and a
        // borrowed `shared_db` would make that impossible to express.
        let remembered = Arc::clone(&runtime.db);
        let id = TaskId::new("discovery.udp");
        if let Err(error) = run_task(supervisor, &id, move |token| {
            synra_core::worker::run_recording(
                &service,
                &peers,
                &deadline,
                token,
                synra_store::sqlite::now_ms,
                // ★ What discovery heard is written down here, because before this nothing wrote `devices_seen` at all —
                // the table existed, the reader existed, and every start of the app showed the same empty list.
                move |candidates| {
                    for candidate in candidates {
                        let sighting = synra_store::Seen {
                            device_id: candidate.device_id.to_string(),
                            display_name: candidate.display_name.clone(),
                            // The announcement's platform is an enum; the column is a string, and the enum's own name is
                            // the string the device-card test compares against.
                            platform: format!(
                                "{:?}",
                                candidate
                                    .platform
                                    .unwrap_or(synra_protocol::session::PlatformKind::Desktop)
                            ),
                            seen_at_ms: candidate.last_seen_ms,
                            source: candidate.address.to_string(),
                        };
                        // Reported rather than retried: the next announcement refreshes the row anyway, and a failed write
                        // is reported once rather than on every scan of the same device.
                        let written = remembered.lock().record_seen_device(&sighting);
                        if let Err(error) = written {
                            eprintln!(
                                "synra-daemon: could not remember {}: {error}",
                                sighting.device_id
                            );
                        }
                    }
                },
            );
            Ok(())
        }) {
            eprintln!("synra-daemon: discovery did not start: {error}");
        }
    }
}

// ★ A restart used to restore every intent and then leave a `Dispatching` one exactly as it found it: the peer was
// still waiting, the board said the action was running, and the only process that could ask again did nothing until
// the 24-hour expiry. The request identifier is the receiver's idempotency key, so asking again is safe. The loop
// runs the kernel's schedule, which is the same one the window runs.
pub(super) fn start_intent_retry(supervisor: &Arc<Supervisor>, runtime: &Runtime) {
    let host = Arc::clone(&runtime.host);
    let board = Arc::clone(&runtime.board);
    let db = Arc::clone(&runtime.db);
    let local = runtime.identity.device_id;
    let id = TaskId::new("intent.retry");
    if let Err(error) = run_task(supervisor, &id, move |token| {
        crate::runtime::retry::run(
            &host,
            &board,
            &db,
            local,
            token,
            synra_core::intent::retry::RetryPolicy::default(),
        );
        Ok(())
    }) {
        eprintln!("synra-daemon: the intent retry loop did not start: {error}");
    }
}
