//! Serving until asked to stop: the daemon's run loop, its heartbeat, and its stop condition.
//!
//! # Why this is in the library and not in `main.rs`
//!
//! Because it is decision-making, not plumbing. The file that starts the process should read as one screen — read the
//! flags, run the start-up, print what it decided, hand over to this loop — and a two-hundred-line loop inside
//! `main.rs` is a loop no test can reach. In the library it is reachable: the crate's own tests can drive [`serve`] the
//! same way a user does.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;

use parking_lot::Mutex;
use synra_control::Listener;

use crate::runtime::{Runtime, now_ms};

mod control;
mod maintenance;
mod network;
mod plugins;
mod prepare;
mod services;

use control::{accept_control, drain_control};
use maintenance::{join_loops, start_loops};

/// Runs the daemon until the supervisor says to stop, and reports how it ended.
///
/// Everything the daemon owns is built here in one order the comments below explain: the claim, the database,
/// the identity, the socket, and then the loops.
pub fn serve(decision: &crate::Startup) -> ExitCode {
    let Some(plan) = decision.plan() else {
        eprintln!("synra-daemon: the start-up said it may run and produced no plan");
        return ExitCode::FAILURE;
    };

    let (db, identity) = match prepare::open_database(plan) {
        Ok(started) => started,
        Err(code) => return code,
    };
    let (host, local_peer) = network::bind_transport(plan, &identity);
    let scan_until_ms = Arc::new(AtomicI64::new(0));
    let discovery = network::bind_discovery(plan, &local_peer);

    let (paths, crashes, log) = prepare::start_diagnostics(plan, &db);
    // Keep the guard alive until serve returns so the writer flushes at shutdown.
    let log_verbosity = log.as_ref().map(|guard| guard.verbosity());
    // And the counters, from the same guard: `synra logs` reports what the writer dropped or failed to write, which is
    // the difference between "no lines" and "lines were lost".
    let log_stats = log.as_ref().map(synra_observe::logging::stats_of);
    // And a handle that can wait for the writer: `synra logs` must answer with what was just written, not with what
    // happened to be flushed already.
    let log_flush = log
        .as_ref()
        .and_then(synra_observe::logging::LogGuard::flush_handle);

    // ★ The database goes behind its lock **here**, before the plugin host is built.
    //
    // The host a plugin's calls reach reads two things from it — which capabilities the user granted, and what the
    // interface was configured with — so the handle has to exist first. It used to be wrapped much later, which is part
    // of why the host had nothing to be built from and no session was ever installed.
    let shared_db = Arc::new(Mutex::new(db));
    // The transport worker owns a handle for recording completed transfers.
    let history_db = Arc::clone(&shared_db);

    // ★ The plugin host is built **before** the runtime, and its failure ends the daemon.
    //
    // This is the one dependency that can refuse. Everything else here is data the daemon reads; an engine that will not
    // start means this host cannot run a plugin at all, and continuing would produce a daemon whose status report says
    // no plugins are loaded for a reason that has nothing to do with what the user installed.
    // ★ The gate's counters, owned here because this is what can report them.
    let metrics = Arc::new(synra_observe::metrics::RingRecorder::new());
    // ★ And the store reports every write's duration to the same recorder. Installed here, once, rather than at each call
    // site — the store's write methods are the one funnel every write goes through.
    crate::runtime::observe_db_writes(&mut shared_db.lock(), &metrics);
    let plugins = match crate::runtime::build_set(&shared_db, &metrics)
        .map_err(|error| error.to_string())
        .and_then(|set| set.into_shared().map_err(|error| error.to_string()))
    {
        Ok(set) => set,
        Err(error) => {
            eprintln!("synra-daemon: the plugin host could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    // ★ What an inbound share is routed with, built here because this is where all three exist.
    //
    // Without it the transport could receive a share and had nothing to ask: a peer's shared text was reported and
    // dropped, so the routing the design calls the kernel's most central orchestration had no inbound half.
    let router = Arc::new(crate::runtime::intent::Router::new(
        Arc::clone(&plugins),
        Arc::clone(&board),
    ));
    let revocations = plugins::read_revocations(plan);
    let plugin_loads = plugins::load_plugins(plan, &shared_db, &plugins, &crashes, &revocations);

    // ★ Wrapped before the runtime is built, because two things need it and only one of them is the runtime.
    //
    // The discovery thread writes what it hears; the control socket reads it. Neither can reach the other, so the handle
    // is shared rather than passed — and it is shared behind a lock because `rusqlite::Connection` is `Send` and not `Sync`.

    let runtime = Arc::new(Runtime {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        data_dir: std::path::PathBuf::from(&plan.data_dir),
        plugins_dir: std::path::PathBuf::from(&plan.plugins_dir),
        paths,
        listen_port: plan.listen_port,
        discovery_port: plan.discovery_port,
        started_at_ms: now_ms(),
        identity,
        host: Arc::new(Mutex::new(host)),
        discovery,
        scan_until_ms,
        db: Arc::clone(&shared_db),
        plugins,
        plugin_loads,
        // ★ The same document the load pass above consulted. `enable` runs long after start-up and must not load a
        // plugin the start-up pass would have refused.
        revocations,
        metrics: Arc::clone(&metrics),
        board: Arc::new(Mutex::new(synra_core::intent::Board::new())),
        // ★ Handed to the runtime so `synra logs --verbose` can raise what the process writes. `None` when logging is
        // not running — a daemon whose log file could not be opened still answers the command, and it must not claim to
        // have raised anything.
        verbosity: log_verbosity,
        log_stats,
        log_flush,
    });

    // ★ Put back what the last run was working on, **before** the socket is bound.
    //
    // The same reason the database is migrated first: a client that connects must find a kernel whose board is what it says
    // it is. A daemon that bound first and restored afterwards would answer the first `intent_snapshot` with "no such
    // intent" for one it was about to remember — and a peer whose answer was lost would take that as permission to raise it
    // again, which is the second run of a user's action this whole path exists to prevent.
    let restored = runtime.restore_intents();
    if restored > 0 {
        println!("restored {restored} intent(s)");
    }

    let listener = match Listener::bind(&runtime.data_dir) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("synra-daemon: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("control socket {}", listener.path().display());

    // ★ The supervisor owns the two long-lived services, and it is what a stop request goes through.
    //
    // Both used to be bare `std::thread::spawn` beside a process-wide `Arc<AtomicBool>` hand-called `beating`. Two things
    // were wrong with that and this round is about both.
    //
    // The first is that `synra_core::supervisor` — registration, cancellation tokens, restart policy, a record per task, a
    // shutdown report — was **fully implemented, fully tested, and run by nothing**: `run_task`, the one function that
    // actually runs a supervised task, had no caller outside its own tests. The daemon is where the kernel's long-lived
    // work lives, so the daemon is where that stops being true.
    //
    // The second is smaller and was a real bug waiting: the flag was named `stop` and meant "keep running", and the first
    // version of the listener read `while !stop.load(..)` — so it exited on its first check and silently refused every
    // connection. A cancellation token is one-way, so that polarity cannot be got wrong.
    let supervisor = Arc::new(synra_core::supervisor::Supervisor::new(
        synra_store::sqlite::now_ms(),
    ));
    let update_worker = crate::runtime::updates::start(&runtime, &supervisor)
        .map_err(|error| eprintln!("synra-daemon: plugin update checks did not start: {error}"))
        .ok();
    for service in ["transport.accept", "discovery.udp", "intent.retry"] {
        // Reported rather than fatal: `TaskSpec::service` is `Ordinary` criticality, so a task that will not register is a
        // capability this run does not have, not a reason to refuse to serve.
        if let Err(error) = supervisor.register(synra_core::supervisor::TaskSpec::service(service))
        {
            eprintln!("synra-daemon: {service} could not be registered: {error}");
        }
    }

    services::start_transport(&supervisor, &runtime, history_db, router);
    services::start_discovery(&supervisor, &runtime);

    // ★ The heartbeat runs on its own thread because the accept loop blocks. A refresh done from the loop would only
    // happen when a client connected — so a daemon nobody was talking to would look dead after the stale window, and the
    // next start would reclaim a directory a live daemon is serving.
    //
    // ★ And the retention sweep, which until it had a runner ran nowhere: `collect_intents` was written with the rule it
    // implements and no caller, so the table the design gives a 24-hour retention to kept everything for ever. A rule with
    // no runner is a sentence in a document.
    //
    // Both are started by one function, which is what `serve` needs: starting a supervised task is four lines of error
    // handling, and two of them in a function already at the workspace's complexity limit is what pushes it over.
    let loops = start_loops(
        &supervisor,
        &shared_db,
        &plan.lock_path(),
        &runtime.host,
        &runtime.data_dir,
    );

    services::start_intent_retry(&supervisor, &runtime);

    // ★ "Trusted" is not "bounded": a local client with a bug can open connections in a loop, and each one costs a thread
    // until the process runs out. The gate admits a fixed number and closes the rest; see `control_gate`.
    let gate = Arc::new(
        crate::control_gate::ControlGate::new(crate::control_gate::MAX_CONTROL_CONNECTIONS)
            .with_metrics(Arc::clone(&metrics)),
    );

    let mut code = ExitCode::SUCCESS;
    while !supervisor.is_shutting_down() {
        if !accept_control(&listener, &gate, &runtime) {
            code = ExitCode::FAILURE;
        }
    }

    // ★ Give the connections that are already being served a bounded chance to finish before their database and runtime
    // are dropped underneath them. The wait is bounded because a client that never closes must not make shutdown hang;
    // whatever is still open is named rather than silently cut off.
    drain_control(&gate);

    // ★ Asked through the supervisor rather than by setting a flag, so the two services stop the way they were started:
    // the token they were given is cancelled, and the stop order is the reverse of registration.
    let _ = supervisor.begin_shutdown();
    if let Some(worker) = update_worker {
        let _ = worker.join();
    }
    join_loops(loops);
    code
}
