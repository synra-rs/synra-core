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
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use synra_control::Listener;

use crate::args::{ClaimFile, refresh_claim};
use crate::runtime::{Runtime, now_ms};

/// How often the claim is refreshed.
///
/// Read from the daemon's own constant rather than written here, because the stale-after window and the interval are two
/// halves of one decision: an interval that outlived the window would make a healthy daemon look dead to the next start.
const HEARTBEAT_MS: u64 = crate::HEARTBEAT_INTERVAL_MS;

/// How long a finished intent is kept, in milliseconds.
///
/// Twenty-four hours, from the design's storage table (`17 §6`: "finished, then cleaned after 24 hours"). Long enough that
/// a user can still read what happened yesterday, short enough that a device raising intents for months does not carry all
/// of them.
const INTENT_RETENTION_MS: i64 = 24 * 60 * 60 * 1_000;

/// How often the retention sweep runs.
///
/// An hour, as the design's `GcTask` says.
const GC_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long a recorded call is kept, in milliseconds.
///
/// Seven days, from the design's storage table (`17 §6`). Longer than a log's window because the record carries no content:
/// a capability names a destination, never what was sent to it, which is the whole reason this is safe to keep.
const AUDIT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// How long the first sweep waits after start-up.
///
/// ★ Not zero, and the reason is the design's own requirement that GC runs when the daemon is *idle*.
///
/// A daemon that has just started is migrating the database, reading plugin manifests and claiming the directory — and a
/// retention sweep beside them would be IO nobody asked for at the one moment the kernel is already busy. A minute is long
/// enough for start-up to finish and short enough that a daemon restarted often still collects.
const GC_FIRST_DELAY: Duration = Duration::from_secs(60);

/// Runs the retention sweep on a schedule, for as long as the daemon serves.
///
/// # Why this is a thread of its own
///
/// For the reason the heartbeat is: the accept loop blocks on a client, so a sweep done from there would happen only when
/// somebody connected — and a daemon nobody talks to would never collect anything. It also must not hold the `Runtime`,
/// which the accept loop owns on its stack, so it is given the database handle and the two durations it needs.
///
/// # Why the durations are parameters and the constants are the caller's
///
/// Because a test that waited an hour to see whether the sweep ran would not be a test. The schedule is decided where the
/// daemon is built and passed in, so the same loop can be driven with milliseconds.
/// Finishes a previous uninstall's leftovers, before any plugin is loaded.
///
/// # Why this is a function
///
/// Because it is three error branches and a report, and `serve` has a complexity budget that a reader benefits from: the
/// start-up reads as "open, restore, sweep, load, serve" when each step is named.
fn sweep_plugin_leftovers(db: &synra_store::SynraDb, paths: &synra_store::Paths) {
    let Ok(rows) = db.plugins() else {
        // A database that cannot list its plugins is a fault the next read will report; the sweep is not where a start-up
        // should fail.
        return;
    };
    let installed: Vec<String> = rows.into_iter().map(|row| row.plugin_id).collect();
    match synra_store::PluginFiles::new(paths.clone()).sweep_orphans(&installed) {
        Ok(sweep) if !sweep.removed.is_empty() => println!(
            "removed {} leftover plugin director{} ({} bytes)",
            sweep.removed.len(),
            if sweep.removed.len() == 1 { "y" } else { "ies" },
            sweep.bytes_freed
        ),
        Ok(sweep) => {
            for path in sweep.leftovers {
                eprintln!("synra-daemon: could not remove {}", path.display());
            }
        }
        Err(error) => eprintln!("synra-daemon: the plugin directory could not be swept: {error}"),
    }
}

/// Starts the two loops the daemon runs for its whole life, and returns what to join on shutdown.
///
/// """ + S + """ Why `run_task` rather than `std::thread::spawn`.
///
/// Both loops were bare spawns, and a bare spawn is a task whose death is indistinguishable from its silence: a panic
/// unwinds, the thread stops, the daemon serves on, and nothing records anything. `run_task` owns the registration, the
/// cancellation token, the restart decision and the record — **and it already existed and was already used** for the
/// transport listener and for discovery. The fix was to use it, not to write a second one beside it.
///
/// A task that will not start leaves nothing to join: the daemon serves without it rather than refusing to run, which is the
/// choice the two services make as well.
/// One supervised loop's handle, when it started.
type LoopHandle = Option<std::thread::JoinHandle<()>>;

fn start_loops(
    supervisor: &Arc<synra_core::supervisor::Supervisor>,
    db: &Arc<Mutex<synra_store::SynraDb>>,
    lock_path: &std::path::Path,
    host: &Arc<Mutex<synra_core::Host>>,
    data_dir: &std::path::Path,
) -> (LoopHandle, LoopHandle, LoopHandle) {
    use synra_core::supervisor::{TaskId, run_task};

    // ★ Answers that could not be delivered when they were produced are retried here, on a timer, because the producer is
    // a connection thread and a connection thread must not wait for a device that may be gone. Thirty seconds is short
    // enough that a peer's restart is noticed and long enough that a permanently gone peer costs two dials a minute.
    let retrier = {
        let host = Arc::clone(host);
        let data_dir = data_dir.to_path_buf();
        let id = TaskId::new("late.retry");
        match run_task(supervisor, &id, move |token| {
            late_retry_loop(token, &host, &data_dir);
            Ok(())
        }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                eprintln!("synra-daemon: the late-answer retrier did not start: {error}");
                None
            }
        }
    };

    let heartbeat = {
        // One clone for the task's body and the caller's own reference for `run_task`: the body may not hold the same
        // `Arc` the caller is borrowing in the same expression.
        let inner = Arc::clone(supervisor);
        let lock_path = lock_path.to_path_buf();
        let id = TaskId::new("heartbeat.tick");
        match run_task(supervisor, &id, move |_token| {
            heartbeat_loop(&inner, &lock_path);
            Ok(())
        }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                eprintln!("synra-daemon: the heartbeat did not start: {error}");
                None
            }
        }
    };

    let collector = {
        let inner = Arc::clone(supervisor);
        let db = Arc::clone(db);
        let id = TaskId::new("gc.collect");
        match run_task(supervisor, &id, move |_token| {
            collect_loop(&db, &inner, gc_task());
            Ok(())
        }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                eprintln!("synra-daemon: the retention sweep did not start: {error}");
                None
            }
        }
    };

    (heartbeat, collector, retrier)
}

/// Joins every supervised loop that started.
///
/// # Why a tuple rather than three calls in `serve`
///
/// Because `serve` has a complexity budget, and three "if it started, join it" branches beside the shutdown report is the
/// kind of code that pushes it over. The loops are a set: they stop together and are joined together.
fn join_loops(loops: (LoopHandle, LoopHandle, LoopHandle)) {
    for handle in [loops.0, loops.1, loops.2].into_iter().flatten() {
        let _ = handle.join();
    }
}

/// Retries queued late answers until the supervisor asks the daemon to stop.
fn late_retry_loop(
    token: &synra_core::supervisor::Cancellation,
    host: &Arc<Mutex<synra_core::Host>>,
    data_dir: &std::path::Path,
) {
    loop {
        let summary = synra_core::listener::retry_late(host, data_dir);
        if summary.delivered > 0 || summary.dropped > 0 {
            tracing::info!(
                delivered = summary.delivered,
                failed = summary.failed,
                dropped = summary.dropped,
                "late answers were retried"
            );
        }
        if token.wait(Duration::from_secs(30)) {
            break;
        }
    }
}

/// The schedule this daemon collects on: the design's `GcTask`, as a value.
const fn gc_task() -> crate::runtime::intents::GcTask {
    crate::runtime::intents::GcTask {
        retention: crate::runtime::intents::Retention {
            intents_ms: INTENT_RETENTION_MS,
            audit_ms: AUDIT_RETENTION_MS,
        },
        first_delay: GC_FIRST_DELAY,
        every: GC_INTERVAL,
    }
}

/// The same schedule at a speed a test can wait for, which is the reason the schedule is a value.
#[cfg(test)]
const fn fast_gc_task() -> crate::runtime::intents::GcTask {
    crate::runtime::intents::GcTask {
        retention: crate::runtime::intents::Retention {
            intents_ms: INTENT_RETENTION_MS,
            audit_ms: AUDIT_RETENTION_MS,
        },
        first_delay: Duration::from_millis(1),
        every: Duration::from_millis(5),
    }
}

fn collect_loop(
    db: &Arc<Mutex<synra_store::SynraDb>>,
    supervisor: &Arc<synra_core::supervisor::Supervisor>,
    task: crate::runtime::intents::GcTask,
) {
    let first_delay = task.first_delay;
    let every = task.every;
    // ★ The first wait is interruptible in slices, so a daemon asked to stop during its first minute does not take the
    // whole minute to notice. The heartbeat loop has the same shape for the same reason.
    if !sleep_until_shutdown(supervisor, first_delay) {
        return;
    }

    while !supervisor.is_shutting_down() {
        let collected = crate::runtime::intents::sweep(&db.lock(), task.retention);
        // ★ A sweep that could not finish says so, on the error stream and by name.
        //
        // It used to say nothing at all: every count was zero, and the failure was a log line written inside the store. A
        // database that cannot be collected from is the one thing about a sweep worth interrupting somebody for, and it was
        // the one thing this loop was silent about.
        for failure in &collected.failures {
            eprintln!("the retention sweep could not finish: {failure}");
        }
        if collected.intents > 0 {
            println!("collected {} finished intent(s)", collected.intents);
        }
        if collected.devices > 0 {
            println!("forgot {} device(s) heard from long ago", collected.devices);
        }
        if collected.audit > 0 {
            println!("forgot {} recorded call(s)", collected.audit);
        }
        // ★ One line for the sweep as a whole, and the reason `removed` is a method rather than a test helper: an
        // operator reading the log wants to know whether collection is happening at all, and three separate numbers that are
        // all zero look the same as a sweep that never ran.
        let removed = collected.removed();
        if removed > 0 {
            println!("the retention sweep removed {removed} row(s)");
        }
        if !sleep_until_shutdown(supervisor, every) {
            return;
        }
    }
}

/// Waits, unless the daemon is asked to stop first.
///
/// # Returns
///
/// `false` when the wait was cut short by a shutdown, so the caller can stop rather than carry on for another interval.
fn sleep_until_shutdown(
    supervisor: &Arc<synra_core::supervisor::Supervisor>,
    total: Duration,
) -> bool {
    const SLICE: Duration = Duration::from_millis(250);
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if supervisor.is_shutting_down() {
            return false;
        }
        std::thread::sleep(SLICE.min(deadline.saturating_duration_since(Instant::now())));
    }
    !supervisor.is_shutting_down()
}

/// Waits for the control connections to finish, and names the ones that did not.
fn drain_control(gate: &Arc<crate::control_gate::ControlGate>) {
    if !gate.wait_for_idle(Duration::from_secs(5)) {
        tracing::warn!(
            open = gate.active(),
            "control connections are still open at shutdown and are being abandoned"
        );
    }
}

/// Accepts and serves one control connection; `false` means the listener itself failed.
///
/// # Why this is a function
///
/// Because the loop is three decisions — admit, spawn, or report an accept failure — and `serve` has a complexity budget.
/// Named, the loop reads as "keep accepting until asked to stop", which is what it means.
fn accept_control(
    listener: &Listener,
    gate: &Arc<crate::control_gate::ControlGate>,
    runtime: &Arc<Runtime>,
) -> bool {
    // ★ One thread per connection. The loop used to call `serve_one`, so one client at a time — which made a command that
    // waits (a remote action's answer, a pairing prompt) an outage for every other command: `status` queued behind an
    // `intent decide` for as long as the wait lasted. The socket is local and each client is a process the user started,
    // so a thread per connection is the trust boundary the one-at-a-time loop had, without the queue.
    match listener.accept() {
        Ok(stream) => {
            let Some(permit) = gate.try_enter() else {
                // ★ Closing rather than answering: a refusal needs a request to answer, and a client over the limit is not
                // one whose request is worth reading. The caller sees a transport error naming the closed connection,
                // which is the truth.
                tracing::warn!(
                    open = gate.active(),
                    "refusing a control connection: the gate is full"
                );
                drop(stream);
                return true;
            };
            let runtime = Arc::clone(runtime);
            std::thread::spawn(move || {
                // The permit is held for the connection's lifetime, so the count cannot leak on an early return.
                let _permit = permit;
                // ★ A panic inside one connection must not be invisible: without this the thread unwinds, the socket
                // closes, and `synra logs` says nothing about why. The payload is not printed — it may contain request
                // data — but the fact is recorded, and the daemon keeps serving.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    synra_control::serve_stream(stream, &*runtime)
                }));
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::error!(%error, "a control connection failed"),
                    Err(_) => tracing::error!("a control connection panicked"),
                }
            });
            true
        }
        Err(error) => {
            // One client's failure is not the daemon's. A transport error is reported and the loop continues, because a
            // daemon that exited on a malformed connection would be one any local process could stop.
            tracing::error!(%error, "the control listener could not accept a connection");
            // ★ It sleeps: acceptance is separate from serving now, so a permanently failing listener would spin.
            std::thread::sleep(Duration::from_millis(10));
            false
        }
    }
}

/// Runs the daemon until the supervisor says to stop, and reports how it ended.
///
/// Everything the daemon owns is built here in one order the comments below explain: the claim, the database,
/// the identity, the socket, and then the loops.
pub fn serve(decision: &crate::Startup) -> ExitCode {
    let Some(plan) = decision.plan() else {
        eprintln!("synra-daemon: the start-up said it may run and produced no plan");
        return ExitCode::FAILURE;
    };

    // ★ The database is opened and migrated **before** the socket is bound, so a client cannot connect to a kernel whose
    // storage is not ready. A daemon that bound first would answer the first command with a statement error about a
    // missing table — and the user would read that as a corrupt database rather than as a start that had not finished.
    let db_path = std::path::PathBuf::from(&plan.db_path);
    let mut db = match synra_store::SynraDb::open(&db_path) {
        Ok(db) => db,
        Err(error) => {
            eprintln!("synra-daemon: {error}");
            return ExitCode::FAILURE;
        }
    };
    match db.migrate() {
        Ok(applied) => {
            if applied > 0 {
                println!("applied {applied} migration(s)");
            }
        }
        Err(error) => {
            eprintln!("synra-daemon: {error}");
            return ExitCode::FAILURE;
        }
    }

    // ★ The identity is read (or created) here, once — after the claim and before the socket. Reading it per request is
    // how a device ends up with a second identity, because the read creates one when the row is absent.
    let identity = match synra_core::Identity::load(&db, std::env::consts::OS, synra_store::sqlite::now_ms()) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("synra-daemon: {error}");
            return ExitCode::FAILURE;
        }
    };
    // ★ Read out before the identity is moved into the host, because the pairing desk needs it: the verification code a
    // user compares is derived from this device's identifier, so a desk built with a stale or defaulted one would show a
    // code the other screen does not match — which reads to a user as an attacker rather than as a bug.
    let local_id = identity.device_id;
    println!("device {} ({})", identity.device_id, identity.display_name);

    // ★ The peer registry is built after the transport port is known, because the announcement carries the port a peer
    // would *connect* to — and an announcement that named a port nothing is listening on would be a device that appears
    // in every list and cannot be reached.
    let local_peer = synra_core::LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        synra_core::platform_of_os(std::env::consts::OS),
        env!("CARGO_PKG_VERSION"),
    );
    let host = synra_core::Host::new(identity.clone(), local_peer.clone());

    // ★ The transport listener is what makes this device *reachable*. `dial` can only make outbound links, so without
    // this a device could send and never receive — and the announcement above would name a port nothing is listening on.
    // Bound here rather than in the library so the port is the one the announcement carries.
    let (host, transport) = {
        let mut host = host;
        match crate::transport::bind(&mut host, plan.listen_port) {
            Ok(address) => {
                println!("transport on {address}");
                (host, Ok(address))
            }
            Err(error) => {
                // Reported rather than fatal, for the same reason discovery is: a device nobody can send to is worse than
                // one that cannot start only in that it is quieter.
                eprintln!("synra-daemon: nothing can connect to this device: {error}");
                (host, Err(error))
            }
        }
    };
    let _ = transport;

    // ★ Discovery is bound *before* the control socket, and a failure is reported rather than fatal. A machine with no
    // network, a firewall, and a sandbox all produce the same thing — and a kernel that could not start without discovery
    // would be one that cannot run with its wireless switched off. What it means is that this device cannot be *found*;
    // every other command still works.
    let scan_until_ms = Arc::new(AtomicI64::new(0));
    let discovery = match synra_core::DiscoveryService::bind_on(
        local_peer.announcement(plan.listen_port),
        plan.discovery_port,
        synra_core::QUERY_INTERVAL,
    ) {
        Ok(service) => {
            match service.responder_address() {
                Ok(address) => println!("discovery on {address}"),
                Err(error) => eprintln!("synra-daemon: {error}"),
            }
            Some(Arc::new(Mutex::new(service)))
        }
        Err(error) => {
            // Not fatal, and said out loud: a user whose device cannot be found needs to know why, and "discovery is not
            // running" is the answer to that rather than a line in a log nobody reads.
            eprintln!("synra-daemon: discovery is not running: {error}");
            None
        }
    };

    // ★ The pairing desk, built before the runtime that holds it and shared with the transport threads. A prompt is
    // raised by the connection a peer dialled and answered by a user on no connection at all, so the structure that
    // holds it has to outlive the connection that made it.
    let pairing = Arc::new(synra_core::pairing::PairingDesk::new(
        local_id,
        synra_protocol::session::SessionTimeouts::default().pairing,
    ));
    // ★ The crash store, and the panic hook that fills it, are set up before anything that can crash.
    //
    // The order matters and is the whole reason this is up here rather than beside the safe-mode check below: a hook
    // installed after the plugin host is built does not record a failure while building it. The log directory comes from
    // `Paths` rather than being joined here, because `Paths` is the one place that decides where things live.
    let paths = synra_store::Paths::new(
        std::path::PathBuf::from(&plan.data_dir),
        std::path::PathBuf::from(&plan.data_dir).join("cache"),
    );
    let log_dir = paths.log_dir().to_path_buf();
    let crashes = synra_observe::crash::CrashStore::new(&log_dir);
    // The daemon's own version, not the observe layer's: the report is about the binary that crashed.
    synra_observe::crash::install_panic_hook(crashes.clone(), env!("CARGO_PKG_VERSION"));

    // ★ A previous run's uninstall may have left an artifact directory behind: a loaded engine held its wasm file open,
    // the row was already gone, and the leftover was reported to the user. This is the moment to finish it — the process
    // that held the file is gone, and no plugin has been loaded yet. The sandbox is **not** swept: data kept on purpose
    // belongs to the user.
    sweep_plugin_leftovers(&db, &paths);

    // ★ And the log itself. Nothing wrote this file before: `synra logs` read a path no code created, so it always
    // answered "no lines", and the CLI's `--follow` and `--trace` had nothing to filter. The subscriber is installed
    // here — early, so everything that follows is recorded, including a failure to start the plugin host.
    //
    // A failure to open the log is reported and then ignored rather than ending the daemon: a host that cannot write a
    // diagnostic file is still a host that can move a file between two machines, and refusing to start over it would
    // trade the user's actual work for its record.
    //
    // ★ `Info`, which is `LogLevel::is_persisted`'s own answer to what belongs on disk, and the level the process
    // **starts** at rather than the level it is stuck with. A raise is what `synra logs --verbose` does now: the guard's
    // `verbosity()` goes into the runtime, and a request for more raises what is written for a bounded window, so a
    // forgotten flag does not leave a debug log running for a week. Before that, `with_max_level` fixed the level for
    // the life of the process and `--verbose` filtered DEBUG out of a file that could never contain any.
    //
    // The guard is held for the life of `serve`, which is what keeps the file open and flushes it on shutdown.
    let _log = match synra_observe::logging::init(
        &synra_observe::logging::LogConfig::in_directory(&log_dir)
            .with_level(synra_observe::logging::LogLevel::Info),
    ) {
        Ok(guard) => Some(guard),
        Err(error) => {
            eprintln!("synra-daemon: logging is not running: {error}");
            None
        }
    };
    // Taken before the guard moves into `_log`, because the runtime needs it and the guard is what keeps the file open.
    let log_verbosity = _log.as_ref().map(|guard| guard.verbosity());
    // And the counters, from the same guard: `synra logs` reports what the writer dropped or failed to write, which is
    // the difference between "no lines" and "lines were lost".
    let log_stats = _log
        .as_ref()
        .map(synra_observe::logging::stats_of);
    // And a handle that can wait for the writer: `synra logs` must answer with what was just written, not with what
    // happened to be flushed already.
    let log_flush = _log
        .as_ref()
        .and_then(synra_observe::logging::LogGuard::flush_handle);

    // ★ The database goes behind its lock **here**, before the plugin host is built.
    //
    // The host a plugin's calls reach reads two things from it — which capabilities the user granted, and what the
    // interface was configured with — so the handle has to exist first. It used to be wrapped much later, which is part
    // of why the host had nothing to be built from and no session was ever installed.
    let shared_db = Arc::new(Mutex::new(db));
    // ★ A second handle, because the first one does not survive to where the history is written: `shared_db` is
    // cloned into `remembered` further down and that holder outlives this function's own use of it. Two `Arc`s to
    // one database is the ordinary way to say "two owners".
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
    let plugins = match crate::runtime::build_set(&shared_db, &metrics) {
        Ok(set) => Arc::new(Mutex::new(set)),
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
    // ★ The revocation list, and where it comes from.
    //
    // It ships **with the application**, so this reads a file beside the data directory rather than fetching one: the offline
    // case is the built-in case, and a list that could only be obtained over the network would leave an offline machine with
    // no revocation data at all — which is the case a revocation list exists for.
    //
    // A file that is missing is an empty list, and that is logged rather than silent: "nothing is revoked" and "there is no
    // list" are different facts, and a daemon that could not tell the user which it was in would be unable to explain why a
    // plugin it was told to disable is still running. It is read once and kept on the runtime, because `enable` runs long
    // after start-up and must consult the same document the load pass did.
    let revocations = {
        let path = std::path::Path::new(&plan.data_dir).join("revocations.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => match synra_plugin_api::revocation::RevocationList::parse(&text) {
                Ok(list) => {
                    eprintln!("synra-daemon: {} revocation entries read from {}", list.len(), path.display());
                    list
                }
                Err(error) => {
                    eprintln!(
                        "synra-daemon: {} could not be read as a revocation list ({error}); no plugin is disabled on its account",
                        path.display()
                    );
                    synra_plugin_api::revocation::RevocationList::empty()
                }
            },
            Err(_) => synra_plugin_api::revocation::RevocationList::empty(),
        }
    };
    let plugin_loads = {
        // ★ Before loading anything: record the plugin directories the database does not know about.
        //
        // This is the step that was missing entirely. `insert_plugin` had no production caller, so `db.plugins()` was
        // always empty, so `load_installed` below always loaded nothing — whatever was on disk. The daemon had no
        // plugins and no way to get one.
        //
        // It records and does not trust: a directory that exists is a plugin that is *installed*, which is a different
        // statement from one the user has approved. See `record_discovered_plugins`.
        for discovered in crate::runtime::record_discovered_plugins(
            &shared_db.lock(),
            std::path::Path::new(&plan.plugins_dir),
            // The runtime clock is `u64` and the database stamps `i64`; saturating rather than `as`, the same direction
            // as the crash-report stamp below — a clock problem should let the daemon run, not refuse to start.
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
        ) {
            match discovered.problem {
                // Printed rather than skipped: a directory that looks like a plugin and is not one is the difference
                // between "nothing is installed" and "the installation is half-copied", and only one needs acting on.
                Some(problem) => {
                    eprintln!("synra-daemon: {} was not recorded: {problem}", discovered.plugin_id);
                }
                None => println!("synra-daemon: {} is installed and switched off", discovered.plugin_id),
            }
        }

        // ★ The guard is scoped to the load and nothing else. It is held while third-party artifacts compile, which is
        // the point of the lock — but not while the refusals are printed, because printing is not something another
        // thread should be waiting behind.
        //
        // ★ Safe mode is decided here, before anything is loaded, and it is the only thing that can decide it. The
        // verdict reads the crash reports the previous runs left behind; a plugin that has crashed this location three
        // times in a row is not started a fourth time, so the settings screen the user needs to switch it off stays
        // reachable.
        //
        // `now_ms()` is `u64` because the runtime's clock is, and a crash report is stamped `i64`. The conversion is
        // saturating rather than `as`: a clock far enough past 2262 to overflow should read as "the latest possible
        // instant", which makes every report look old and lets the daemon run — the direction that fails open on a clock
        // problem rather than refusing to start.
        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        let verdict = crashes.verdict(now);
        // ★ The environment is read **before** the store lock is taken. `KernelHost::locale` reads a setting, which
        // needs the store; reading it while the loader holds the store was a same-thread deadlock.
        let activation = {
            let set = plugins.lock();
            synra_core::plugin::activation_config(set.host().as_ref())
        };
        let summary = {
            let mut set = plugins.lock();
            crate::runtime::load_installed_with_config(
                &mut set,
                &shared_db.lock(),
                std::path::Path::new(&plan.plugins_dir),
                &verdict,
                &revocations,
                &activation,
            )
        };
        // ★ Printed, because a plugin that failed to load is invisible otherwise and a silent skip is how a broken
        // plugin becomes a support question months later.
        for refused in &summary.refused {
            eprintln!("synra-daemon: {} was not loaded: {}", refused.plugin_id, refused.reason);
        }
        // ★ And safe mode is printed for the same reason, louder: the user is looking at a daemon with no plugins and
        // needs to know it was a decision rather than a failed install.
        if let Some(why) = &summary.safe_mode {
            eprintln!("synra-daemon: plugins are not being started. {why}");
        }
        Arc::new(Mutex::new(summary))
    };

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
        discovery: discovery.clone(),
        scan_until_ms: Arc::clone(&scan_until_ms),
        db: Arc::clone(&shared_db),
        pairing,
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
    let supervisor = Arc::new(synra_core::supervisor::Supervisor::new(synra_store::sqlite::now_ms()));
    for service in ["transport.accept", "discovery.udp", "intent.retry"] {
        // Reported rather than fatal: `TaskSpec::service` is `Ordinary` criticality, so a task that will not register is a
        // capability this run does not have, not a reason to refuse to serve.
        if let Err(error) = supervisor.register(synra_core::supervisor::TaskSpec::service(service)) {
            eprintln!("synra-daemon: {service} could not be registered: {error}");
        }
    }

    // ★ The transport listener runs on its own thread for the same reason discovery does: taking a connection is cheap but
    // a handshake is not. Each accepted transport connection is handed to its own thread, so a peer that is slow to say
    // `Hello` delays nothing — and since control connections are threaded too, neither listener can queue the other.
    if runtime.host.lock().listen_nonblocking().is_ok() {
        let peers = Arc::clone(&runtime.host);
        let data_dir = runtime.data_dir.clone();
        // The runtime's own desk, not a second one: a prompt raised by the transport must be the prompt a control command
        // answers, and two desks would mean a user answering a request the waiting connection never hears about.
        let desk = Arc::clone(&runtime.pairing);
        // ★ Cloned before the task closure: the closure owns what it captures, and the listener below still needs the
        // runtime. A `runtime.plugins` moved into the closure would make `serve_one(&runtime)` a use after move.
        let receive_plugins = Arc::clone(&runtime.plugins);
        let receive_plugins_dir = runtime.data_dir.join("plugins");
        let receive_board = Arc::clone(&runtime.board);
        let local_device = runtime.identity.device_id;
        let id = synra_core::supervisor::TaskId::new("transport.accept");
        // The token is the loop's stop condition, so cancelling the task *is* stopping the listener — there is no second
        // flag for the two to disagree about.
        if let Err(error) = synra_core::supervisor::run_task(&supervisor, &id, move |token| {
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
                    }
                    else {
                        synra_core::plugin_sync::record_received(&db, transfer)
                    }
                })
            };
    // ★ A kernel event is run here, on the connection that asked, because the answer is a reply. The listener owns the
    // link and this host owns the plugins and the board; the callback is the seam between them — and without it an
    // `INTENT_INVOKE` arrived, was counted and was dropped: the sender waited for an outcome that no side produced.
    let on_kernel_events: Arc<synra_core::listener::KernelEventCallback> = {
        let plugins = Arc::clone(&receive_plugins);
        let board = Arc::clone(&receive_board);
        let local = local_device;
        Arc::new(move |envelope: &synra_protocol::envelope::Envelope| {
            let now = synra_store::sqlite::now_ms();
            crate::runtime::intent::handle_event(&plugins, &board, local, envelope, now)
        })
    };
    synra_core::listener::serve(
        &peers,
        token,
        &data_dir,
        &desk,
        &router,
        &on_finished,
        &on_kernel_events,
    );
            Ok(())
        }) {
            eprintln!("synra-daemon: the transport listener did not start: {error}");
        }
    }

    // ★ Discovery runs on its own thread and the control loop only reads what it learned. `serve_one` blocks and the
    // listener cannot be cloned, so a scan inside a command would hold the control socket for its whole budget — and a
    // user's `status`, run to find out why things are slow, would wait for the network too.
    if let Some(discovery) = &discovery {
        let service = Arc::clone(discovery);
        let peers = Arc::clone(&runtime.host);
        let deadline = Arc::clone(&scan_until_ms);
        // ★ Cloned into the closure because it outlives this function — it runs for the process's lifetime, and a
        // borrowed `shared_db` would make that impossible to express.
        let remembered = Arc::clone(&shared_db);
        let id = synra_core::supervisor::TaskId::new("discovery.udp");
        if let Err(error) = synra_core::supervisor::run_task(&supervisor, &id, move |token| {
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
                            platform: format!("{:?}", candidate.platform.unwrap_or(synra_protocol::session::PlatformKind::Desktop)),
                            seen_at_ms: candidate.last_seen_ms,
                            source: candidate.address.to_string(),
                        };
                        // Reported rather than retried: the next announcement refreshes the row anyway, and a failed write
                        // is reported once rather than on every scan of the same device.
                        let written = remembered.lock().record_seen_device(&sighting);
                        if let Err(error) = written {
                            eprintln!("synra-daemon: could not remember {}: {error}", sighting.device_id);
                        }
                    }
                },
            );
            Ok(())
        }) {
            eprintln!("synra-daemon: discovery did not start: {error}");
        }
    }

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

    // ★ A restart used to restore every intent and then leave a `Dispatching` one exactly as it found it: the peer was
    // still waiting, the board said the action was running, and the only process that could ask again did nothing until
    // the 24-hour expiry. The request identifier is the receiver's idempotency key, so asking again is safe. This is one
    // pass, not the window's backoff loop — the schedule belongs to the host that shows it.
    {
        let host = Arc::clone(&runtime.host);
        let board = Arc::clone(&runtime.board);
        let db = Arc::clone(&runtime.db);
        let local = runtime.identity.device_id;
        let id = synra_core::supervisor::TaskId::new("intent.retry");
        if let Err(error) = synra_core::supervisor::run_task(&supervisor, &id, move |_token| {
            let report = crate::runtime::retry::resend_outstanding(&host, &board, &db, local);
            if report.attempted > 0 {
                eprintln!(
                    "synra-daemon: re-sent {} dispatch(es): {} answered, {} unanswered, {} failed",
                    report.attempted, report.answered, report.unanswered, report.failed
                );
            }
            Ok(())
        }) {
            eprintln!("synra-daemon: the intent resend did not start: {error}");
        }
    }

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
    join_loops(loops);
    code
}


/// Refreshes the claim on an interval until asked to stop.
///
/// # ★ Why this asks the supervisor to stop rather than setting a flag
///
/// Because there is one shutdown path now. The loop used to clear a process-wide `AtomicBool` that four other places read,
/// which meant "the claim is gone" and "the user pressed Ctrl-C" and "a task failed" all arrived as the same unlabelled
/// event — and the transport loop had already been written with the polarity backwards once, which is what an untyped
/// boolean shared by five readers invites.
///
/// [`Supervisor::begin_shutdown`] is that one path: it cancels every task's token, and the two services stop because the
/// token they were given is cancelled, not because somebody remembered to look at a flag.
///
/// # Why the claim is re-read rather than held
///
/// The file is the source of truth, and a copy held in memory would go stale the moment anything else touched it — which
/// is exactly the condition this loop exists to notice. Re-reading costs one small file per interval and makes "does
/// this process still own the directory" a question about the directory rather than about a copy of it.
fn heartbeat_loop(supervisor: &Arc<synra_core::supervisor::Supervisor>, lock_path: &std::path::Path) {
    while !supervisor.is_shutting_down() {
        std::thread::sleep(Duration::from_millis(HEARTBEAT_MS));

        let current = match ClaimFile::read(lock_path) {
            Ok(ClaimFile::Found(lock)) => lock,
            // No claim to refresh. Either the start-up wrote none — a daemon that never claimed the directory — or
            // another process removed it. Neither is a reason to stop serving: what a *client* needs is the socket, and
            // what the next *start* needs is the claim it will find missing and treat as a crash.
            Ok(ClaimFile::Absent) => continue,
            Err(error) => {
                eprintln!("synra-daemon: the claim could not be read, stopping: {error}");
                let _ = supervisor.begin_shutdown();
                return;
            }
        };

        // ★ Only this process's own claim is refreshed. A claim naming another process means the directory has been
        // reclaimed — another daemon is serving it — and continuing would be two daemons over one database, which is a
        // correctness problem rather than a performance one.
        if current.owner.pid != std::process::id() {
            eprintln!(
                "synra-daemon: the claim now names process {}, stopping",
                current.owner.pid
            );
            let _ = supervisor.begin_shutdown();
            return;
        }

        if let Err(error) = refresh_claim(lock_path, &current, now_ms()) {
            eprintln!("synra-daemon: the claim could not be refreshed, stopping: {error}");
            let _ = supervisor.begin_shutdown();
            return;
        }
    }
}
#[cfg(test)]
mod tests {

    use std::sync::Arc;
    use std::time::Duration;

    use parking_lot::Mutex;

    use super::{collect_loop, sleep_until_shutdown};

    /// A migrated database, and a supervisor that is not shutting down.
    fn world() -> (Arc<Mutex<synra_store::SynraDb>>, Arc<synra_core::supervisor::Supervisor>) {
        let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        (
            Arc::new(Mutex::new(db)),
            Arc::new(synra_core::supervisor::Supervisor::new(1_000)),
        )
    }

    fn stored(id: &str, state: &str, at_ms: i64) -> synra_store::records::IntentRecord {
        synra_store::records::IntentRecord {
            intent_id: id.to_owned(),
            state: state.to_owned(),
            created_ms: at_ms,
            updated_ms: at_ms,
            origin_device: None,
            request_id: None,
            document: "{}".to_owned(),
        }
    }

    #[test]
    fn the_sweep_runs_on_its_schedule() {
        // ★ The schedule is the whole of what this function is, so it is what the test drives — with milliseconds rather
        // than the hour the daemon uses. A loop that never ran would leave the table growing for ever, and nothing else in
        // the daemon would notice.
        let (db, supervisor) = world();
        // ★ The epoch, which is older than any retention window. The first version of this used a large *positive* number
        // hoping it read as "long ago" — it is 2.1e12, which is **after** now, so the intent was in the future and the
        // sweep was right to keep it.
        db.lock().save_intent(&stored("finished", "succeeded", 0)).expect("stored");

        let running = {
            let db = Arc::clone(&db);
            let supervisor = Arc::clone(&supervisor);
            std::thread::spawn(move || {
                collect_loop(&db, &supervisor, super::fast_gc_task());
            })
        };

        // Give it long enough for the first delay and at least one interval.
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(db.lock().intent_count().expect("counted"), 0, "the old one went");

        let _ = supervisor.begin_shutdown();
        assert!(running.join().is_ok(), "and the loop returned");
    }

    #[test]
    fn a_daemon_asked_to_stop_does_not_wait_out_its_schedule() {
        // ★ Why the first wait is sliced. The daemon's first sweep is a minute away, and a stop request during that minute
        // must not take the whole minute to be noticed — the shutdown report would be missing a task that was still asleep.
        let (_, supervisor) = world();
        let shutdown = {
            let supervisor = Arc::clone(&supervisor);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let _ = supervisor.begin_shutdown();
            })
        };

        let started = std::time::Instant::now();
        let waited = sleep_until_shutdown(&supervisor, Duration::from_secs(30));
        let elapsed = started.elapsed();

        assert!(!waited, "the wait was cut short");
        assert!(elapsed < Duration::from_secs(5), "and it did not wait out the thirty seconds: {elapsed:?}");
        assert!(shutdown.join().is_ok());
    }

    #[test]
    fn the_schedule_forgets_devices_beyond_the_ceiling_too() {
        // ★ The other half of the sweep, and the one table in the design's GC section that genuinely fills up: the discovery
        // thread writes it, and a kernel on a shared network hears a new device every few minutes.
        let (db, supervisor) = world();
        for index in 0..(crate::runtime::intents::SEEN_DEVICE_CEILING + 3) {
            let sighting = synra_store::Seen {
                device_id: format!("{index:08}-0000-4000-8000-000000000000"),
                display_name: format!("device {index}"),
                platform: "linux".to_owned(),
                seen_at_ms: 1_000 + i64::try_from(index).unwrap_or(0),
                source: "broadcast".to_owned(),
            };
            db.lock().record_seen_device(&sighting).expect("heard");
        }
        assert_eq!(db.lock().seen_devices().expect("listed").len(), 503);

        let running = {
            let db = Arc::clone(&db);
            let supervisor = Arc::clone(&supervisor);
            std::thread::spawn(move || {
                collect_loop(&db, &supervisor, super::fast_gc_task());
            })
        };

        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            db.lock().seen_devices().expect("listed").len(),
            crate::runtime::intents::SEEN_DEVICE_CEILING,
            "the ceiling held"
        );

        let _ = supervisor.begin_shutdown();
        assert!(running.join().is_ok());
    }

    #[test]
    fn a_sweep_with_nothing_to_collect_removes_nothing() {
        // The ordinary case, and the one that runs every hour: a daemon whose intents are all recent logs nothing and
        // changes nothing.
        let (db, supervisor) = world();
        // `now_ms` is already an `i64`, which the first version of this did not notice.
        let recent = synra_store::sqlite::now_ms();
        db.lock().save_intent(&stored("recent", "succeeded", recent)).expect("stored");

        let running = {
            let db = Arc::clone(&db);
            let supervisor = Arc::clone(&supervisor);
            std::thread::spawn(move || {
                collect_loop(&db, &supervisor, super::fast_gc_task());
            })
        };

        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(db.lock().intent_count().expect("counted"), 1, "nothing was old enough");

        let _ = supervisor.begin_shutdown();
        assert!(running.join().is_ok());
    }
}
