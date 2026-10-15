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

use synra_control::Listener;

use crate::args::{ClaimFile, refresh_claim};
use crate::runtime::{Runtime, now_ms};

/// How often the claim is refreshed.
///
/// Read from the daemon's own constant rather than written here, because the stale-after window and the interval are two
/// halves of one decision: an interval that outlived the window would make a healthy daemon look dead to the next start.
const HEARTBEAT_MS: u64 = crate::HEARTBEAT_INTERVAL_MS;

/// Binds the control socket and serves until interrupted.
///
/// # Why this is one loop and not a task per client
///
/// A command-line client sends one batch and closes, so the work per connection is bounded by what the kernel does for
/// that batch — and the kernel has nothing to overlap, because the layer that would do the work is not written. A thread
/// per connection would be concurrency with nothing to run concurrently.
///
/// # Why a missing plan is not a failure here
///
/// `may_run` was already true, so a plan exists. Reading it as `None` would be a contradiction rather than a condition a
/// user can act on, and the honest answer is to say which invariant broke.
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
            Some(Arc::new(parking_lot::Mutex::new(service)))
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
    let log_dir = synra_store::Paths::new(
        std::path::PathBuf::from(&plan.data_dir),
        std::path::PathBuf::from(&plan.data_dir).join("cache"),
    )
    .log_dir()
    .to_path_buf();
    let crashes = synra_observe::crash::CrashStore::new(&log_dir);
    // The daemon's own version, not the observe layer's: the report is about the binary that crashed.
    synra_observe::crash::install_panic_hook(crashes.clone(), env!("CARGO_PKG_VERSION"));

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

    // ★ The database goes behind its lock **here**, before the plugin host is built.
    //
    // The host a plugin's calls reach reads two things from it — which capabilities the user granted, and what the
    // interface was configured with — so the handle has to exist first. It used to be wrapped much later, which is part
    // of why the host had nothing to be built from and no session was ever installed.
    let shared_db = Arc::new(parking_lot::Mutex::new(db));

    // ★ The plugin host is built **before** the runtime, and its failure ends the daemon.
    //
    // This is the one dependency that can refuse. Everything else here is data the daemon reads; an engine that will not
    // start means this host cannot run a plugin at all, and continuing would produce a daemon whose status report says
    // no plugins are loaded for a reason that has nothing to do with what the user installed.
    let plugins = match crate::runtime::build_set(Arc::clone(&shared_db)) {
        Ok(set) => Arc::new(parking_lot::Mutex::new(set)),
        Err(error) => {
            eprintln!("synra-daemon: the plugin host could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let board = Arc::new(parking_lot::Mutex::new(synra_core::intent::Board::new()));
    // ★ What an inbound share is routed with, built here because this is where all three exist.
    //
    // Without it the transport could receive a share and had nothing to ask: a peer's shared text was reported and
    // dropped, so the routing the design calls the kernel's most central orchestration had no inbound half.
    let router = Arc::new(crate::runtime::intent::Router::new(
        Arc::clone(&plugins),
        Arc::clone(&board),
    ));
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
        let summary = {
            let mut set = plugins.lock();
            crate::runtime::load_installed(
                &mut set,
                &shared_db.lock(),
                std::path::Path::new(&plan.plugins_dir),
                &verdict,
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
        Arc::new(parking_lot::Mutex::new(summary))
    };

    // ★ Wrapped before the runtime is built, because two things need it and only one of them is the runtime.
    //
    // The discovery thread writes what it hears; the control socket reads it. Neither can reach the other, so the handle
    // is shared rather than passed — and it is shared behind a lock because `rusqlite::Connection` is `Send` and not `Sync`.

    let runtime = Runtime {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        data_dir: std::path::PathBuf::from(&plan.data_dir),
        plugins_dir: std::path::PathBuf::from(&plan.plugins_dir),
        listen_port: plan.listen_port,
        discovery_port: plan.discovery_port,
        started_at_ms: now_ms(),
        identity,
        host: Arc::new(parking_lot::Mutex::new(host)),
        discovery: discovery.clone(),
        scan_until_ms: Arc::clone(&scan_until_ms),
        db: Arc::clone(&shared_db),
        pairing,
        plugins,
        plugin_loads,
        board: Arc::new(parking_lot::Mutex::new(synra_core::intent::Board::new())),
        // ★ Handed to the runtime so `synra logs --verbose` can raise what the process writes. `None` when logging is
        // not running — a daemon whose log file could not be opened still answers the command, and it must not claim to
        // have raised anything.
        verbosity: log_verbosity,
    };

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
    for service in ["transport.accept", "discovery.udp"] {
        // Reported rather than fatal: `TaskSpec::service` is `Ordinary` criticality, so a task that will not register is a
        // capability this run does not have, not a reason to refuse to serve.
        if let Err(error) = supervisor.register(synra_core::supervisor::TaskSpec::service(service)) {
            eprintln!("synra-daemon: {service} could not be registered: {error}");
        }
    }

    // ★ The transport listener runs on its own thread for the same reason discovery does: taking a connection is cheap but
    // a handshake is not, and the control socket serves one client at a time. Each accepted connection is handed to its
    // own thread, so a peer that is slow to say `Hello` delays nothing.
    if runtime.host.lock().listen_nonblocking().is_ok() {
        let peers = Arc::clone(&runtime.host);
        let data_dir = runtime.data_dir.clone();
        // The runtime's own desk, not a second one: a prompt raised by the transport must be the prompt a control command
        // answers, and two desks would mean a user answering a request the waiting connection never hears about.
        let desk = Arc::clone(&runtime.pairing);
        let id = synra_core::supervisor::TaskId::new("transport.accept");
        // The token is the loop's stop condition, so cancelling the task *is* stopping the listener — there is no second
        // flag for the two to disagree about.
        if let Err(error) = synra_core::supervisor::run_task(&supervisor, &id, move |token| {
            synra_core::listener::serve(&peers, token, &data_dir, &desk, &router);
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
    let heartbeat = {
        let supervisor = Arc::clone(&supervisor);
        let lock_path = plan.lock_path();
        std::thread::spawn(move || heartbeat_loop(&supervisor, &lock_path))
    };

    let mut code = ExitCode::SUCCESS;
    while !supervisor.is_shutting_down() {
        if let Err(error) = listener.serve_one(&runtime) {
            // One client's failure is not the daemon's. A transport error is reported and the loop continues, because a
            // daemon that exited on a malformed connection would be one any local process could stop.
            eprintln!("synra-daemon: {error}");
            code = ExitCode::FAILURE;
        }
    }

    // ★ Asked through the supervisor rather than by setting a flag, so the two services stop the way they were started:
    // the token they were given is cancelled, and the stop order is the reverse of registration.
    let _ = supervisor.begin_shutdown();
    let _ = heartbeat.join();
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
        std::thread::sleep(std::time::Duration::from_millis(HEARTBEAT_MS));

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
