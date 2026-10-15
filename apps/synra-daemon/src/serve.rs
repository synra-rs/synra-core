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
use std::sync::atomic::{AtomicBool, Ordering};

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
    // ★ The plugin host is built **before** the runtime, and its failure ends the daemon.
    //
    // This is the one dependency that can refuse. Everything else here is data the daemon reads; an engine that will not
    // start means this host cannot run a plugin at all, and continuing would produce a daemon whose status report says
    // no plugins are loaded for a reason that has nothing to do with what the user installed.
    let plugins = match crate::runtime::build_set() {
        Ok(set) => Arc::new(parking_lot::Mutex::new(set)),
        Err(error) => {
            eprintln!("synra-daemon: the plugin host could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let plugin_loads = {
        // ★ The guard is scoped to the load and nothing else. It is held while third-party artifacts compile, which is
        // the point of the lock — but not while the refusals are printed, because printing is not something another
        // thread should be waiting behind.
        //
        // ★ Safe mode is decided here, before anything is loaded, and it is the only thing that can decide it. The
        // verdict reads the crash reports the previous runs left behind; a plugin that has crashed this location three
        // times in a row is not started a fourth time, so the settings screen the user needs to switch it off stays
        // reachable.
        //
        // The log directory comes from `Paths` rather than being joined here, because `Paths` is the one place that
        // decides where things live — the same reason `plan.rs` routes the data directory through it.
        let log_dir = synra_store::Paths::new(
            std::path::PathBuf::from(&plan.data_dir),
            std::path::PathBuf::from(&plan.data_dir).join("cache"),
        )
        .log_dir()
        .to_path_buf();
        // `now_ms()` is `u64` because the runtime's clock is, and a crash report is stamped `i64` because it is written
        // to SQLite. The conversion is saturating rather than `as`: a clock far enough past 2262 to overflow should read
        // as "the latest possible instant", which makes every report look old and lets the daemon run — the direction
        // that fails open on a clock problem rather than refusing to start.
        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        let verdict = synra_observe::crash::CrashStore::new(&log_dir).verdict(now);
        let summary = {
            let mut set = plugins.lock();
            crate::runtime::load_installed(
                &mut set,
                &db,
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
    let shared_db = Arc::new(parking_lot::Mutex::new(db));

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
    };

    let listener = match Listener::bind(&runtime.data_dir) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("synra-daemon: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("control socket {}", listener.path().display());

    // ★ The stop flag is created **before** the threads that read it. The first version created it after the discovery
    // worker and before the transport loop, which happened to work for one and not the other — an ordering that is a
    // latent bug rather than a design, so the flag now comes first and everything that watches it starts below.
    let beating = Arc::new(AtomicBool::new(true));

    // ★ The transport listener runs on its own thread for the same reason discovery does: taking a connection is cheap but
    // a handshake is not, and the control socket serves one client at a time. Each accepted connection is handed to its
    // own thread, so a peer that is slow to say `Hello` delays nothing.
    if runtime.host.lock().listen_nonblocking().is_ok() {
        let peers = Arc::clone(&runtime.host);
        let stop = Arc::clone(&beating);
        let data_dir = runtime.data_dir.clone();
        // The runtime's own desk, not a second one: a prompt raised by the transport must be the prompt a control command
        // answers, and two desks would mean a user answering a request the waiting connection never hears about.
        let desk = Arc::clone(&runtime.pairing);
        std::thread::spawn(move || crate::transport::serve(&peers, &stop, &data_dir, &desk));
    }

    // ★ Discovery runs on its own thread and the control loop only reads what it learned. `serve_one` blocks and the
    // listener cannot be cloned, so a scan inside a command would hold the control socket for its whole budget — and a
    // user's `status`, run to find out why things are slow, would wait for the network too.
    if let Some(discovery) = &discovery {
        let service = Arc::clone(discovery);
        let peers = Arc::clone(&runtime.host);
        let deadline = Arc::clone(&scan_until_ms);
        // ★ Cloned into the thread because the closure outlives this function — it runs for the process's lifetime, and a
        // borrowed `shared_db` would make that impossible to express.
        let remembered = Arc::clone(&shared_db);
        // ★ The thread runs for the process's lifetime and is not joined. Nothing needs to end it early: the loop reads a
        // deadline that expires on its own, and the process is what stops it. There is no join handle to keep either —
        // dropping one detaches the thread, which is exactly what is wanted.
        std::thread::spawn(move || {
            synra_core::worker::run_recording(
                &service,
                &peers,
                &deadline,
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
        });
    }

    // ★ The heartbeat runs on its own thread because the accept loop blocks. A refresh done from the loop would only
    // happen when a client connected — so a daemon nobody was talking to would look dead after the stale window, and the
    // next start would reclaim a directory a live daemon is serving.
    let heartbeat = {
        let stop = Arc::clone(&beating);
        let lock_path = plan.lock_path();
        std::thread::spawn(move || heartbeat_loop(&stop, &lock_path))
    };

    let mut code = ExitCode::SUCCESS;
    while !stop_requested(&beating) {
        if let Err(error) = listener.serve_one(&runtime) {
            // One client's failure is not the daemon's. A transport error is reported and the loop continues, because a
            // daemon that exited on a malformed connection would be one any local process could stop.
            eprintln!("synra-daemon: {error}");
            code = ExitCode::FAILURE;
        }
    }

    beating.store(false, Ordering::Relaxed);
    let _ = heartbeat.join();
    code
}

/// Whether the process has been asked to stop.
///
/// # Why a flag rather than a signal handler
///
/// A signal handler needs either `unsafe` or a crate, and this workspace forbids the first. What is checked instead is
/// whether the **claim still belongs to this process** — so a `synra-daemon` replaced by a newer one, or a claim removed
/// by hand, stops this one rather than leaving two daemons serving one data directory. Ctrl-C ends the process, and the
/// claim it leaves behind is what the next start reads as an unclean shutdown.
fn stop_requested(beating: &AtomicBool) -> bool {
    // The heartbeat thread clears the flag when the claim stops being refreshable, which is the one condition under
    // which continuing would be worse than stopping.
    !beating.load(Ordering::Relaxed)
}

/// Refreshes the claim on an interval until asked to stop.
///
/// # Why the claim is re-read rather than held
///
/// The file is the source of truth, and a copy held in memory would go stale the moment anything else touched it — which
/// is exactly the condition this loop exists to notice. Re-reading costs one small file per interval and makes "does
/// this process still own the directory" a question about the directory rather than about a copy of it.
fn heartbeat_loop(beating: &AtomicBool, lock_path: &std::path::Path) {
    while beating.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(HEARTBEAT_MS));

        let current = match ClaimFile::read(lock_path) {
            Ok(ClaimFile::Found(lock)) => lock,
            // No claim to refresh. Either the start-up wrote none — a daemon that never claimed the directory — or
            // another process removed it. Neither is a reason to stop serving: what a *client* needs is the socket, and
            // what the next *start* needs is the claim it will find missing and treat as a crash.
            Ok(ClaimFile::Absent) => continue,
            Err(error) => {
                eprintln!("synra-daemon: the claim could not be read, stopping: {error}");
                beating.store(false, Ordering::Relaxed);
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
            beating.store(false, Ordering::Relaxed);
            return;
        }

        if let Err(error) = refresh_claim(lock_path, &current, now_ms()) {
            eprintln!("synra-daemon: the claim could not be refreshed, stopping: {error}");
            beating.store(false, Ordering::Relaxed);
            return;
        }
    }
}
