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
        db,
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
        std::thread::spawn(move || crate::transport::serve(&peers, &stop, &data_dir));
    }

    // ★ Discovery runs on its own thread and the control loop only reads what it learned. `serve_one` blocks and the
    // listener cannot be cloned, so a scan inside a command would hold the control socket for its whole budget — and a
    // user's `status`, run to find out why things are slow, would wait for the network too.
    if let Some(discovery) = &discovery {
        let service = Arc::clone(discovery);
        let peers = Arc::clone(&runtime.host);
        let deadline = Arc::clone(&scan_until_ms);
        // ★ The thread runs for the process's lifetime and is not joined. Nothing needs to end it early: the loop reads a
        // deadline that expires on its own, and the process is what stops it. There is no join handle to keep either —
        // dropping one detaches the thread, which is exactly what is wanted.
        std::thread::spawn(move || {
            synra_core::worker::run(&service, &peers, &deadline, synra_store::sqlite::now_ms);
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
