//! `synra-daemon` — the kernel's windowless host.
//!
//! Short on purpose: read the flags, run the start-up, print what it decided, serve until asked to stop, release the
//! claim on the way out. Everything decidable lives in the library, which is what keeps this file readable in one go —
//! the crate docs say why that is a design requirement rather than a preference.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use synra_control::Listener;
use synra_daemon::args::{ClaimFile, DaemonArgs, refresh_claim};
use synra_daemon::runtime::{Runtime, now_ms};
use synra_daemon::startup::{begin, release};

/// How often the claim is refreshed.
///
/// Read from the daemon's own constant rather than written here, because the stale-after window and the interval are two
/// halves of one decision: an interval that outlived the window would make a healthy daemon look dead to the next start.
const HEARTBEAT_MS: u64 = synra_daemon::HEARTBEAT_INTERVAL_MS;

fn main() -> ExitCode {
    let args = <DaemonArgs as clap::Parser>::parse();
    // ★ A real reading, not zero. The claim's heartbeat is in the same frame, and a reading of zero made every claim
    // look like it had just beaten — so the crash recovery never fired and a daemon that died abruptly blocked the
    // next start for ever.
    let decision = begin(&args, std::process::id(), now_ms());

    for line in decision.lines() {
        println!("{line}");
    }
    // A refusal goes to the error stream, so a script redirecting one does not lose it and a user piping to a pager
    // does not have it buried among the output.
    if let Some(reason) = decision.failure() {
        eprintln!("synra-daemon: {reason}");
    }

    let exit = if decision.may_run() {
        serve(&decision)
    }
    else {
        ExitCode::from(decision.exit_code())
    };

    // ★ A clean shutdown says so in the claim rather than deleting it. A deleted file is indistinguishable from a
    // daemon that was killed before it wrote one — and that difference is exactly what the next start wants to know,
    // because it is what lets a crashed session be reported as a crash.
    if decision.may_run()
        && let Err(error) = release(&decision)
    {
        eprintln!("synra-daemon: {error}");
        return ExitCode::FAILURE;
    }

    exit
}

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
fn serve(decision: &synra_daemon::Startup) -> ExitCode {
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
    let host = synra_core::Host::new(identity.clone(), local_peer);

    let runtime = Runtime {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        data_dir: std::path::PathBuf::from(&plan.data_dir),
        plugins_dir: std::path::PathBuf::from(&plan.plugins_dir),
        listen_port: plan.listen_port,
        discovery_port: plan.discovery_port,
        started_at_ms: now_ms(),
        identity,
        host: parking_lot::Mutex::new(host),
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

    // ★ The heartbeat runs on its own thread because the accept loop blocks. A refresh done from the loop would only
    // happen when a client connected — so a daemon nobody was talking to would look dead after the stale window, and the
    // next start would reclaim a directory a live daemon is serving.
    let beating = Arc::new(AtomicBool::new(true));
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
