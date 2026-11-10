//! Opens the persistent state and prepares diagnostics before the daemon serves.

use std::process::ExitCode;

use synra_core::Identity;
use synra_observe::crash::CrashStore;
use synra_observe::logging::LogGuard;
use synra_store::{Paths, SynraDb};

use crate::DaemonPlan;

pub(super) fn open_database(plan: &DaemonPlan) -> Result<(SynraDb, Identity), ExitCode> {
    // ★ The database is opened and migrated **before** the socket is bound, so a client cannot connect to a kernel whose
    // storage is not ready. A daemon that bound first would answer the first command with a statement error about a
    // missing table — and the user would read that as a corrupt database rather than as a start that had not finished.
    let db_path = std::path::PathBuf::from(&plan.db_path);
    let mut db = match SynraDb::open(&db_path) {
        Ok(db) => db,
        Err(error) => {
            eprintln!("synra-daemon: {error}");
            return Err(ExitCode::FAILURE);
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
            return Err(ExitCode::FAILURE);
        }
    }

    // ★ The identity is read (or created) here, once — after the claim and before the socket. Reading it per request is
    // how a device ends up with a second identity, because the read creates one when the row is absent.
    let identity = match Identity::load(
        &db,
        std::env::consts::OS,
        synra_store::sqlite::now_ms(),
    ) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("synra-daemon: {error}");
            return Err(ExitCode::FAILURE);
        }
    };
    // ★ Read out before the identity is moved into the host, because the pairing desk needs it: the verification code a
    // user compares is derived from this device's identifier, so a desk built with a stale or defaulted one would show a
    // code the other screen does not match — which reads to a user as an attacker rather than as a bug.
    println!("device {} ({})", identity.device_id, identity.display_name);
    Ok((db, identity))
}

pub(super) fn start_diagnostics(
    plan: &DaemonPlan,
    db: &SynraDb,
) -> (Paths, CrashStore, Option<LogGuard>) {
    // ★ The crash store, and the panic hook that fills it, are set up before anything that can crash.
    //
    // The order matters and is the whole reason this is up here rather than beside the safe-mode check below: a hook
    // installed after the plugin host is built does not record a failure while building it. The log directory comes from
    // `Paths` rather than being joined here, because `Paths` is the one place that decides where things live.
    let data_dir = std::path::PathBuf::from(&plan.data_dir);
    let cache_dir = data_dir.join("cache");
    let paths = Paths::new(data_dir, cache_dir);
    let log_dir = paths.log_dir().to_path_buf();
    let crashes = CrashStore::new(&log_dir);
    // The daemon's own version, not the observe layer's: the report is about the binary that crashed.
    synra_observe::crash::install_panic_hook(crashes.clone(), env!("CARGO_PKG_VERSION"));

    // ★ A previous run's uninstall may have left an artifact directory behind: a loaded engine held its wasm file open,
    // the row was already gone, and the leftover was reported to the user. This is the moment to finish it — the process
    // that held the file is gone, and no plugin has been loaded yet. The sandbox is **not** swept: data kept on purpose
    // belongs to the user.
    super::plugins::sweep_leftovers(db, &paths);

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
    let log = match synra_observe::logging::init(
        &synra_observe::logging::LogConfig::in_directory(&log_dir)
            .with_level(synra_observe::logging::LogLevel::Info),
    ) {
        Ok(guard) => Some(guard),
        Err(error) => {
            eprintln!("synra-daemon: logging is not running: {error}");
            None
        }
    };
    (paths, crashes, log)
}
