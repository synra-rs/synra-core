//! Startup checks for installed plugins and artifacts left by a previous uninstall.

use std::sync::Arc;

use parking_lot::Mutex;
use synra_core::dispatch::PluginSet;
use synra_observe::crash::CrashStore;
use synra_plugin_api::revocation::RevocationList;
use synra_store::{Paths, SynraDb};

use crate::DaemonPlan;
use crate::runtime::{LoadedSummary, now_ms};

/// Finishes a previous uninstall's leftovers, before any plugin is loaded.
///
/// # Why this is a function
///
/// Because it is three error branches and a report, and `serve` has a complexity budget that a reader benefits from: the
/// start-up reads as "open, restore, sweep, load, serve" when each step is named.
pub(super) fn sweep_leftovers(db: &SynraDb, paths: &Paths) {
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
pub(super) fn read_revocations(plan: &DaemonPlan) -> RevocationList {
    let path = std::path::Path::new(&plan.data_dir).join("revocations.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => match RevocationList::parse(&text) {
            Ok(list) => {
                eprintln!(
                    "synra-daemon: {} revocation entries read from {}",
                    list.len(),
                    path.display()
                );
                list
            }
            Err(error) => {
                eprintln!(
                    "synra-daemon: {} could not be read as a revocation list ({error}); no plugin is disabled on its account",
                    path.display()
                );
                RevocationList::empty()
            }
        },
        Err(_) => RevocationList::empty(),
    }
}

pub(super) fn load_plugins(
    plan: &DaemonPlan,
    shared_db: &Arc<Mutex<SynraDb>>,
    plugins: &Arc<Mutex<PluginSet>>,
    crashes: &CrashStore,
    revocations: &RevocationList,
) -> Arc<Mutex<LoadedSummary>> {
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
                eprintln!(
                    "synra-daemon: {} was not recorded: {problem}",
                    discovered.plugin_id
                );
            }
            None => println!(
                "synra-daemon: {} is installed and switched off",
                discovered.plugin_id
            ),
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
    // Snapshot the environment once. The loader releases its short store reads before guest activation.
    let activation = {
        let set = plugins.lock();
        synra_core::plugin::activation_config(set.host().as_ref())
    };
    let summary = {
        let mut set = plugins.lock();
        crate::runtime::load_installed_with_config(
            &mut set,
            shared_db,
            std::path::Path::new(&plan.plugins_dir),
            &verdict,
            revocations,
            &activation,
        )
    };
    // ★ Printed, because a plugin that failed to load is invisible otherwise and a silent skip is how a broken
    // plugin becomes a support question months later.
    for refused in &summary.refused {
        eprintln!(
            "synra-daemon: {} was not loaded: {}",
            refused.plugin_id, refused.reason
        );
    }
    // ★ And safe mode is printed for the same reason, louder: the user is looking at a daemon with no plugins and
    // needs to know it was a decision rather than a failed install.
    if let Some(why) = &summary.safe_mode {
        eprintln!("synra-daemon: plugins are not being started. {why}");
    }
    Arc::new(Mutex::new(summary))
}
