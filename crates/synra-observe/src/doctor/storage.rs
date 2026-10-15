//! The probes the filesystem answers, and the disk-space policy they are judged against.

use std::path::Path;

use super::ProbeResult;

/// The disk space below which a warning is raised, in bytes.
///
/// Declared here because the threshold is a policy decision rather than a platform fact, and the settings
/// screen shows it. Enforcing it needs a free-space figure, which is a platform query: see
/// [`probe_disk_space`], which measures writability portably and states that the figure is unavailable rather
/// than guessing. A caller that *does* have the figure — the application layer calling `GetDiskFreeSpaceEx`
/// or `statvfs` — compares it using [`is_low_disk_space`], so the rule is stated once.
pub const LOW_DISK_BYTES: u64 = 500 * 1024 * 1024;

/// How large a sample [`probe_disk_space`] writes.
///
/// One mebibyte: enough that a full or nearly-full disk fails the write, small enough that a diagnosis is
/// unnoticeable. A sample scaled to [`LOW_DISK_BYTES`] would mean writing a hundred megabytes in order to
/// report on disk space.
pub const DISK_PROBE_SAMPLE_BYTES: usize = 1024 * 1024;

/// Whether a free-space figure is low enough to warn about.
///
/// Split out so the threshold can be tested without filling a disk, and so the application layer — which can
/// read the figure — applies the same rule instead of restating it.
#[must_use]
pub const fn is_low_disk_space(free_bytes: u64) -> bool {
    free_bytes < LOW_DISK_BYTES
}

/// Whether the data directory can be written to.
///
/// Tested by writing a file rather than by asking about permissions. A directory's mode bits do not account
/// for a read-only mount, an ACL, or a full disk, and the write is what the application actually needs.
#[must_use]
pub fn probe_data_dir_writable(data_dir: &Path) -> ProbeResult {
    if let Err(error) = std::fs::create_dir_all(data_dir) {
        return ProbeResult::fail(
            "data_dir_writable",
            format!("{} cannot be created: {error}", data_dir.display()),
            "check that the parent directory exists and is writable by this user",
        );
    }

    let probe = data_dir.join(".synra-write-probe");
    match std::fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            ProbeResult::ok("data_dir_writable", format!("{} is writable", data_dir.display()))
        }
        Err(error) => ProbeResult::fail(
            "data_dir_writable",
            format!("{} cannot be written: {error}", data_dir.display()),
            "check the directory's permissions, or move the data directory in Settings → Advanced",
        ),
    }
}

/// How much space is left where the data lives.
///
/// Reports what it can. Reading free space portably needs a platform call, so when the host cannot supply it
/// the probe measures what it *can* — whether the directory is writable — and says the free-space figure is
/// unavailable rather than inventing one.
#[must_use]
pub fn probe_disk_space(data_dir: &Path) -> ProbeResult {
    // A portable free-space query does not exist in the standard library, so this measures what it can: a file
    // of a known size is written and read back. A full disk fails that, which is the case the probe exists to
    // catch; the free-space *figure* still needs a platform call, and the detail says so rather than inventing
    // one.
    //
    // The earlier version called the writability probe and discarded its result, which checked nothing and
    // reported success — a probe that always passes is worse than no probe, because it is believed.
    let probe = data_dir.join(".synra-disk-probe");
    if let Err(error) = std::fs::create_dir_all(data_dir) {
        return ProbeResult::fail(
            "disk_space",
            format!("the data directory is unusable: {error}"),
            "check the directory's permissions, or move the data directory in Settings → Advanced",
        );
    }

    // One mebibyte, not a fraction of the low-space threshold. A larger sample would mean a diagnosis writes
    // a hundred megabytes to report on disk space, which is both slow and rude; a mebibyte is enough that a
    // full or nearly-full disk fails the write, and small enough to be unnoticeable.
    let sample = vec![0u8; DISK_PROBE_SAMPLE_BYTES];
    match std::fs::write(&probe, &sample) {
        Ok(()) => {
            let read_back = std::fs::read(&probe).map(|bytes| bytes.len()).unwrap_or(0);
            let _ = std::fs::remove_file(&probe);

            if read_back != sample.len() {
                return ProbeResult::fail(
                    "disk_space",
                    format!("wrote {} bytes but read back {read_back}", sample.len()),
                    "the storage may be failing; back up your data and check the disk",
                );
            }
            ProbeResult::ok(
                "disk_space",
                "the data directory accepts writes; the free-space figure needs a platform query",
            )
        }
        Err(error) => {
            // ★ The failure path cleans up too, and this was wrong until a stray file proved it.
            //
            // `std::fs::write` creates the file before it writes, so a write that fails partway — a full disk, a
            // permission the sandbox withdrew, a device error — leaves a probe file behind. The success path removed it;
            // this one did not. So the case this probe exists to diagnose (a disk that cannot be written) was also the
            // case that littered the user's data directory, once per `synra doctor`, with a file named after the probe.
            //
            // Found the honest way: a 0-byte `apps/synra-cli/.synra-disk-probe` was sitting untracked in the repository
            // after a test run whose write had been denied. The artefact was the bug report.
            let _ = std::fs::remove_file(&probe);
            ProbeResult::fail(
                "disk_space",
                format!("a {} byte write failed: {error}", sample.len()),
                "free some disk space; Synra needs room for plugin data and transfer buffers",
            )
        }
    }
}

/// Whether the plugin directory is usable.
///
/// Existence and writability only. Whether each installed plugin's *artifact* is intact needs the loader,
/// which lives in another crate; this reports the container rather than overstating what it checked.
#[must_use]
pub fn probe_plugin_dir(plugins_dir: &Path) -> ProbeResult {
    if !plugins_dir.exists() {
        return ProbeResult::ok(
            "plugin_dir",
            format!("{} does not exist yet; no plugins are installed", plugins_dir.display()),
        );
    }
    match std::fs::read_dir(plugins_dir) {
        Ok(entries) => {
            let count = entries.filter_map(Result::ok).count();
            ProbeResult::ok(
                "plugin_dir",
                format!("{} holds {count} entr(ies)", plugins_dir.display()),
            )
        }
        Err(error) => ProbeResult::fail(
            "plugin_dir",
            format!("{} cannot be read: {error}", plugins_dir.display()),
            "check the directory's permissions",
        ),
    }
}
