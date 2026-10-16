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
                match free_space(data_dir) {
                    Some(bytes) => format!("the data directory accepts writes; {bytes} bytes are free"),
                    // The figure is still not guaranteed: a mount table with nothing matching the path is a host this
                    // cannot answer for, and saying so is better than printing a number for the wrong volume.
                    None => "the data directory accepts writes; this host did not report the free space".to_owned(),
                },
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

/// How much space is left where `path` lives, when this host can say.
///
/// ★ **Why this replaced "the free-space figure needs a platform query".**
///
/// That sentence was true of the standard library and false of the ecosystem. `sysinfo` reads the mount table in safe
/// Rust — which matters here, because the workspace **forbids `unsafe_code`**, so the direct route (`GetDiskFreeSpaceExW`
/// on Windows, `statvfs` elsewhere) is one this crate cannot take. A diagnosis that cannot say how much room is left is
/// one a user can only answer with "free some", and the case this probe exists for is a disk that is nearly full rather
/// than already full.
///
/// ★ **The longest matching mount point wins**, which is the same care the shape guard needed in the other direction: `/`
/// is a prefix of every path, so taking the first match would report the root filesystem's free space for a path on a
/// mounted volume — a number that is real, about the wrong disk, and therefore worse than no number.
#[must_use]
pub fn free_space(path: &Path) -> Option<u64> {
    // Canonicalised because a mount point is an absolute, symlink-resolved path and the comparison is textual. A path
    // that does not resolve is measured as written, which is the best this can do without failing the probe.
    let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    // ★ **And the device-namespace prefix is stripped, which is what made this return `None` for every path on Windows.**
    //
    // `canonicalize` answers `\\?\C:\Users\…` there, while a mount point is `C:\`, so no prefix matched and the function
    // reported "this host did not say" about a disk it had just read. Found by the receiver check that used it as a gate:
    // its three tests failed with *"this host did not report the free space"*, and the probe's own test had passed only
    // because it treated `None` as a reason to skip — a check that could not fail, protecting a function that did not
    // work. This crate's `synra-platform` already names the prefix in `PathError::DeviceNamespace`; this is the same fact.
    let absolute = absolute.to_string_lossy();
    let trimmed = absolute.strip_prefix(r"\\?\").unwrap_or(&absolute);
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let absolute = Path::new(trimmed);
    disks
        .list()
        .iter()
        .filter(|disk| absolute.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(sysinfo::Disk::available_space)
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
