use super::super::{
    DISK_PROBE_SAMPLE_BYTES, LOW_DISK_BYTES, ProbeStatus, free_space, is_low_disk_space,
    probe_data_dir_writable, probe_disk_space,
};
use super::unique_suffix;

#[test]
fn a_writable_directory_passes_and_gains_no_litter() {
    let dir = std::env::temp_dir().join(format!("synra-doctor-rw-{}", unique_suffix()));
    let _ = std::fs::remove_dir_all(&dir);

    let result = probe_data_dir_writable(&dir);
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
    // The probe file is removed, so a repeated diagnosis does not accumulate files.
    assert!(
        !dir.join(".synra-write-probe").exists(),
        "the probe left its file behind"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_directory_that_cannot_be_created_fails() {
    // A path under an existing regular file cannot become a directory, on every platform.
    let file = std::env::temp_dir().join(format!("synra-doctor-file-{}", unique_suffix()));
    std::fs::write(&file, b"not a directory").expect("writes");

    let result = probe_data_dir_writable(&file.join("under-a-file"));
    assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
    assert!(result.suggestion.is_some());

    let _ = std::fs::remove_file(&file);
}

#[test]
fn the_disk_probe_reports_a_figure_it_can_read() {
    // ★ This test asserted the opposite until round 128, and the change is the point.
    //
    // It used to require the detail to contain "platform query" — the probe's way of saying it could not read a
    // free-space figure. That was true of the standard library and false of the ecosystem: `sysinfo` reads the mount table
    // in safe Rust, which is what the workspace's `unsafe_code = "forbid"` requires. So the probe now reports a number,
    // and the test asserts the weaker thing that actually matters — that whatever it says is something it can support.
    let dir = std::env::temp_dir().join(format!("synra-doctor-disk-{}", unique_suffix()));
    let result = probe_disk_space(&dir);
    assert!(result.status.needs_attention() || result.status == ProbeStatus::Ok);
    assert!(
        result.detail.contains("bytes are free") || result.detail.contains("did not report"),
        "the probe said something it cannot support: {}",
        result.detail
    );
}

#[test]
fn free_space_names_a_figure_for_the_volume_the_path_is_on() {
    // The longest-matching-mount-point rule is what makes this the *right* volume: `/` is a prefix of every path, so the
    // first match would report the root filesystem's space for a path on a mounted disk — a real number about the wrong
    // disk, which is worse than no number.
    let dir = std::env::temp_dir();
    // ★ This used to be `let Some(bytes) = … else { return; }` — "a host whose mount table does not mention the temp
    // directory is one this cannot answer for, and that is a skip, not a failure". It read as caution and it was the bug:
    // `free_space` returned `None` for **every** path on Windows, because `canonicalize` answers `\\?\C:\…` while a mount
    // point is `C:\`, so the skip swallowed a function that did not work. Round 130 found it from the other side, when the
    // receiver's disk gate refused three tests with "this host did not report the free space".
    //
    // Asked for the figure now, because there is no honest reason for a real directory on a real volume to be an unknown.
    let bytes = free_space(&dir).expect("a real directory on a real volume has a free-space figure");
    assert!(bytes > 0, "a mounted volume reporting no free space at all: {bytes}");
    // And a path that does not exist must not panic: the probe runs on directories a user may have deleted between the
    // call and the check. Either answer is fine here — the parent's volume or nothing — so the call itself is the
    // assertion. Written as a call and not as `assert!(x.is_none() || true)`, which was the first thing I typed and is a
    // criterion that cannot fail.
    let _ = free_space(&dir.join("no-such-directory-here"));
}

#[test]
fn the_disk_probe_leaves_the_data_directory_as_it_found_it() {
    // ★ `synra doctor` is a read-only diagnosis, and a diagnosis that writes must at least clean up after itself.
    //
    // The probe measures writability by writing a mebibyte and reading it back, so it necessarily creates a file in the
    // user's data directory. It removed that file on the success path and **not** on the failure path — which is the
    // path a user with a full disk is on, and the one where a stray file is least welcome.
    //
    // The failure path is fixed, and this test covers the half that is reproducible: after a probe that succeeded, the
    // directory holds nothing. The failure half has no portable trigger — every portable way to make the write fail
    // (a read-only directory, a path that is a directory) fails *before* the file is created, so there is nothing to
    // observe — and a test that cannot fail for the right reason is worse than none. What found the bug was the
    // artefact itself: a 0-byte `.synra-disk-probe` left in the repository by a run whose write had been denied.
    let dir = std::env::temp_dir().join(format!("synra-doctor-disk-clean-{}", unique_suffix()));
    let result = probe_disk_space(&dir);
    assert!(
        result.status != ProbeStatus::Fail,
        "this test needs a probe that succeeded: {}",
        result.detail
    );

    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .expect("the probe created the directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(leftovers.is_empty(), "the probe left {leftovers:?} behind");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_low_space_threshold_is_inclusive_at_its_boundary() {
    // A disk with exactly the threshold free is not yet low, and one byte less is. The boundary has to be
    // decided once, here, or the settings screen and the probe would disagree.
    assert!(!is_low_disk_space(LOW_DISK_BYTES));
    assert!(is_low_disk_space(LOW_DISK_BYTES - 1));
    assert!(is_low_disk_space(0));
    assert!(!is_low_disk_space(LOW_DISK_BYTES + 1));
}

#[test]
fn the_disk_probe_sample_is_small_enough_to_be_unobtrusive() {
    // A diagnosis that writes a hundred megabytes to talk about disk space is both slow and rude.
    assert_eq!(DISK_PROBE_SAMPLE_BYTES, 1024 * 1024);
    assert!(
        (DISK_PROBE_SAMPLE_BYTES as u64) < LOW_DISK_BYTES / 100,
        "the sample is a material fraction of the threshold it is checking"
    );
}
