use std::path::Path;
use super::super::{CrashStore, CRASH_DIR, MAX_REPORTS, SAFE_MODE_THRESHOLD, StartupVerdict, now_ms};
use super::{report, test_suffix};

#[test]
fn three_crashes_in_the_same_millisecond_are_three_reports() {
    // ★ The flake that was a bug. Found by running the integration test in a loop: it failed 2 times in 15, and the
    // assertion was "every panic should have produced its own report: 2 of 3".
    //
    // The cause was the file name — `crash-{at_ms}.json` — so a crash loop panicking three times inside one
    // millisecond wrote one file, each write overwriting the last. A tight activation loop is exactly that shape.
    //
    // Why it matters beyond lost paperwork: `startup_verdict` **counts** reports to decide safe mode. A count that
    // comes up short is a daemon that starts the crashing plugin again on every run, which is the one outcome the
    // whole crash-reporting mechanism exists to prevent — and the settings screen the user needs to disable it is
    // behind that start.
    //
    // The three reports are written with the *same* timestamp, which is the condition; distinct timestamps would
    // have passed against the broken version and proved nothing. It has to be a **recent** one as well, because
    // safe mode is decided from recent crashes only — a fixed timestamp from years ago is ignored by design, and a
    // test that used one would be asserting about a verdict that never looked at these reports.
    let dir = std::env::temp_dir().join(format!("synra-crash-collide-{}", test_suffix()));
    let store = CrashStore::at(dir.clone());
    let _ = std::fs::remove_dir_all(&dir);

    let at = now_ms();
    for _ in 0..SAFE_MODE_THRESHOLD {
        store.write(&report(at, Some("a.rs:1:1"))).expect("writes");
    }

    let read = store.read_all();
    assert_eq!(
        read.len(),
        SAFE_MODE_THRESHOLD,
        "a report was overwritten by one sharing its millisecond"
    );

    // And the point of counting: the same location, hit this many times, has to reach safe mode.
    assert!(
        !store.verdict(now_ms()).allows_plugins(),
        "the crash loop should reach safe mode: {:?}",
        store.verdict(now_ms())
    );

    // The files are distinct on disk too, so the count is not an artefact of reading one file repeatedly.
    let files = std::fs::read_dir(&dir).expect("the directory").filter_map(Result::ok).count();
    assert_eq!(files, SAFE_MODE_THRESHOLD, "one file per report");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_store_writes_and_reads_reports() {
    let dir = std::env::temp_dir().join(format!("synra-crash-test-{}", test_suffix()));
    let store = CrashStore::at(dir.clone());
    let _ = std::fs::remove_dir_all(&dir);

    assert!(store.is_empty(), "nothing written yet");
    assert_eq!(store.len(), 0);

    let first = report(1_000, Some("a.rs:1:1"));
    let second = report(2_000, Some("b.rs:2:2"));
    store.write(&first).expect("writes");
    store.write(&second).expect("writes");

    let read = store.read_all();
    assert_eq!(read.len(), 2);
    // Oldest first, so a caller can walk them in the order they happened.
    assert_eq!(read[0].at_ms, 1_000);
    assert_eq!(read[1].at_ms, 2_000);

    store.clear().expect("clears");
    assert!(store.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_store_reads_an_empty_directory_as_no_reports() {
    // A fresh install has no crash directory at all, and that is not an error.
    let dir = std::env::temp_dir().join(format!("synra-crash-missing-{}", test_suffix()));
    let store = CrashStore::at(dir);
    assert!(store.read_all().is_empty());
    assert_eq!(store.verdict(now_ms()), StartupVerdict::Clean);
    // Clearing a directory that does not exist is not an error either.
    assert!(store.clear().is_ok());
}

#[test]
fn an_unreadable_report_is_skipped_rather_than_failing_the_read() {
    // A truncated file is exactly what a crash during a write produces, and it must not stop the next
    // start from noticing the other reports.
    let dir = std::env::temp_dir().join(format!("synra-crash-partial-{}", test_suffix()));
    let store = CrashStore::at(dir.clone());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creates");

    store.write(&report(1_000, Some("a.rs:1:1"))).expect("writes");
    std::fs::write(dir.join("crash-2000.json"), b"{ this is not json").expect("writes a bad file");

    let read = store.read_all();
    assert_eq!(read.len(), 1, "the good report survives: {read:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_store_keeps_only_the_most_recent_reports() {
    // A crash loop writes one report per start. An unbounded directory fills the disk in an afternoon.
    let dir = std::env::temp_dir().join(format!("synra-crash-prune-{}", test_suffix()));
    let store = CrashStore::at(dir.clone());
    let _ = std::fs::remove_dir_all(&dir);

    for index in 0..(MAX_REPORTS + 5) {
        store
            .write(&report(index as i64 * 1_000, Some("a.rs:1:1")))
            .expect("writes");
    }

    let read = store.read_all();
    assert!(read.len() <= MAX_REPORTS, "held {} reports", read.len());
    // The survivors are the newest, because the file names carry the timestamp.
    assert_eq!(read.last().map(|r| r.at_ms), Some((MAX_REPORTS as i64 + 4) * 1_000));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_store_builds_its_directory_from_the_log_directory() {
    let store = CrashStore::new(Path::new("/var/log/synra"));
    assert!(store.directory().ends_with(CRASH_DIR));
    assert!(store.directory().to_string_lossy().contains("synra"));
}
