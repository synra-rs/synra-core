//! The panic hook, exercised through a real panic.
//!
//! # Why this is an integration test and not a unit test
//!
//! `install_panic_hook` calls `std::panic::set_hook`, which is **process-wide**. A test that installed one inside
//! `src/crash.rs` would change how every other test in that binary reports its own failures — the ordinary
//! `thread '...' panicked at ...` line, which is the whole reason a failing test is readable. A file under `tests/` is
//! its own binary, so the hook installed here belongs to this file and to nothing else.
//!
//! # Why there is one test and not two
//!
//! Because there is one hook. Two `#[test]` functions run on separate threads by default, and the second call to
//! `install_panic_hook` would replace the first's hook — so the first test's panic would be written to the second
//! test's store and the first would fail for a reason that has nothing to do with the code. That is a race that would
//! pass most runs and fail on a loaded machine, which is the worst kind: it is exactly the shape this repository keeps
//! finding and calling out. One test, one installation, both phases.
//!
//! # What it proves
//!
//! That a panic produces a file on disk, that the file names the location the repeat count is kept on, and that three
//! panics in one place reach safe mode. Those together are what stops a plugin that crashes on activation from being
//! started again — and the settings screen the user needs to disable it is behind that start.
//!
//! Before this hook existed the whole chain was built and dry: the report type, the store, the threshold, the
//! plugin-loading path that consults it, and no report ever written.

// A test file that cannot unwrap a fixture is a test file that reports its own bug as a mystery.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use synra_observe::crash::{CrashReport, CrashStore, SAFE_MODE_THRESHOLD, install_panic_hook};

/// A directory that removes itself.
///
/// Written here rather than pulled from `synra-testkit`, because `synra-observe` does not depend on it and adding a
/// dev-dependency for eight lines would be a worse trade than repeating them.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-crash-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Panics, catching the unwind so the test can carry on.
///
/// `#[track_caller]` is not used and cannot be: what matters is that every call reports the **same** location, because
/// that is the key safe mode counts on. A helper called from a loop does that — the panic happens inside this function
/// on the same line every time, which is also how a real crash loop looks.
fn crash_once() {
    panic!("the plugin host fell over");
}

#[test]
fn a_crash_loop_is_recorded_and_reaches_safe_mode() {
    let dir = TempDir::new("panic-hook");
    let store = CrashStore::new(dir.path());

    // ★ Installed once. Everything below runs under this hook.
    install_panic_hook(store.clone(), "9.9.9");

    // ── One panic: what a single crash produces ──────────────────────────────────────────────────────────
    let caught = std::panic::catch_unwind(crash_once);
    assert!(caught.is_err(), "the panic has to actually happen for this to test anything");

    let first: Vec<CrashReport> = store.read_all();
    assert_eq!(first.len(), 1, "the hook wrote {} reports, not one", first.len());

    let report = first.first().expect("one report");
    assert_eq!(report.version, "9.9.9", "the version passed in is the version recorded");
    assert_eq!(
        report.message.as_deref(),
        Some("the plugin host fell over"),
        "the panic message is the part a user reads"
    );

    // ★ The location, which is the field safe mode counts on. A report without one cannot contribute to the repeat
    // count at all — the store's own comment says why: an unknown location is not evidence that the same bug happened
    // again.
    let location = report.location.as_deref().expect("a panic from `panic!` carries a location");
    assert!(location.contains("panic_hook.rs"), "the location should name this file: {location}");

    // ── Up to the threshold, at the same location: what a crash loop produces ────────────────────────────
    for _ in 1..SAFE_MODE_THRESHOLD {
        let _ = std::panic::catch_unwind(crash_once);
    }

    let all = store.read_all();
    assert_eq!(
        all.len(),
        SAFE_MODE_THRESHOLD,
        "every panic should have produced its own report: {} of {SAFE_MODE_THRESHOLD}",
        all.len()
    );

    // Every report names the same place, which is what the count is kept on. If the locations differed, the verdict
    // below would see three unrelated bugs and correctly refuse to enter safe mode.
    let locations: Vec<&str> = all.iter().filter_map(|r| r.location.as_deref()).collect();
    assert_eq!(locations.len(), SAFE_MODE_THRESHOLD, "every report needs a location to be counted");
    assert!(
        locations.windows(2).all(|pair| pair.first() == pair.last()),
        "the panics came from more than one location, so this is not a crash loop: {locations:?}"
    );

    // ★ The end-to-end statement. A real panic, written by the real hook, counted by the real verdict, is what stops a
    // plugin from being started on the next run. Each part had its own test and nothing tied them together, which is
    // how the chain stayed dry.
    let verdict = store.verdict(synra_observe::crash::now_ms());
    assert!(
        !verdict.allows_plugins(),
        "three panics in one place did not reach safe mode: {verdict:?}"
    );
}
