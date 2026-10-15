//! The logging subscriber, exercised by writing real log lines.
//!
//! # Why this is an integration test and not a unit test
//!
//! Because `tracing` allows **one global subscriber per process**, and `try_init` fails if one is already installed. A
//! test inside `src/` would install one for every test in that binary and they would then race for it — passing on a
//! quiet machine and failing on a busy one. A file under `tests/` is its own binary, so the subscriber installed here
//! belongs to this file.
//!
//! # Why there is one test and not three
//!
//! For the same reason as the panic hook beside it: there is one subscriber. Three `#[test]` functions would each call
//! `init`, the second and third would get `AlreadyInstalled`, and the assertions would depend on which thread won. One
//! test, one installation, and the phases below are ordered statements rather than competing ones.
//!
//! # What it proves
//!
//! That the chain reaches the disk at all — which is the part that did not exist. `tracing` and `tracing-subscriber`
//! were declared dependencies of this crate and used by no source file, so every log line in the process went nowhere,
//! the daemon's `synra logs` read a file nothing created, and `--follow` and `--trace` had nothing to filter.

// A test file that cannot unwrap a fixture is a test file that reports its own bug as a mystery.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use synra_observe::logging::{LOG_FILE_NAME, LogConfig, LogLevel, LogError, init};

/// A directory that removes itself.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-log-{name}-{}", std::process::id()));
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

#[test]
fn a_log_line_reaches_the_file_with_its_secrets_removed() {
    let dir = TempDir::new("init");

    // A small cap so the rotation phase below needs only a few lines rather than eight megabytes of them.
    let config = LogConfig::in_directory(dir.path())
        .with_level(LogLevel::Info)
        .with_max_bytes(600)
        .with_keep(3);
    let guard = init(&config).expect("the subscriber installs");

    // ── Phase 1: a line reaches the file ─────────────────────────────────────────────────────────────────
    tracing::info!(device = "phone", "a device was paired");
    // ★ A secret in a field the redaction policy knows. This is the property that makes a log file safe to send in a
    // diagnostic bundle, and it is asserted where it can fail — at the disk.
    tracing::info!(token = "hunter2", "the handshake used a token");

    drop(guard);

    let path = dir.path().join(LOG_FILE_NAME);
    let text = std::fs::read_to_string(&path).expect("the log file exists after a line was written");

    assert!(text.contains("a device was paired"), "the message never reached the file: {text}");
    assert!(text.contains("phone"), "the field never reached the file: {text}");
    assert!(
        !text.contains("hunter2"),
        "the secret reached the disk, which is the one thing the redacting writer exists to prevent: {text}"
    );

    // ── Phase 2: a second `init` is refused rather than silently ignored ─────────────────────────────────
    //
    // The subscriber is already installed from phase 1 and stays installed for the life of the process — dropping the
    // guard closes the file, it does not uninstall. A second `init` has to say so: a caller that believed its own
    // configuration had taken effect would be reading someone else's log format.
    match init(&config) {
        Err(LogError::AlreadyInstalled) => {}
        Err(other) => panic!("a second init failed for the wrong reason: {other}"),
        // `LogGuard` is deliberately not `Debug` — it holds a writer, and a rendering of it would be a rendering of a
        // file handle. So the success arm is named rather than formatted.
        Ok(_) => panic!("a second init succeeded, which means two subscribers are writing to one file"),
    }
}

#[test]
fn the_file_rotates_and_keeps_the_newest_under_its_own_name() {
    // ★ A separate process-wide concern, but **not** a separate subscriber: this test runs in the same binary as the one
    // above, and it does not call `init`. It exercises `RotatingFile` directly, which is where the rotation lives — the
    // subscriber only decides that lines get there.
    use std::io::Write;

    let dir = TempDir::new("rotate");
    let mut file = synra_observe::logging::RotatingFile::open(dir.path(), 200, 2).expect("a log file");

    // Enough lines to rotate twice at 200 bytes a file.
    for index in 0..12 {
        writeln!(file, "line {index} of a log that has to rotate").expect("writes");
    }
    file.flush().expect("flushes");

    let active = dir.path().join(LOG_FILE_NAME);
    assert!(active.is_file(), "the active file keeps the plain name so a reader finds it");
    assert!(
        dir.path().join(format!("{LOG_FILE_NAME}.1")).is_file(),
        "the first rotation did not happen"
    );

    // ★ `keep` is what bounds the space, and it has to be enforced by *removing*, not by refusing to rotate. A directory
    // that only ever grew would make the cap a comment.
    assert!(
        !dir.path().join(format!("{LOG_FILE_NAME}.3")).exists(),
        "a file past the keep limit was left behind, so the cap does not bound anything"
    );
    assert!(file.keep() == 2, "the writer should report the keep limit it was given");
}
