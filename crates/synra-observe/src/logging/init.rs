//! Installing the subscriber, and the guard that keeps it alive.
//!
//! # Why this exists
//!
//! `tracing` and `tracing-subscriber` were declared dependencies of this crate and **used by no source file**. Every
//! part of the logging layer was here — the level enum, the verbosity window, the counters, the redacting writer — and
//! nothing wrote a line, because nothing had installed a subscriber. The daemon's `synra logs` command reads a file
//! under `data_dir/logs` that no code created, so it always answered "no lines" and `--follow` and `--trace` had nothing
//! to filter.
//!
//! # Why the writer is shared behind a lock
//!
//! Because `tracing`'s `MakeWriter` hands out a writer per event and the redacting writer takes `&mut self`. The lock is
//! the same one `RedactingWriter` already takes internally for its destination, so this adds a second layer around the
//! first rather than a new contention point: a log line already serialised on the destination.
//!
//! # Why the subscriber is never replaced
//!
//! `tracing` allows one global subscriber per process, and `set_global_default` fails if one is already installed. That
//! failure is returned rather than worked around — a second `init` in the same process is a bug in the caller, and
//! silently keeping the first subscriber would make it look like the second had taken effect.

use std::io::{self, Write};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing_subscriber::fmt::MakeWriter;

use super::file::{DEFAULT_KEEP, DEFAULT_MAX_BYTES, RotatingFile};
use super::level::LogLevel;
use super::writer::RedactingWriter;

/// What the caller wants logged, and where.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// The directory the log file lives in. Created if it does not exist.
    pub directory: std::path::PathBuf,
    /// The most verbose level that is written.
    pub level: LogLevel,
    /// How large the file may grow before it rotates.
    pub max_bytes: u64,
    /// How many rotated files to keep.
    pub keep: usize,
}

impl LogConfig {
    /// The configuration for a directory, with the documented defaults.
    #[must_use]
    pub fn in_directory(directory: impl Into<std::path::PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            // `Info` rather than `Debug`: a default that writes debug lines is a default that fills a disk on a machine
            // nobody is watching. `--verbose` is how a person asks for more.
            level: LogLevel::Info,
            max_bytes: DEFAULT_MAX_BYTES,
            keep: DEFAULT_KEEP,
        }
    }

    /// The most verbose level that is written.
    #[must_use]
    pub const fn with_level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// How large the file may grow before it rotates.
    #[must_use]
    pub const fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// How many rotated files to keep.
    #[must_use]
    pub const fn with_keep(mut self, keep: usize) -> Self {
        self.keep = keep;
        self
    }
}

/// Why logging could not be started.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LogError {
    /// The log file could not be opened.
    #[error("the log file could not be opened: {0}")]
    File(#[from] io::Error),
    /// A subscriber was already installed for this process.
    #[error("a logging subscriber is already installed for this process")]
    AlreadyInstalled,
}

/// Keeps the subscriber's writer alive, and flushes it on the way out.
///
/// # Why a guard and not a bare `init`
///
/// Because the writer is reference-counted and the subscriber holds one of the references: dropping the last one closes
/// the file. Returning a guard makes the lifetime explicit — a caller that drops it stops logging, which is
/// `tracing-subscriber`'s own contract and is better stated here than discovered.
///
/// It flushes on drop rather than only closing, because the last line before a shutdown is often the one that explains
/// the shutdown.
#[must_use = "dropping the guard stops the log being written"]
pub struct LogGuard {
    writer: Arc<Mutex<RedactingWriter<RotatingFile>>>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        let _ = self.writer.lock().flush();
    }
}

/// A writer handle handed to `tracing` once per event.
///
/// Cheap to clone — an `Arc` — because `MakeWriter` is called for every event.
#[derive(Clone)]
struct SharedWriter(Arc<Mutex<RedactingWriter<RotatingFile>>>);

/// One event's writer, holding the shared handle for the duration of the write.
struct SharedGuard(Arc<Mutex<RedactingWriter<RotatingFile>>>);

impl Write for SharedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().flush()
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedGuard(Arc::clone(&self.0))
    }
}

/// Installs the subscriber that writes to a rotating file.
///
/// # Errors
///
/// [`LogError::File`] when the log file cannot be opened, and [`LogError::AlreadyInstalled`] when this process already
/// has a subscriber.
///
/// # Panics
///
/// Never. The subscriber's own `init` panics on a second installation; this uses `try_init` and returns the failure
/// instead, because a logging call is not a good place to abort a process that was otherwise starting.
pub fn init(config: &LogConfig) -> Result<LogGuard, LogError> {
    let file = RotatingFile::open(config.directory.clone(), config.max_bytes, config.keep)?;
    let writer = Arc::new(Mutex::new(RedactingWriter::new(file)));

    let subscriber = tracing_subscriber::fmt()
        // ★ The writer is where redaction happens, which is the point: a field named `token` never reaches the disk, and
        // the policy is applied on the way out rather than by every call site remembering to be careful.
        .with_writer(SharedWriter(Arc::clone(&writer)))
        // The ANSI escapes a terminal would interpret become noise in a file that is read back and filtered as text.
        .with_ansi(false)
        // The level is this crate's own enum rather than the environment variable `fmt` would otherwise consult, so the
        // daemon's `--verbose` flag and the file's contents cannot disagree.
        .with_max_level(config.level.to_tracing())
        .finish();

    use tracing_subscriber::util::SubscriberInitExt;
    subscriber.try_init().map_err(|_| LogError::AlreadyInstalled)?;

    Ok(LogGuard { writer })
}

/// The bytes a running logger has written, for a status report.
///
/// A free function rather than a method on the guard, because the daemon needs it from a thread that does not own the
/// guard — and the guard is what keeps the file open, not what owns the count.
#[must_use]
pub fn stats_of(guard: &LogGuard) -> Arc<super::stats::LogStats> {
    guard.writer.lock().stats()
}
