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
    /// What is being written, and the window a raise lasts for.
    ///
    /// Held here because the guard is what `init` hands back and what a caller keeps for the life of the process — the
    /// daemon shares this with the thread that answers `synra logs --verbose`.
    verbosity: Arc<super::verbosity::Verbosity>,
}

impl LogGuard {
    /// The runtime verbosity, for a caller that wants to raise it.
    ///
    /// ★ This is what makes `--verbose` mean something. Raising it here changes what the subscriber writes from the
    /// next event onwards, and the raise lapses after [`VERBOSE_WINDOW`](super::verbosity::VERBOSE_WINDOW) so a
    /// forgotten flag does not leave a debug log running for a week.
    #[must_use]
    pub fn verbosity(&self) -> Arc<super::verbosity::Verbosity> {
        Arc::clone(&self.verbosity)
    }
}

impl std::fmt::Debug for LogGuard {
    /// Renders as the writer's own `Debug`, which names the file.
    ///
    /// ★ Not derived, because the guard holds an `Arc<Mutex<RedactingWriter<RotatingFile>>>` and a derive would render a
    /// lock rather than the thing a reader wants to know: which file is being written. A shell that keeps this beside its
    /// other state needs `Debug` — `AppState` derives it — and "logging is on, here" is the useful rendering.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("LogGuard").field(&self.writer.lock()).finish()
    }
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

/// Raises what is written, at runtime, for a bounded window.
///
/// # ★ Why the level cannot simply be a constant
///
/// `with_max_level` fixes the level when the subscriber is built, and `tracing` allows one global subscriber per
/// process — so a level chosen at start-up is the level for the life of the daemon. That made `synra logs --verbose`
/// and `--trace` **promises with nothing behind them**: the CLI asked for debug lines, the file had none because
/// nothing ever wrote any, and the command quietly showed the same lines as the default.
///
/// So the decision moves to the moment each event is considered. `Verbosity` already held the rule — a configured
/// level, an override, and a window after which the override lapses — and had no production caller; this is what gives
/// it one. The window matters as much as the raise: an override that never lapses is a debug log left on by accident,
/// which is how a log file fills a disk on a machine nobody is watching.
#[derive(Clone)]
struct DynamicLevel(Arc<super::verbosity::Verbosity>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for DynamicLevel {
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        // `LevelFilter`'s own ordering, so this cannot drift from the enum's: `Info >= Debug` is false, `Trace >=
        // Debug` is true.
        self.0.effective().to_tracing() >= *metadata.level()
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
    let verbosity = Arc::new(super::verbosity::Verbosity::new(config.level));

    use tracing_subscriber::layer::SubscriberExt as _;
    let subscriber = tracing_subscriber::registry()
        // The gate. It is a layer rather than a constant on the writer because the answer has to be able to change
        // between two events, and this is the only place `tracing` asks.
        .with(DynamicLevel(Arc::clone(&verbosity)))
        .with(
            tracing_subscriber::fmt::layer()
                // ★ The writer is where redaction happens, which is the point: a field named `token` never reaches the
                // disk, and the policy is applied on the way out rather than by every call site remembering to be
                // careful.
                .with_writer(SharedWriter(Arc::clone(&writer)))
                // The ANSI escapes a terminal would interpret become noise in a file that is read back and filtered as
                // text.
                .with_ansi(false),
        );

    use tracing_subscriber::util::SubscriberInitExt;
    subscriber.try_init().map_err(|_| LogError::AlreadyInstalled)?;

    Ok(LogGuard { writer, verbosity })
}

/// The bytes a running logger has written, for a status report.
///
/// A free function rather than a method on the guard, because the daemon needs it from a thread that does not own the
/// guard — and the guard is what keeps the file open, not what owns the count.
#[must_use]
pub fn stats_of(guard: &LogGuard) -> Arc<super::stats::LogStats> {
    guard.writer.lock().stats()
}
