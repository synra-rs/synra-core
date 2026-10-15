//! The file the log is written to, and how it is rotated.
//!
//! # Why rotation is here and not in the `tracing` subscriber
//!
//! Because `tracing-appender` is not a dependency, and adding one for a rename would be a poor trade: rotation is
//! `rename` and a counter, and this way the policy — how large a file may grow and how many are kept — is a number in
//! the code rather than a feature flag nobody reads.
//!
//! # Why the newest file keeps the plain name
//!
//! Because the reader finds the log by **modification time**, not by name (`newest_file` in the daemon's
//! `runtime/reports.rs`). Naming the active file `synra.log` and the older ones `synra.log.1`, `.2` means the file a
//! reader opens by hand is also the one being written — a log called `synra.log.7` that happens to be newest would be a
//! log nobody finds.
//!
//! # Why a write never fails on rotation
//!
//! A log that stops being written because it could not be rotated is worse than a log that grew a little past its
//! limit. Every rotation error is swallowed and the write continues to the file that is already open: the alternative is
//! a process that loses its diagnostics exactly when something has gone wrong enough to fill a log.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

/// The name of the file being written.
pub const LOG_FILE_NAME: &str = "synra.log";

/// How large the active file may grow before it is rotated.
///
/// Eight megabytes: large enough that a normal session never rotates, small enough that a crash loop does not fill a
/// disk before anyone notices. The cap on how many are kept is what actually bounds the space.
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// How many rotated files are kept beside the active one.
///
/// Seven, so a week of daily crashes is still on disk. With the cap above that is at most 64 MiB per installation, which
/// is a number a person can be told.
pub const DEFAULT_KEEP: usize = 7;

/// A file that rotates itself once it grows past a limit.
pub struct RotatingFile {
    /// The directory the log lives in.
    directory: PathBuf,
    /// The size at which the active file is rotated.
    max_bytes: u64,
    /// How many rotated files to keep.
    keep: usize,
    /// The open file, absent only when it could not be opened at all.
    open: Option<File>,
    /// How many bytes have been written to the open file.
    ///
    /// Kept rather than asked of the filesystem on every write: `metadata()` is a syscall, and this is on the path of
    /// every log line. The initial value comes from the file's length, so a restart does not reset the count and
    /// immediately rotate a file that is already full.
    written: u64,
}

impl RotatingFile {
    /// Opens the log in a directory, creating it if needed.
    ///
    /// # Errors
    ///
    /// An I/O error when the directory cannot be created or the file cannot be opened. The caller decides what that
    /// means — a host that cannot log is not necessarily a host that should refuse to start.
    pub fn open(directory: impl Into<PathBuf>, max_bytes: u64, keep: usize) -> io::Result<Self> {
        let directory = directory.into();
        std::fs::create_dir_all(&directory)?;

        let path = directory.join(LOG_FILE_NAME);
        let open = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = open.metadata().map(|meta| meta.len()).unwrap_or(0);

        Ok(Self { directory, max_bytes, keep, open: Some(open), written })
    }

    /// The file being written.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.directory.join(LOG_FILE_NAME)
    }

    /// How many rotated files are kept.
    #[must_use]
    pub const fn keep(&self) -> usize {
        self.keep
    }

    /// Shifts the active file aside and starts a new one.
    ///
    /// Best effort by design: see the module comment. A failure leaves the existing file open and the caller writing to
    /// it, which is the behaviour that keeps diagnostics available.
    fn rotate(&mut self) {
        // Dropped first, so the rename is not of an open handle on a platform that refuses that.
        self.open = None;

        // From the oldest to the newest, so nothing is overwritten before it has been moved. The last kept file is
        // removed rather than shifted, which is what bounds the space.
        let oldest = self.directory.join(format!("{LOG_FILE_NAME}.{}", self.keep));
        let _ = std::fs::remove_file(&oldest);

        for index in (1..self.keep).rev() {
            let from = self.directory.join(format!("{LOG_FILE_NAME}.{index}"));
            let to = self.directory.join(format!("{LOG_FILE_NAME}.{}", index + 1));
            // Absent is the ordinary case for a young installation, so a failure here is not worth reporting.
            let _ = std::fs::rename(&from, &to);
        }

        let active = self.path();
        let _ = std::fs::rename(&active, self.directory.join(format!("{LOG_FILE_NAME}.1")));

        self.open = OpenOptions::new().create(true).append(true).open(&active).ok();
        self.written = 0;
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // ★ `self.written > 0` is the part worth stating: a single line larger than the limit would otherwise rotate
        // before every write and leave a directory of one-line files. Rotating only a file that already has content
        // means an oversized line goes to a file of its own and the next write starts the rotation.
        let would_exceed = self.max_bytes > 0
            && self.written > 0
            && self.written.saturating_add(buf.len() as u64) > self.max_bytes;
        if would_exceed {
            self.rotate();
        }

        let Some(file) = self.open.as_mut() else {
            return Ok(buf.len());
        };
        let written = file.write(buf)?;
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.open.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl core::fmt::Debug for RotatingFile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RotatingFile")
            .field("path", &self.path())
            .field("written", &self.written)
            .field("max_bytes", &self.max_bytes)
            .field("keep", &self.keep)
            .finish()
    }
}
