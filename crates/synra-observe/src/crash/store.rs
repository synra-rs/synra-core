//! Persistent crash report storage and pruning.

use std::path::{Path, PathBuf};

use super::{CRASH_DIR, CrashReport, MAX_REPORTS, StartupVerdict, startup_verdict};

/// Where crash reports live, and how to read and write them.
#[derive(Debug, Clone)]
pub struct CrashStore {
    directory: PathBuf,
}

impl CrashStore {
    /// A store under `log_dir/crash`.
    #[must_use]
    pub fn new(log_dir: &Path) -> Self {
        Self { directory: log_dir.join(CRASH_DIR) }
    }

    /// A store at an explicit directory, for a test.
    #[must_use]
    pub const fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// The directory reports are written to.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Writes a report, returning the file it went to.
    ///
    /// # Errors
    ///
    /// An I/O error if the directory or file cannot be written. The caller is a panic hook and is expected
    /// to ignore it: a report that cannot be written must not become a second panic.
    pub fn write(&self, report: &CrashReport) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.directory)?;
        let json = serde_json::to_vec_pretty(report).map_err(std::io::Error::other)?;

        // ★ The name must be unique even when two crashes land in the same millisecond.
        //
        // It was `crash-{at_ms}.json`, and a crash loop that panics three times inside one millisecond — which is what
        // a tight activation loop does, and what this crate's own integration test does — wrote **one** file instead of
        // three. The consequence is not lost paperwork: [`startup_verdict`] counts reports to decide safe mode, so the
        // count came up short and the daemon started the crashing plugin again on the next run. The mechanism that
        // exists to stop a crash loop was defeated by a filename.
        //
        // `create_new` rather than "check whether it exists, then write": a check followed by an action is two steps
        // another thread can interleave, and the hook runs on whichever thread panicked — so two threads crashing at
        // once is a real case rather than a hypothetical one. `create_new` fails atomically if the name is taken, which
        // is what makes the loop below correct rather than merely usually correct.
        let mut suffix = 0u32;
        loop {
            let path = if suffix == 0 {
                self.directory.join(format!("crash-{}.json", report.at_ms))
            } else {
                self.directory.join(format!("crash-{}-{suffix}.json", report.at_ms))
            };

            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(&json)?;
                    self.prune();
                    return Ok(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Four billion reports in one millisecond is not a situation to invent a policy for, but it is a
                    // situation the loop would otherwise spin in, so it ends in an error like any other write failure.
                    suffix = suffix.checked_add(1).ok_or_else(|| {
                        std::io::Error::other("too many crash reports share one millisecond")
                    })?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Reads every report, oldest first.
    ///
    /// A file that cannot be read or parsed is skipped rather than failing the whole read: a truncated
    /// report is exactly what a crash during a write produces, and it must not stop the application from
    /// noticing the other nine.
    #[must_use]
    pub fn read_all(&self) -> Vec<CrashReport> {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return Vec::new();
        };

        let mut reports: Vec<CrashReport> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .filter_map(|entry| std::fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<CrashReport>(&bytes).ok())
            .collect();
        reports.sort_by_key(|report| report.at_ms);
        reports
    }

    /// What to do at start-up, read from disk.
    #[must_use]
    pub fn verdict(&self, now_ms: i64) -> StartupVerdict {
        startup_verdict(&self.read_all(), now_ms)
    }

    /// How many reports are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read_all().len()
    }

    /// Whether there are no reports.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read_all().is_empty()
    }

    /// Deletes every report, for the user's "ignore" action.
    ///
    /// # Errors
    ///
    /// An I/O error if a file cannot be removed.
    pub fn clear(&self) -> std::io::Result<()> {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return Ok(());
        };
        for entry in entries.filter_map(Result::ok) {
            let _ = std::fs::remove_file(entry.path());
        }
        Ok(())
    }

    /// Drops the oldest reports past [`MAX_REPORTS`].
    ///
    /// Best effort, and deliberately so: this runs inside the panic hook's write path, where a failure must
    /// not propagate. A crash loop that outran the prune would fill the disk with reports, which is why the
    /// cap exists at all.
    fn prune(&self) {
        let mut paths: Vec<PathBuf> = match std::fs::read_dir(&self.directory) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect(),
            Err(_) => return,
        };
        if paths.len() <= MAX_REPORTS {
            return;
        }
        // The file names carry the timestamp, so sorting by name sorts by age.
        paths.sort();
        let excess = paths.len() - MAX_REPORTS;
        for path in paths.into_iter().take(excess) {
            let _ = std::fs::remove_file(path);
        }
    }
}


