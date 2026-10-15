//! Crash reports, and the safe-mode decision that follows from them.
//!
//! # A crash report is not telemetry
//!
//! It is a file on the user's own disk, written because the process is about to die and there was
//! information in it. Nothing uploads it. The start-up check reads it back and offers the user three
//! things: look at it, export a diagnostic bundle, or ignore it.
//!
//! # Safe mode is the point of the repeat count
//!
//! A plugin that crashes the host on activation makes the application unusable: the user cannot reach the
//! settings screen to disable it, because reaching the settings screen is what crashes. Counting crashes
//! in the same place and starting without plugins is the only way out that does not require the user to
//! find a config file.
//!
//! The count is per **location**, not global. Three unrelated crashes in three different places are three
//! bugs; three crashes on the same line is one bug that will happen again on the next start.
//!
//! # Writing must not panic
//!
//! The panic hook runs while the process is unwinding. Anything it does that can fail has to fail quietly:
//! a second panic inside the hook aborts the process, and the report — the only record of what happened —
//! is lost. Every error path here returns rather than panicking, and the hook ignores the result.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use synra_protocol::TraceId;

/// How long after a crash the report still counts as "the last run".
///
/// Five minutes, per the design document. A longer window would treat yesterday's crash as this morning's
/// and offer the user a prompt about something they already dealt with.
pub const RECENT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// How many crashes in one place trigger safe mode.
pub const SAFE_MODE_THRESHOLD: usize = 3;

/// How many reports are kept.
///
/// Bounded because a crash loop writes one per start, and an unbounded directory fills the disk in the
/// course of an afternoon.
pub const MAX_REPORTS: usize = 20;

/// The substring of the crash directory's path.
pub const CRASH_DIR: &str = "crash";

/// What went wrong, as far as the process could tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashReport {
    /// When the crash happened, in milliseconds since the epoch.
    pub at_ms: i64,
    /// The application's version.
    pub version: String,
    /// Where it happened, as `file:line:column`, when the panic carried a location.
    ///
    /// This is the key the repeat count is kept on. A report without one cannot contribute to safe mode,
    /// which is deliberate: an unknown location is not evidence that the same bug happened again.
    pub location: Option<String>,
    /// The panic message, when it was a string.
    pub message: Option<String>,
    /// The thread's name, when it had one.
    pub thread: Option<String>,
    /// A captured backtrace.
    pub backtrace: Option<String>,
    /// The trace in progress, when the panic happened inside one.
    ///
    /// Recorded so a maintainer can find the steps that led here in the log, rather than guessing from the
    /// timestamp.
    pub trace_id: Option<TraceId>,
}

impl CrashReport {
    /// Builds a report from what a panic hook can see.
    ///
    /// Takes the pieces rather than the `PanicHookInfo` so the type is testable without inducing a panic,
    /// and so a caller that catches a `JoinHandle` error can build one from a different source.
    #[must_use]
    pub fn new(
        at_ms: i64,
        version: impl Into<String>,
        location: Option<String>,
        message: Option<String>,
        thread: Option<String>,
        backtrace: Option<String>,
        trace_id: Option<TraceId>,
    ) -> Self {
        Self {
            at_ms,
            version: version.into(),
            location,
            message,
            thread,
            backtrace,
            trace_id,
        }
    }

    /// Whether this crash is recent enough to be about the run that just ended.
    #[must_use]
    pub fn is_recent(&self, now_ms: i64) -> bool {
        let elapsed = now_ms.saturating_sub(self.at_ms);
        if elapsed < 0 {
            // A report from the future means the clock moved backwards — a suspend, a manual change. Treating
            // it as old would hide a crash; treating it as fresh is the safe direction.
            return true;
        }
        elapsed <= i64::try_from(RECENT_WINDOW.as_millis()).unwrap_or(i64::MAX)
    }

    /// The key the repeat count is kept on.
    #[must_use]
    pub fn location_key(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// A one-line summary for the prompt.
    #[must_use]
    pub fn summary(&self) -> String {
        let where_at = self.location.as_deref().unwrap_or("unknown location");
        let what = self.message.as_deref().unwrap_or("no message");
        format!("{what} (at {where_at})")
    }
}

/// What the user is offered at start-up after a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupVerdict {
    /// Nothing recent. Start normally.
    Clean,
    /// A recent crash. Offer to show it, export a bundle, or ignore it.
    Crashed {
        /// The most recent report.
        latest: Box<CrashReport>,
        /// How many reports are recent.
        recent_count: usize,
    },
    /// The same place crashed too many times. Start without plugins.
    ///
    /// The one outcome that has to exist: a plugin that crashes on activation makes the settings screen
    /// unreachable, and this is the only way back to it that does not involve editing a file.
    SafeMode {
        /// The location that keeps crashing.
        location: String,
        /// How many times it crashed.
        count: usize,
        /// The most recent report, for the prompt.
        latest: Box<CrashReport>,
    },
}

impl StartupVerdict {
    /// Whether plugins should be loaded.
    #[must_use]
    pub const fn allows_plugins(&self) -> bool {
        !matches!(self, Self::SafeMode { .. })
    }

    /// Whether anything needs to be shown to the user.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        !matches!(self, Self::Clean)
    }

    /// A sentence for the prompt.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::Clean => "no recent crash".to_owned(),
            Self::Crashed { recent_count, latest } => format!(
                "the application exited unexpectedly {recent_count} time(s); last: {}",
                latest.summary()
            ),
            Self::SafeMode { location, count, .. } => format!(
                "it crashed {count} times at {location}; starting without plugins so this can be fixed"
            ),
        }
    }
}

/// Decides what to do at start-up from the reports on disk.
///
/// Pure, so the decision is testable without a filesystem and without crashing anything.
#[must_use]
pub fn startup_verdict(reports: &[CrashReport], now_ms: i64) -> StartupVerdict {
    let recent: Vec<&CrashReport> = reports.iter().filter(|r| r.is_recent(now_ms)).collect();
    let Some(latest) = recent.iter().max_by_key(|r| r.at_ms) else {
        return StartupVerdict::Clean;
    };

    // Counted per location, not in total. Three unrelated crashes in three places are three bugs; three on
    // one line is one bug that will happen again on the next start.
    let mut by_location: HashMap<&str, usize> = HashMap::new();
    for report in &recent {
        if let Some(location) = report.location_key() {
            *by_location.entry(location).or_insert(0) += 1;
        }
    }

    let worst = by_location
        .iter()
        .filter(|(_, count)| **count >= SAFE_MODE_THRESHOLD)
        .max_by_key(|(_, count)| **count);

    match worst {
        Some((location, count)) => StartupVerdict::SafeMode {
            location: (*location).to_owned(),
            count: *count,
            latest: Box::new((*latest).clone()),
        },
        None => StartupVerdict::Crashed {
            latest: Box::new((*latest).clone()),
            recent_count: recent.len(),
        },
    }
}

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

/// Installs the panic hook that writes a [`CrashReport`].
///
/// # ★ Why this exists, and what its absence meant
///
/// Every part of the crash pipeline was here — the report type, the store, the repeat count per location, the safe-mode
/// verdict, and a plugin-loading path that consults it — and **nothing ever wrote a report**. `set_hook` and `take_hook`
/// appeared nowhere in the workspace. So the chain was complete and dry: safe mode could not trigger, because the file
/// it counts was never created, and a user whose plugin crashed the host on activation would get the crash and nothing
/// else, every time.
///
/// # Why it chains rather than replaces
///
/// The previous hook is what prints `thread 'main' panicked at ...` and the backtrace. Replacing it would mean a build
/// with the crash hook installed panicked **silently** in a terminal, which is a worse failure than the one this is
/// meant to record. The report is written first and the previous hook runs afterwards, so a write that fails still
/// leaves the ordinary message.
///
/// # Why the version is a parameter
///
/// A report records which build crashed, and this crate does not know: `synra-observe` has its own version, and the
/// thing that crashed is the daemon or the application. Taking it from the caller is the only way to record the right
/// one — and it is not a `&'static str`, because the daemon reports the version it was built with rather than one
/// compiled into the observe layer.
///
/// # Errors
///
/// None. Everything that can fail inside the hook fails quietly: it runs while the process is unwinding, and a second
/// panic inside a panic hook aborts instead of unwinding — which would lose the report and the message together.
pub fn install_panic_hook(store: CrashStore, version: impl Into<String>) {
    let previous = std::panic::take_hook();
    let version = version.into();

    std::panic::set_hook(Box::new(move |info| {
        // ★ Built here rather than in a helper that returns a `Result`: there is no failure path worth propagating, and
        // a signature that could fail would invite a caller to handle it inside the hook.
        let report = report_from_panic(info, &version);
        // The result is dropped deliberately. The store's own documentation says the caller is a panic hook and is
        // expected to ignore it; a report that cannot be written must not become a second panic.
        let _ = store.write(&report);

        // The ordinary message still appears, after the report is safely on disk.
        previous(info);
    }));
}

/// Turns a panic into the report that gets written.
///
/// Split out from the hook so the extraction can be tested without installing a process-wide hook — a global hook is
/// shared by every test in a binary, and a test that installed one would change how the other tests in the same binary
/// report their own failures.
#[must_use]
fn report_from_panic(
    info: &std::panic::PanicHookInfo<'_>,
    version: &str,
) -> CrashReport {
    // `file:line:column`, which is the key the repeat count is kept on. A panic with no location cannot contribute to
    // safe mode — the store's own comment explains why: an unknown location is not evidence that the same bug happened
    // again.
    let location = info
        .location()
        .map(|at| format!("{}:{}:{}", at.file(), at.line(), at.column()));

    // `panic!("literal")` arrives as `&str` and `panic!("{formatted}")` as `String`; anything else is a payload the
    // caller chose, and saying so is better than a `Debug` rendering that could itself panic.
    let payload = info.payload();
    let message = if let Some(text) = payload.downcast_ref::<&str>() {
        Some((*text).to_owned())
    } else {
        payload.downcast_ref::<String>().cloned()
    };

    CrashReport::new(
        now_ms(),
        version,
        location,
        message,
        std::thread::current().name().map(str::to_owned),
        // ★ Only captured when the process was asked to capture one. `Backtrace::capture` returns a `Disabled` value
        // otherwise, and a `Disabled` backtrace stringifies to a sentence saying so — which is worth recording, because
        // a reader looking for frames should be told they were not collected rather than shown an empty section.
        Some(std::backtrace::Backtrace::capture().to_string()),
        None,
    )
}

/// The current time in milliseconds since the epoch.
///
/// A helper rather than a `SystemTime` so the report's field is a plain number: a report has to be readable
/// by a human in a text editor, and a serialised `SystemTime` is a struct of seconds and nanoseconds.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// Extracts the message from a panic payload.
///
/// `Box<dyn Any>` because that is what the hook offers: a `panic!` with a format string produces a
/// `String`, and `panic_any` can produce anything. Only the two shapes that carry readable text are
/// handled; anything else yields `None` rather than a `Debug` rendering that would be a pointer.
#[must_use]
pub fn panic_message(payload: &(dyn core::any::Any + Send)) -> Option<String> {
    if let Some(text) = payload.downcast_ref::<&'static str>() {
        return Some((*text).to_owned());
    }
    payload.downcast_ref::<String>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(at_ms: i64, location: Option<&str>) -> CrashReport {
        CrashReport::new(
            at_ms,
            "1.0.0",
            location.map(str::to_owned),
            Some("index out of bounds".to_owned()),
            Some("main".to_owned()),
            None,
            None,
        )
    }

    #[test]
    fn a_report_records_everything_a_hook_can_see() {
        let trace = TraceId::new();
        let report = CrashReport::new(
            1_700_000_000_000,
            "1.2.3",
            Some("src/kernel.rs:42:9".to_owned()),
            Some("boom".to_owned()),
            Some("sync".to_owned()),
            Some("0: backtrace".to_owned()),
            Some(trace),
        );

        assert_eq!(report.version, "1.2.3");
        assert_eq!(report.location_key(), Some("src/kernel.rs:42:9"));
        assert_eq!(report.trace_id, Some(trace));
        assert!(report.summary().contains("boom"));
        assert!(report.summary().contains("src/kernel.rs:42:9"));
    }

    #[test]
    fn a_report_without_a_location_still_summarises() {
        let report = report(1_000, None);
        assert_eq!(report.location_key(), None);
        assert!(report.summary().contains("unknown location"));
    }

    #[test]
    fn a_report_without_a_message_still_summarises() {
        let mut report = report(1_000, Some("a.rs:1:1"));
        report.message = None;
        assert!(report.summary().contains("no message"));
    }

    #[test]
    fn recency_is_bounded_by_the_window() {
        let now = 1_700_000_000_000;
        let window_ms = i64::try_from(RECENT_WINDOW.as_millis()).expect("fits");

        assert!(report(now, Some("a")).is_recent(now));
        assert!(report(now - window_ms, Some("a")).is_recent(now), "exactly at the window");
        assert!(!report(now - window_ms - 1, Some("a")).is_recent(now), "one past it");
        // Yesterday's crash must not be offered as this morning's.
        assert!(!report(now - 86_400_000, Some("a")).is_recent(now));
    }

    #[test]
    fn a_report_from_the_future_counts_as_recent() {
        // A clock that moved backwards — a suspend, a manual change — must not hide a crash. Treating a
        // future timestamp as old would do exactly that.
        let now = 1_000;
        assert!(report(now + 10_000_000, Some("a")).is_recent(now));
    }

    #[test]
    fn no_reports_means_a_clean_start() {
        assert_eq!(startup_verdict(&[], 1_000), StartupVerdict::Clean);
        assert!(!StartupVerdict::Clean.needs_attention());
        assert!(StartupVerdict::Clean.allows_plugins());
        assert_eq!(StartupVerdict::Clean.explain(), "no recent crash");
    }

    #[test]
    fn an_old_report_does_not_trigger_the_prompt() {
        // A prompt about something the user already dealt with is noise, and noise is what trains people to
        // dismiss prompts without reading them.
        let now = 1_700_000_000_000;
        let old = report(now - 86_400_000, Some("a.rs:1:1"));
        assert_eq!(startup_verdict(&[old], now), StartupVerdict::Clean);
    }

    #[test]
    fn one_recent_crash_is_reported_without_safe_mode() {
        let now = 1_700_000_000_000;
        let verdict = startup_verdict(&[report(now - 1_000, Some("a.rs:1:1"))], now);

        // Matched by reference, so the verdict can still be asked about after its contents are inspected.
        match &verdict {
            StartupVerdict::Crashed { latest, recent_count } => {
                assert_eq!(*recent_count, 1);
                assert_eq!(latest.location_key(), Some("a.rs:1:1"));
            }
            other => panic!("expected a crash prompt, got {other:?}"),
        }
        assert!(verdict.allows_plugins(), "one crash is not a reason to disable plugins");
        assert!(verdict.needs_attention());
    }

    #[test]
    fn the_same_place_crashing_three_times_enters_safe_mode() {
        // The scenario the whole mechanism exists for: a plugin that crashes on activation makes the
        // settings screen unreachable, and this is the only way back to it.
        let now = 1_700_000_000_000;
        let reports: Vec<CrashReport> = (0..SAFE_MODE_THRESHOLD)
            .map(|index| report(now - 1_000 - index as i64, Some("plugin.rs:99:1")))
            .collect();

        let verdict = startup_verdict(&reports, now);
        match &verdict {
            StartupVerdict::SafeMode { location, count, .. } => {
                assert_eq!(location, "plugin.rs:99:1");
                assert_eq!(*count, SAFE_MODE_THRESHOLD);
            }
            other => panic!("expected safe mode, got {other:?}"),
        }
        assert!(!verdict.allows_plugins(), "safe mode exists to start without plugins");
        assert!(verdict.explain().contains("without plugins"));
    }

    #[test]
    fn unrelated_crashes_do_not_add_up_to_safe_mode() {
        // Three bugs in three places are three bugs. Counting them together would disable plugins for a user
        // who has no plugin problem at all.
        let now = 1_700_000_000_000;
        let reports = vec![
            report(now - 1_000, Some("a.rs:1:1")),
            report(now - 900, Some("b.rs:2:2")),
            report(now - 800, Some("c.rs:3:3")),
        ];

        match startup_verdict(&reports, now) {
            StartupVerdict::Crashed { recent_count, .. } => assert_eq!(recent_count, 3),
            other => panic!("expected a plain crash prompt, got {other:?}"),
        }
    }

    #[test]
    fn a_report_without_a_location_cannot_contribute_to_safe_mode() {
        // An unknown location is not evidence that the same bug happened again, and treating it as such
        // would disable plugins on the strength of an unrelated series.
        let now = 1_700_000_000_000;
        let reports: Vec<CrashReport> = (0..5).map(|i| report(now - i as i64, None)).collect();

        match startup_verdict(&reports, now) {
            StartupVerdict::Crashed { recent_count, .. } => assert_eq!(recent_count, 5),
            other => panic!("expected a plain crash prompt, got {other:?}"),
        }
    }

    #[test]
    fn only_recent_crashes_are_counted_toward_safe_mode() {
        // Two from yesterday plus one today is not three in a row: the plugin may have been fixed since.
        let now = 1_700_000_000_000;
        let reports = vec![
            report(now - 86_400_000, Some("plugin.rs:99:1")),
            report(now - 86_300_000, Some("plugin.rs:99:1")),
            report(now - 1_000, Some("plugin.rs:99:1")),
        ];

        match startup_verdict(&reports, now) {
            StartupVerdict::Crashed { recent_count, .. } => assert_eq!(recent_count, 1),
            other => panic!("expected a plain crash prompt, got {other:?}"),
        }
    }

    #[test]
    fn the_latest_report_is_the_one_shown() {
        let now = 1_700_000_000_000;
        let reports = vec![
            report(now - 5_000, Some("old.rs:1:1")),
            report(now - 1_000, Some("new.rs:9:9")),
            report(now - 3_000, Some("middle.rs:5:5")),
        ];

        match startup_verdict(&reports, now) {
            StartupVerdict::Crashed { latest, .. } => {
                assert_eq!(latest.location_key(), Some("new.rs:9:9"));
            }
            other => panic!("expected a crash prompt, got {other:?}"),
        }
    }

    #[test]
    fn the_location_that_crashed_most_decides_safe_mode() {
        // With two locations both over the threshold, the one that crashed more is the one named, because it
        // is the one to disable first.
        let now = 1_700_000_000_000;
        let reports = vec![
            report(now - 100, Some("a.rs:1:1")),
            report(now - 200, Some("a.rs:1:1")),
            report(now - 300, Some("a.rs:1:1")),
            report(now - 400, Some("b.rs:2:2")),
            report(now - 500, Some("b.rs:2:2")),
            report(now - 600, Some("b.rs:2:2")),
            report(now - 700, Some("b.rs:2:2")),
        ];

        match startup_verdict(&reports, now) {
            StartupVerdict::SafeMode { location, count, .. } => {
                assert_eq!(location, "b.rs:2:2");
                assert_eq!(count, 4);
            }
            other => panic!("expected safe mode, got {other:?}"),
        }
    }

    #[test]
    fn a_report_round_trips_through_json() {
        // The report is written by the panic hook and read by the next start, so the shape has to survive
        // both, and the field names are camelCase like the rest of the project's data.
        let report = report(1_700_000_000_000, Some("a.rs:1:1"));
        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.contains("\"atMs\""), "{json}");
        assert!(!json.contains("at_ms"), "{json}");

        let back: CrashReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }

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

    #[test]
    fn a_panic_message_is_read_from_both_shapes() {
        // `panic!("literal")` produces a `&str` and `panic!("{}", x)` produces a `String`; the hook offers
        // both through the same `Box<dyn Any>`.
        let literal: &'static str = "a literal panic";
        assert_eq!(panic_message(&literal), Some("a literal panic".to_owned()));

        let formatted = String::from("a formatted panic");
        assert_eq!(panic_message(&formatted), Some("a formatted panic".to_owned()));

        // Something else entirely yields nothing rather than a pointer rendering.
        let number: u32 = 42;
        assert_eq!(panic_message(&number), None);
    }

    #[test]
    fn the_clock_helper_returns_a_plausible_timestamp() {
        // After 2020 and before 2100, so a broken clock is caught rather than silently written into reports.
        let now = now_ms();
        assert!(now > 1_577_836_800_000, "{now}");
        assert!(now < 4_102_444_800_000, "{now}");
    }

    #[test]
    fn a_verdict_explains_itself_for_every_case() {
        let now = 1_700_000_000_000;
        let crashed = startup_verdict(&[report(now - 1, Some("a.rs:1:1"))], now);
        assert!(crashed.explain().contains("1 time"));

        let reports: Vec<CrashReport> = (0..3).map(|i| report(now - i as i64, Some("a.rs:1:1"))).collect();
        let safe = startup_verdict(&reports, now);
        assert!(safe.explain().contains("a.rs:1:1"));
        assert!(safe.explain().contains('3'));
    }

    /// A per-test suffix, so two tests running at once do not share a temporary directory.
    ///
    /// A counter rather than a random value: a test failure has to be reproducible, and a directory named
    /// after a counter is one a developer can go and look at.
    pub(super) fn test_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_report() -> impl Strategy<Value = CrashReport> {
        (
            0i64..1_000_000,
            proptest::option::of("[a-z]{1,8}\\.rs:[0-9]{1,4}:[0-9]{1,3}"),
            proptest::option::of("[a-zA-Z ]{1,30}"),
        )
            .prop_map(|(at_ms, location, message)| {
                CrashReport::new(at_ms, "1.0.0", location, message, None, None, None)
            })
    }

    proptest! {
        /// Safe mode is entered exactly when one location has crashed at least the threshold number of
        /// times, counting only recent crashes. Getting this wrong in either direction is bad in a
        /// different way: too eager disables plugins for unrelated bugs, too lax leaves a user unable to
        /// reach the settings screen.
        #[test]
        fn safe_mode_depends_only_on_repeated_recent_locations(
            reports in proptest::collection::vec(arbitrary_report(), 0..12),
            now in 1_000_000i64..2_000_000,
        ) {
            let verdict = startup_verdict(&reports, now);

            let recent: Vec<&CrashReport> = reports.iter().filter(|r| r.is_recent(now)).collect();
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for report in &recent {
                if let Some(location) = report.location_key() {
                    *counts.entry(location).or_insert(0) += 1;
                }
            }
            let worst = counts.values().copied().max().unwrap_or(0);

            match verdict {
                StartupVerdict::Clean => {
                    prop_assert!(recent.is_empty());
                }
                StartupVerdict::Crashed { recent_count, .. } => {
                    prop_assert!(!recent.is_empty());
                    prop_assert_eq!(recent_count, recent.len());
                    prop_assert!(worst < SAFE_MODE_THRESHOLD);
                }
                StartupVerdict::SafeMode { count, .. } => {
                    prop_assert!(count >= SAFE_MODE_THRESHOLD);
                    prop_assert!(worst >= SAFE_MODE_THRESHOLD);
                }
            }
        }

        /// Recency is monotonic in the timestamp: if a crash is recent, a later one is too. A window that
        /// behaved otherwise would offer a prompt for something older than something it ignored.
        #[test]
        fn recency_is_monotonic(
            base in 0i64..1_000_000,
            offset_a in 0i64..500_000,
            offset_b in 0i64..500_000,
        ) {
            let now = 2_000_000;
            let (earlier, later) = if offset_a <= offset_b {
                (base + offset_a, base + offset_b)
            }
            else {
                (base + offset_b, base + offset_a)
            };

            let earlier_report = CrashReport::new(earlier, "1", Some("a".into()), None, None, None, None);
            let later_report = CrashReport::new(later, "1", Some("a".into()), None, None, None, None);
            if earlier_report.is_recent(now) {
                prop_assert!(later_report.is_recent(now));
            }
        }

        /// A report survives a trip through the wire format with every field intact. The report is written by
        /// a dying process and read by the next start, so anything lost in between is lost for good.
        #[test]
        fn reports_round_trip(report in arbitrary_report()) {
            let json = serde_json::to_string(&report).expect("serialises");
            let back: CrashReport = serde_json::from_str(&json).expect("deserialises");
            prop_assert_eq!(back, report);
        }
    }
}
