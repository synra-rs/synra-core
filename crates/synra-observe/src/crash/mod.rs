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

mod hook;
mod report;
mod store;
mod verdict;

pub use hook::{install_panic_hook, now_ms, panic_message};
pub use report::{CrashReport, RECENT_WINDOW};
pub use store::CrashStore;
pub use verdict::{SAFE_MODE_THRESHOLD, StartupVerdict, startup_verdict};

/// How many reports are kept.
///
/// Bounded because a crash loop writes one per start, and an unbounded directory fills the disk in the
/// course of an afternoon.
pub const MAX_REPORTS: usize = 20;

/// The substring of the crash directory's path.
pub const CRASH_DIR: &str = "crash";

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

