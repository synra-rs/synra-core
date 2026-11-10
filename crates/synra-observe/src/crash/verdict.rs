use std::collections::HashMap;

use super::CrashReport;

/// How many crashes in one place trigger safe mode.
pub const SAFE_MODE_THRESHOLD: usize = 3;

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
