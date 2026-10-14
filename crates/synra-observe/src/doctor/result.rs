//! One check's outcome, and the report a whole run accumulates.

use serde::{Deserialize, Serialize};

/// How the check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ProbeStatus {
    /// Nothing to do.
    Ok,
    /// It works, and it will probably bite later.
    Warn,
    /// Something will not work.
    Fail,
}

impl ProbeStatus {
    /// The name used in the interface and in a diagnostic bundle.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    /// Whether this deserves the user's attention.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

impl core::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    /// A stable machine-readable name, such as `tcp_port_available`.
    ///
    /// Stable because it is what a support conversation quotes and what a test asserts on; the `detail` text
    /// is for humans and will be reworded.
    pub name: String,
    /// How it went.
    pub status: ProbeStatus,
    /// What was found, in a sentence.
    pub detail: String,
    /// What to do about it, when there is something to do.
    ///
    /// Shown next to the result. A probe that reports a problem without a suggestion has moved the work onto
    /// the user without giving them the means to do it.
    pub suggestion: Option<String>,
}

impl ProbeResult {
    /// A passing check.
    #[must_use]
    pub fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { name: name.into(), status: ProbeStatus::Ok, detail: detail.into(), suggestion: None }
    }

    /// A check that works but will bite later.
    #[must_use]
    pub fn warn(
        name: impl Into<String>,
        detail: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: ProbeStatus::Warn,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// A check that found something broken.
    #[must_use]
    pub fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: ProbeStatus::Fail,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// A check that could not reach a conclusion.
    ///
    /// Reported as a warning rather than a failure, because `Fail` claims the feature is broken and "could not
    /// tell" is a different claim.
    #[must_use]
    pub fn unknown(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ProbeStatus::Warn,
            detail: detail.into(),
            suggestion: Some("include this report when asking for help".to_owned()),
        }
    }

    /// The probe names, for the summary line.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.name
    }
}

/// A whole run's results.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProbeReport {
    /// Every result, in the order the probes ran.
    pub results: Vec<ProbeResult>,
}

impl ProbeReport {
    /// An empty report.
    #[must_use]
    pub const fn new() -> Self {
        Self { results: Vec::new() }
    }

    /// Adds a result.
    pub fn push(&mut self, result: ProbeResult) {
        self.results.push(result);
    }

    /// The worst status in the report.
    ///
    /// What the summary badge shows: one failure among ten passes is a failing report.
    #[must_use]
    pub fn worst(&self) -> ProbeStatus {
        self.results
            .iter()
            .map(|result| result.status)
            .max()
            .unwrap_or(ProbeStatus::Ok)
    }

    /// Whether anything needs attention.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.results.iter().any(|result| result.status.needs_attention())
    }

    /// How many results have each status.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for result in &self.results {
            match result.status {
                ProbeStatus::Ok => ok += 1,
                ProbeStatus::Warn => warn += 1,
                ProbeStatus::Fail => fail += 1,
            }
        }
        (ok, warn, fail)
    }

    /// A one-line summary for the settings screen.
    #[must_use]
    pub fn summarise(&self) -> String {
        let (ok, warn, fail) = self.counts();
        if fail > 0 {
            return format!("{fail} problem(s), {warn} warning(s), {ok} ok");
        }
        if warn > 0 {
            return format!("{warn} warning(s), {ok} ok");
        }
        format!("all {ok} checks passed")
    }

    /// Only the results that need attention.
    #[must_use]
    pub fn problems(&self) -> Vec<&ProbeResult> {
        self.results
            .iter()
            .filter(|result| result.status.needs_attention())
            .collect()
    }

    /// The result for a probe, by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ProbeResult> {
        self.results.iter().find(|result| result.name == name)
    }
}
