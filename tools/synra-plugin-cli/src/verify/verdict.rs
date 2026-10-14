//! What the check decided, why, and the report that adds the reasons up.

use serde::Serialize;
/// How a finding went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    /// It is fine.
    Pass,
    /// It will bite later.
    Warn,
    /// The plugin will not work.
    Fail,
}

impl Verdict {
    /// The word a person reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    /// Whether it stops the plugin working.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Fail)
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// A stable machine-readable name, such as `manifest`.
    pub name: String,
    /// How it went.
    pub verdict: Verdict,
    /// What was found, in a sentence.
    pub detail: String,
    /// What to do about it, when there is something to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl Finding {
    /// A passing check.
    #[must_use]
    pub fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            verdict: Verdict::Pass,
            detail: detail.into(),
            suggestion: None,
        }
    }

    /// A check that will bite later.
    #[must_use]
    pub fn warn(name: &str, detail: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            verdict: Verdict::Warn,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// A check that found something broken.
    #[must_use]
    pub fn fail(name: &str, detail: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            verdict: Verdict::Fail,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }
}

/// Everything `verify` concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    /// The plugin, when the manifest parsed far enough to say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    /// The version, likewise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Every finding, in the order the checks ran.
    pub findings: Vec<Finding>,
}

impl VerifyReport {
    /// How many findings reported a failure.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.findings.iter().filter(|finding| finding.verdict.is_failure()).count()
    }

    /// How many reported something that will bite later.
    #[must_use]
    pub fn warnings(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.verdict == Verdict::Warn)
            .count()
    }

    /// Whether the plugin will work.
    ///
    /// Failures only. A warning is something that will bite later, and a plugin that warns still installs.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures() == 0
    }

    /// What the process should exit with.
    ///
    /// `0` when nothing failed, `1` when something did, so a build script branches on it. It is a judgement rather
    /// than a formality: a `verify` that always exited zero would be a check CI could not use.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.is_ok() { 0 } else { 1 }
    }

    /// The lines a person reads.
    ///
    /// Returned rather than printed, so a test asserts the text and the caller decides where it goes.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match (&self.plugin_id, &self.version) {
            (Some(id), Some(version)) => lines.push(format!("{id} {version}")),
            _ => lines.push("the manifest could not be read".to_owned()),
        }

        for finding in &self.findings {
            lines.push(format!(
                "{:<4}  {:<22} {}",
                finding.verdict.as_str(),
                finding.name,
                finding.detail
            ));
            if let Some(suggestion) = &finding.suggestion {
                lines.push(format!("      {:<22} {suggestion}", ""));
            }
        }

        let passed = self.findings.len() - self.failures() - self.warnings();
        lines.push(format!(
            "{passed} ok, {} warn, {} fail",
            self.warnings(),
            self.failures()
        ));
        lines
    }
}
