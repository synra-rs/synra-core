use synra_plugin_api::publisher::PluginTrust;

use super::Stage;

/// One check's outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    /// Which check.
    pub stage: Stage,
    /// What it concluded.
    pub verdict: Verdict,
    /// What was found, in a sentence.
    pub detail: String,
}

/// How a check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// It is fine.
    Pass,
    /// It will not work on this machine, but it is a valid package.
    ///
    /// Distinct from [`Self::Fail`] because the caller's next step differs: a warning is something to *tell the user*
    /// — this plugin's notification button will not work on this device — and a failure is something to refuse.
    Warn,
    /// The package may not be installed.
    Fail,
}

impl Verdict {
    /// A name, for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// What the pipeline concluded.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Every step that ran, in order.
    pub steps: Vec<Step>,
    /// The level of trust the publisher earned, when there was a signature.
    pub trust: Option<PluginTrust>,
    /// The publisher's fingerprint, for a prompt.
    pub fingerprint: Option<synra_plugin_api::publisher::Fingerprint>,
}

impl Report {
    /// Whether the package may be installed.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        self.steps.iter().all(|step| step.verdict != Verdict::Fail)
    }

    /// The first step that refused, which is the one a caller reports.
    #[must_use]
    pub fn refusal(&self) -> Option<&Step> {
        self.steps.iter().find(|step| step.verdict == Verdict::Fail)
    }

    /// The steps that warned, which are the things to tell a user.
    #[must_use]
    pub fn warnings(&self) -> Vec<&Step> {
        self.steps.iter().filter(|step| step.verdict == Verdict::Warn).collect()
    }

    /// The stage a report stopped at, for a metric label.
    #[must_use]
    pub fn stopped_at(&self) -> Option<Stage> {
        self.refusal().map(|step| step.stage)
    }

    /// A sentence for a log line or a status screen.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.refusal() {
            Some(step) => format!("refused at {}: {}", step.stage.as_str(), step.detail),
            None => {
                let warnings = self.warnings().len();
                if warnings == 0 {
                    format!("all {} checks passed", self.steps.len())
                }
                else {
                    format!("{} checks passed with {warnings} warning(s)", self.steps.len())
                }
            }
        }
    }
}
