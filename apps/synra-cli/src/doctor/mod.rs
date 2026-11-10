//! The checks a user runs when something is wrong, as a report rather than as printed text.
//!
//! # Why this is not a `println!`
//!
//! `synra doctor` is the command a user runs when the application is misbehaving, which makes its output the thing a
//! support conversation is built on. Formatting it here rather than in `main` means the *report* is a value: it can be
//! asserted about, turned into JSON for a script, and written into a diagnostic bundle — and the three views cannot
//! disagree because there is one report behind them.
//!
//! # A warning is not a failure, and the exit code says so
//!
//! [`ProbeStatus`] has three answers, and the middle one is the one that matters here. A probe that warns found
//! something that will bite later — low disk space, a firewall that may block discovery — and a machine that warns
//! can still run the kernel. Collapsing a warning into a failure would make `doctor` refuse to proceed on machines
//! that have been working all along, and collapsing it into a pass would hide the thing the user ran `doctor` to
//! find.
//!
//! So [`DoctorReport::is_healthy`] counts failures only, and the exit code follows it. A script checking whether the
//! machine is *usable* branches on that; a script that wants to see warnings reads them from the output.
//!
//! # The suggestion is part of the line
//!
//! A probe that reports a problem without saying what to do about it has moved the work onto the user without giving
//! them the means to do it. The suggestion is on a separate line under its probe rather than appended, because a long
//! detail plus a long suggestion on one line is a line nobody reads to the end.

use std::path::Path;

use serde::Serialize;
use synra_observe::doctor::{HostFacts, ProbeReport, ProbeStatus, ProbeTargets, run_probes};

/// What a `doctor` run concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    /// Every probe, in the order they ran.
    pub probes: Vec<ProbeLine>,
    /// How many reported a problem that stops the kernel working.
    pub failed: usize,
    /// How many reported something that will bite later.
    pub warned: usize,
    /// The host the probes ran against, so a reader knows what machine the report describes.
    pub host: HostSummary,
}

/// One probe's result, flattened for a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeLine {
    /// Its stable machine-readable name.
    pub name: String,
    /// How it went.
    pub status: ProbeStatus,
    /// What it found, in a sentence.
    pub detail: String,
    /// What to do about it, when there is something to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

/// The parts of the host a reader needs to interpret the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSummary {
    /// The operating system, from the build rather than from a probe.
    ///
    /// Known at compile time, so it is reported even on a machine where every probe failed — which is exactly the
    /// machine whose report somebody is reading.
    pub platform: String,
    /// The kernel's version.
    pub kernel_version: String,
    /// Where the probes looked.
    pub data_dir: String,
}

impl DoctorReport {
    /// Runs every probe.
    ///
    /// The targets name the directories and ports to check, including `data_dir`, so a run against a directory the
    /// user cannot write says that rather than reporting a kernel failure it cannot actually know about.
    #[must_use]
    pub fn run(targets: &ProbeTargets, host: &HostFacts) -> Self {
        let raw = run_probes(targets, host);
        Self::from_probe_report(&raw, &targets.data_dir)
    }

    /// Wraps a probe report.
    ///
    /// Split out so a test can build a report without running probes — the probes touch the network, the filesystem
    /// and the clock, and a test that ran them would be a test of the machine rather than of the report.
    #[must_use]
    pub fn from_probe_report(raw: &ProbeReport, data_dir: &Path) -> Self {
        let probes: Vec<ProbeLine> = raw
            .results
            .iter()
            .map(|result| ProbeLine {
                name: result.name.clone(),
                status: result.status,
                detail: result.detail.clone(),
                suggestion: result.suggestion.clone(),
            })
            .collect();

        Self {
            failed: probes.iter().filter(|line| line.status == ProbeStatus::Fail).count(),
            warned: probes.iter().filter(|line| line.status == ProbeStatus::Warn).count(),
            probes,
            host: HostSummary {
                platform: std::env::consts::OS.to_owned(),
                kernel_version: env!("CARGO_PKG_VERSION").to_owned(),
                data_dir: data_dir.display().to_string(),
            },
        }
    }

    /// Whether the machine can run the kernel.
    ///
    /// Failures only. A warning is something that will bite later, and a machine that warns can still run — so
    /// treating it as unhealthy would make `doctor` refuse to proceed on machines that have been working all along.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.failed == 0
    }

    /// What the process should exit with.
    ///
    /// `0` when nothing failed and `1` when something did, so a script can branch on it. It is a judgement rather
    /// than a formality: a `doctor` that always exited zero would be a check a script could not use.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        if self.is_healthy() { 0 } else { 1 }
    }

    /// Only the probes that reported a failure, for `--failures-only`.
    #[must_use]
    pub fn failures(&self) -> Vec<&ProbeLine> {
        self.probes.iter().filter(|line| line.status == ProbeStatus::Fail).collect()
    }

    /// The lines a user sees, as a vector rather than printed.
    ///
    /// Returned rather than written so the caller decides where they go — and so a test asserts the text a user reads
    /// instead of capturing a stream.
    #[must_use]
    pub fn lines(&self, failures_only: bool) -> Vec<String> {
        let mut lines = vec![format!(
            "synra {} on {} — probes looked in {}",
            self.host.kernel_version, self.host.platform, self.host.data_dir
        )];

        let shown: Vec<&ProbeLine> = if failures_only {
            self.failures()
        }
        else {
            self.probes.iter().collect()
        };

        if shown.is_empty() {
            // A run with `--failures-only` on a healthy machine has nothing to show, and saying so is the difference
            // between "nothing is wrong" and "the command did not run".
            lines.push("no failures".to_owned());
            return lines;
        }

        for line in shown {
            // The marker is the leading character so a user scanning the left margin sees the status without reading
            // the words. Four columns wide, so the names line up.
            let marker = match line.status {
                ProbeStatus::Ok => "ok  ",
                ProbeStatus::Warn => "warn",
                ProbeStatus::Fail => "FAIL",
                // `ProbeStatus` is `#[non_exhaustive]`, so a probe written later may report a status this build does
                // not know. Marking it as a question is the honest answer: showing it as `ok` would hide a problem the
                // newer probe found, and showing it as `FAIL` would claim the machine is unusable when nothing said
                // so.
                _ => "?   ",
            };
            lines.push(format!("{marker}  {:<38} {}", line.name, line.detail));
            // The suggestion on its own line: a long detail plus a long suggestion on one line is a line nobody reads
            // to the end, and the suggestion is the half that tells them what to do.
            if let Some(suggestion) = &line.suggestion {
                lines.push(format!("      {:<38} {suggestion}", ""));
            }
        }

        if !failures_only {
            let passed = self.probes.len() - self.failed - self.warned;
            lines.push(format!(
                "{passed} ok, {} warn, {} fail",
                self.warned, self.failed
            ));
        }

        lines
    }
}

#[cfg(test)]
mod tests;
