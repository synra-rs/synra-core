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
mod tests {
    use super::*;
    use synra_observe::doctor::ProbeResult;

    fn report(results: Vec<ProbeResult>) -> DoctorReport {
        let mut raw = ProbeReport::new();
        for result in results {
            raw.push(result);
        }
        DoctorReport::from_probe_report(&raw, Path::new("/data"))
    }

    fn ok(name: &str) -> ProbeResult {
        ProbeResult::ok(name, "fine")
    }

    fn warn(name: &str) -> ProbeResult {
        ProbeResult::warn(name, "9% of the disk is free", "free some space")
    }

    fn fail(name: &str) -> ProbeResult {
        ProbeResult::fail(name, "port 47000 is taken", "close whatever holds 47000")
    }

    #[test]
    fn a_report_counts_what_it_shows() {
        let report = report(vec![ok("a"), fail("b"), warn("c"), ok("d")]);
        assert_eq!(report.failed, 1);
        assert_eq!(report.warned, 1);
        assert_eq!(report.probes.len(), 4);
    }

    #[test]
    fn a_warning_is_not_a_failure() {
        // ★ The distinction that matters. A probe that warns found something that will bite later, and a machine that
        // warns can still run — so treating it as unhealthy would make `doctor` refuse to proceed on machines that
        // have been working all along.
        let report = report(vec![ok("a"), warn("b")]);
        assert!(report.is_healthy());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_failure_is_an_exit_code_a_script_can_branch_on() {
        // A `doctor` that always exited zero would be a check a script could not use.
        assert_eq!(report(vec![ok("a")]).exit_code(), 0);
        assert_eq!(report(vec![warn("a")]).exit_code(), 0);
        assert_eq!(report(vec![fail("a")]).exit_code(), 1);
        assert_eq!(report(vec![ok("a"), fail("b")]).exit_code(), 1);
    }

    #[test]
    fn failures_only_shows_only_failures() {
        let report = report(vec![ok("a"), fail("b"), warn("c")]);
        let failures = report.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "b");
    }

    #[test]
    fn the_lines_name_the_host_the_report_describes() {
        // A report without the machine it describes is one a reader cannot interpret — and one they will compare
        // against the wrong machine. The platform is known at compile time, so it is present even when every probe
        // failed.
        let lines = report(vec![ok("a")]).lines(false);
        assert!(lines[0].contains(env!("CARGO_PKG_VERSION")), "{lines:?}");
        assert!(lines[0].contains(std::env::consts::OS), "{lines:?}");
        assert!(lines[0].contains("/data"), "{lines:?}");
    }

    #[test]
    fn every_probe_gets_a_line_with_its_status_in_the_left_margin() {
        // A user scanning the left margin sees the status without reading the words, which is what makes a long report
        // usable. The probes are built without suggestions here, so each contributes exactly one line and the markers
        // are what is under test — a suggestion would add a line and shift the ones being asserted about.
        let plain = |name: &str, status: ProbeStatus| ProbeResult {
            name: name.to_owned(),
            status,
            detail: "detail".to_owned(),
            suggestion: None,
        };
        let lines = report(vec![
            plain("a", ProbeStatus::Ok),
            plain("b", ProbeStatus::Fail),
            plain("c", ProbeStatus::Warn),
        ])
        .lines(false);

        let body: Vec<&String> = lines.iter().skip(1).take(3).collect();
        assert!(body[0].starts_with("ok  "), "{:?}", body[0]);
        assert!(body[1].starts_with("FAIL"), "{:?}", body[1]);
        assert!(body[2].starts_with("warn"), "{:?}", body[2]);
        // And the name and the detail are both there, because one says which check ran and the other says what it
        // found.
        assert!(body[1].contains('b') && body[1].contains("detail"), "{:?}", body[1]);
    }

    #[test]
    fn a_suggestion_gets_its_own_line() {
        // A long detail plus a long suggestion on one line is a line nobody reads to the end, and the suggestion is
        // the half that tells a user what to do.
        let lines = report(vec![fail("port")]).lines(false);

        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[1].contains("port 47000 is taken"), "{:?}", lines[1]);
        assert!(
            lines[2].contains("close whatever holds 47000"),
            "{:?}",
            lines[2]
        );
        assert!(lines[2].starts_with("      "), "not indented: {:?}", lines[2]);
    }

    #[test]
    fn a_probe_without_a_suggestion_gets_one_line() {
        // The detail already said there is nothing to do. Built by hand rather than through `fail`, because every
        // constructor that reports a problem requires a suggestion — which is the design imposing itself on the
        // fixture, and the reason this test constructs the value directly.
        let probe = ProbeResult {
            name: "quiet".to_owned(),
            status: ProbeStatus::Fail,
            detail: "something broke".to_owned(),
            suggestion: None,
        };
        let lines = report(vec![probe]).lines(false);
        assert_eq!(lines.len(), 3, "the probe, then the tally: {lines:?}");
        assert!(lines[1].contains("something broke"), "{:?}", lines[1]);
    }

    #[test]
    fn the_lines_end_with_a_tally() {
        let lines = report(vec![ok("a"), fail("b"), warn("c")]).lines(false);
        let last = lines.last().expect("a line");
        assert!(last.contains("1 ok"), "{last}");
        assert!(last.contains("1 warn"), "{last}");
        assert!(last.contains("1 fail"), "{last}");
    }

    #[test]
    fn a_quiet_run_with_nothing_wrong_says_so() {
        // Saying so is the difference between "nothing is wrong" and "the command did not run".
        let lines = report(vec![ok("a")]).lines(true);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[1], "no failures");
    }

    #[test]
    fn a_quiet_run_shows_the_failures_and_no_tally() {
        // A script reading `--failures-only` wants the failures, and a tally on the end is one more line it has to
        // know to skip.
        let lines = report(vec![ok("a"), fail("b")]).lines(true);
        // The failure, its suggestion — because showing a failure and not what to do about it is half an answer — and
        // no tally, which is one more line for a script to know to skip.
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[1].contains("FAIL"));
        assert!(lines[2].contains("close whatever holds 47000"));
        assert!(!lines.iter().any(|line| line.contains(" ok,")), "{lines:?}");
    }

    #[test]
    fn an_empty_report_is_healthy_and_says_nothing_is_wrong() {
        // Not reachable from `run`, which always has probes — but a report built from nothing must not be a report
        // that claims a failure.
        let report = report(vec![]);
        assert!(report.is_healthy());
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.lines(false).len(), 2);
    }

    #[test]
    fn the_report_serialises_for_a_script() {
        // The JSON view and the prose view come from one report, so they cannot disagree.
        let report = report(vec![fail("port"), ok("disk")]);
        let json = serde_json::to_value(&report).expect("serialises");

        assert_eq!(json["failed"], 1);
        assert_eq!(json["warned"], 0);
        assert_eq!(json["probes"][0]["name"], "port");
        // Lowercase, matching `ProbeStatus::as_str` — the JSON view uses the same spelling as the diagnostic bundle and
        // the interface, so a reader has one spelling to learn rather than three.
        assert_eq!(json["probes"][0]["status"], "fail");
        assert_eq!(json["host"]["platform"], std::env::consts::OS);
        assert_eq!(json["host"]["dataDir"], "/data");
        // A probe with no suggestion omits the key rather than carrying a null, so a script can test for its presence.
        assert!(json["probes"][1].get("suggestion").is_none(), "{json}");
    }

    #[test]
    fn the_report_runs_the_real_probes_when_asked() {
        // The wiring, asserted once: `run` calls the probes and wraps them. A report that ran nothing would be a
        // doctor that always said the machine was fine. The targets point at a directory that certainly does not
        // exist, so the run is deterministic-ish and touches nothing the test owns.
        let targets = ProbeTargets {
            data_dir: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            plugins_dir: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            // Port 0 asks the operating system for a free one, so the port probes pass rather than depending on what
            // the machine happens to be running.
            listen_port: 0,
            discovery_port: 0,
        };
        let report = DoctorReport::run(&targets, &HostFacts::default());

        assert!(!report.probes.is_empty(), "no probes ran");
        // The counts cannot exceed what they count, which is the invariant that keeps the tally honest.
        assert!(report.failed + report.warned <= report.probes.len());
        assert_eq!(report.host.data_dir, env!("CARGO_MANIFEST_DIR"));
    }
}
