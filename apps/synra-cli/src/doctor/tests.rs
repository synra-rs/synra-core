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
