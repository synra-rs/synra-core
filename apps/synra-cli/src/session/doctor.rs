use std::path::PathBuf;

use crate::args::OutputFormat;
use crate::doctor::DoctorReport;
use synra_observe::diagnostics::{BundlePlan, BundleSources};
use synra_observe::doctor::{HostFacts, ProbeReport, ProbeTargets, run_probes};
use synra_store::Paths;

use super::{data_root, CommandOutcome};

/// Runs the probes and formats the report.
pub(crate) fn doctor_outcome(format: Option<OutputFormat>, args: &crate::args::DoctorArgs) -> CommandOutcome {
    let paths = Paths::under(data_root());
    let targets = ProbeTargets {
        data_dir: paths.data_dir().to_path_buf(),
        plugins_dir: paths.plugins_dir(),
        // Port zero asks the operating system for a free one, so the port probes answer "is there a free port" rather
        // than "is the port this machine happens to use busy" — which is what a user wants to know before starting.
        listen_port: 0,
        discovery_port: 0,
    };

    // ★ The probes run **once**, and the bundle and the report are two views of the same run.
    //
    // `DoctorReport::run` used to call `run_probes` and discard the raw report, keeping only the flattened lines — which was
    // right while nothing else wanted the results. A bundle wants them, and running the probes twice would mean a bundle
    // whose probe section could disagree with the report printed beside it.
    let raw = run_probes(&targets, &HostFacts::default());
    let report = DoctorReport::from_probe_report(&raw, paths.data_dir());

    // ★ `--bundle` used to be parsed and then never read.
    //
    // The argument existed, the parser had a test asserting it was parsed, and `doctor_outcome` looked only at
    // `failures_only` — so `synra doctor --bundle /tmp/d.json` printed its report and wrote no file, without an error. A flag
    // that looks supported and does nothing is worse than one that is refused, because the user has no way to tell.
    if let Some(destination) = args.bundle.as_deref() {
        return match write_bundle(destination, &raw) {
            Ok(lines) => CommandOutcome::Lines(lines),
            Err(why) => CommandOutcome::Failed(why),
        };
    }

    match format {
        // A report that could not be serialised is a failure rather than a silent fallback to prose: a script that
        // asked for JSON and got a sentence would parse nothing and say nothing.
        Some(OutputFormat::Json) => match serde_json::to_string_pretty(&report) {
            // The JSON goes out either way, because the detail is what a caller wants — and the `ok` flag is what
            // makes the exit code agree with the report rather than with its *shape*. A failing `doctor` that printed
            // JSON returned zero before this, which is the one signal a script reads.
            Ok(json) => {
                if report.is_healthy() {
                    CommandOutcome::json(json)
                }
                else {
                    CommandOutcome::json_failure(json)
                }
            }
            Err(error) => CommandOutcome::Failed(format!("could not format the report: {error}")),
        },
        _ => CommandOutcome::Lines(report.lines(args.failures_only)),
    }
}

/// Writes a diagnostic bundle, and answers with what went into it.
///
/// # Why this is the first production caller of `BundlePlan`
///
/// Because the whole bundle subsystem — the plan, the sections, the two redaction passes, the digest, the exclusions list
/// carried inside the file — was written, tested and reachable from nothing. `BundlePlan::plan` appeared only in its own
/// tests and proptests, so the redaction that exists to stop a credential leaving the machine had never run on a machine.
/// This is where it does.
///
/// # What goes in, and what the file says about what did not
///
/// The probe results, because that is what this command has. Nothing else is filled in from an assumption: a device list
/// this command cannot read is **absent** rather than empty, and the bundle carries the list of sections that are never
/// included (`excludes`) so a maintainer reading the file sees the same promise the consent screen would have shown.
///
/// # Errors
///
/// A sentence naming what went wrong — the bundle could not be assembled, or the destination could not be written. A
/// refusal rather than a silent success, because the caller asked for a file and the only two honest answers are the path
/// or the reason there is none.
pub(crate) fn write_bundle(destination: &str, raw: &ProbeReport) -> Result<Vec<String>, String> {
    let sources = BundleSources {
        probes: Some(raw.results.clone()),
        ..BundleSources::default()
    };
    let plan = BundlePlan::plan(
        sources,
        synra_store::sqlite::now_ms(),
        PathBuf::from(destination),
    );

    let rendered = plan
        .render()
        .map_err(|error| format!("the bundle could not be assembled: {error}"))?;

    std::fs::write(plan.destination(), &rendered)
        .map_err(|error| format!("`{destination}` could not be written: {error}"))?;

    let mut lines = vec![format!("wrote {} bytes to {destination}", rendered.len())];
    // The sections that went in, and the ones that never do — the same two lists the file itself carries.
    for (name, because) in plan.inclusions() {
        lines.push(format!("  included: {name} ({because})"));
    }
    for excluded in plan.excludes() {
        lines.push(format!("  never included: {excluded}"));
    }
    Ok(lines)
}
