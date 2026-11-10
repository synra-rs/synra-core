use super::super::{CommandOutcome, dispatch};
use super::cli;

#[test]
fn the_bundle_flag_writes_the_file_it_names() {
    // ★ The flag that used to do nothing.
    //
    // `--bundle` was parsed, had a test asserting it was parsed, and `doctor_outcome` read only `failures_only` — so a
    // user asking for a file got a report and no file, with no error. This runs the command the way the user does and
    // reads what landed on disk.
    let directory = std::env::temp_dir().join(format!("synra-bundle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a temporary directory");
    let destination = directory.join("bundle.json");
    let destination_text = destination.to_string_lossy().to_string();

    let outcome = dispatch(&cli(&["synra", "doctor", "--bundle", &destination_text]));

    match outcome {
        CommandOutcome::Lines(lines) => {
            assert!(lines[0].contains("wrote"), "the answer says what it did: {lines:?}");
            assert!(lines[0].contains("bundle.json"), "and where: {lines:?}");
        }
        other => panic!("expected lines, got {other:?}"),
    }

    let written = std::fs::read_to_string(&destination).expect("the file the user asked for");
    let parsed: serde_json::Value = serde_json::from_str(&written).expect("a JSON bundle");
    // The probes are the section this command has, and they are in it.
    let sections = parsed["sections"].as_array().expect("a section list");
    assert!(
        sections.iter().any(|section| section.as_str() == Some("probes")),
        "the probes went in: {sections:?}"
    );
    assert!(parsed["probes"].is_array(), "with their results");

    // ★ And the file carries the list of what is never included, so a maintainer reads the same promise the consent
    // screen would have shown rather than having to trust that it said so.
    let excluded = parsed["excluded"].as_array().expect("an exclusion list");
    assert!(!excluded.is_empty(), "the exclusions are in the file: {excluded:?}");

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_bundle_that_cannot_be_written_is_refused_rather_than_silently_skipped() {
    // ★ The other half of honouring a flag: when it cannot be honoured, say so. A command that printed its report and
    // wrote nothing would be the state this replaced.
    let destination = std::env::temp_dir()
        .join("synra-no-such-directory-here")
        .join("nested")
        .join("bundle.json");

    let outcome = dispatch(&cli(&[
        "synra",
        "doctor",
        "--bundle",
        &destination.to_string_lossy(),
    ]));

    match outcome {
        CommandOutcome::Failed(why) => {
            assert!(why.contains("could not be written"), "{why}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_doctor_runs_and_reports() {
    // The one command that works with no kernel, which is the point: a user whose kernel will not start runs this
    // first. The probes touch the real machine, so the assertions are about the shape rather than the answers.
    let outcome = dispatch(&cli(&["synra", "doctor"]));
    match outcome {
        CommandOutcome::Lines(lines) => {
            assert!(lines.len() > 1, "the report should have a header and at least one probe: {lines:?}");
            assert!(lines[0].contains("synra"), "{:?}", lines[0]);
            // The header names the directory that was probed, so a user can see that `doctor` looked where the
            // kernel would.
            assert!(lines[0].contains("synra"), "{:?}", lines[0]);
        }
        other => panic!("expected text lines, got {other:?}"),
    }
}

#[test]
fn the_doctor_serialises_when_asked() {
    let outcome = dispatch(&cli(&["synra", "--output", "json", "doctor"]));
    match outcome {
        CommandOutcome::Json { body, .. } => {
            let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
            assert!(value["probes"].as_array().is_some_and(|probes| !probes.is_empty()));
            assert!(value["host"]["kernelVersion"].is_string());
        }
        other => panic!("expected JSON, got {other:?}"),
    }
}

#[test]
fn a_quiet_doctor_shows_only_failures() {
    // `--failures-only` is for a script and for a user who has already read the full report once.
    //
    // ★ What is asserted is the *shape*, not the count of failures. The probes touch the real machine — a port that
    // happens to be busy, a directory that happens to be read-only — so an assertion like "at most one failure"
    // would pass on this machine and fail on a busy one. The properties that hold everywhere are that the header
    // is printed, that no tally is printed for a script to skip, and that every line is either the header or a
    // failure.
    let outcome = dispatch(&cli(&["synra", "doctor", "--failures-only"]));
    match outcome {
        CommandOutcome::Lines(lines) => {
            assert!(!lines.is_empty(), "nothing was printed at all");
            assert!(lines[0].contains("synra"), "the header is missing: {lines:?}");
            assert!(
                !lines.iter().any(|line| line.contains(" ok,")),
                "a tally reached a failures-only report: {lines:?}"
            );
            for line in lines.iter().skip(1) {
                // Three shapes are allowed: a failure, the indented suggestion under one, and the sentence a
                // healthy machine gets instead of silence — which is the difference between "nothing is wrong"
                // and "the command did not run".
                assert!(
                    line.starts_with("FAIL")
                        || line.starts_with("      ")
                        || line == "no failures",
                    "a non-failure reached the output: {line:?}"
                );
            }
        }
        other => panic!("expected text lines, got {other:?}"),
    }
}
