//! Where the kernel's data lives, and what each command does.
//!
//! # Why this is not in `main`
//!
//! The design document caps `main.rs` at sixty lines of code, and the reason is not brevity. `main` is the one file in
//! a program that nobody writes tests for, so every decision that *can* be tested is moved here: where the data
//! directory is, what a command does with no kernel reachable, and what the process should exit with.
//!
//! What is left in `main` is the three things that need a process — read the arguments, call [`dispatch`], return the
//! code — and those are short enough to read in one go.
//!
//! # The data root has one answer
//!
//! `synra doctor` checks the directories the kernel would actually use, so the two have to agree about where those
//! are. A `doctor` that probed a directory nobody uses would report a healthy installation on a machine whose real
//! one is broken, which is the worst possible answer from a diagnostic tool.
//!
//! The environment variable is the answer for now: `SYNRA_DATA_DIR` if it is set, and a directory under the system's
//! temporary location otherwise. It is deliberately **not** an XDG-style lookup yet, because a lookup needs the
//! platform abstraction and this crate has no dependency on it — the daemon owns that decision, and duplicating it
//! here is how the two would come to disagree.

mod commands;
mod data;
mod doctor;

pub use commands::{dispatch, follow, follow_in};
pub use data::{data_root, data_root_from, CommandOutcome, DATA_DIR_VAR};
pub(crate) use doctor::doctor_outcome;
#[cfg(test)]
pub(crate) use commands::{plugin_request, registry_reference};
#[cfg(test)]
pub(crate) use doctor::write_bundle;

#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use crate::args::{Cli, Command};
#[cfg(test)]
use synra_control::Request;

// `no_kernel` used to live here: every command but `doctor` printed "no kernel is reachable". It is gone because the
// commands now open the socket, and the sentence a user needs is the one the socket error carries — which names the
// **path the client looked at**. A generic message hid the commonest cause, which is that the client looked in the wrong
// place.

#[cfg(test)]
mod tests {

    #[test]
    fn publisher_decisions_require_a_fingerprint_and_reach_the_daemon() {
        use clap::Parser as _;
        for (args, expected) in [
            (vec!["publisher", "list"], Request::PluginPublishers),
            (
                vec!["publisher", "decide", "@acme", "trusted", "--fingerprint", "AB12 CD34 EF56 7890"],
                Request::PluginPublisherDecide {
                    publisher_id: "@acme".to_owned(),
                    fingerprint: "AB12 CD34 EF56 7890".to_owned(),
                    trust: "trusted".to_owned(),
                },
            ),
        ] {
            let cli = Cli::try_parse_from(["synra", "plugin"].into_iter().chain(args)).expect("parse");
            let question = crate::question_for(&cli.command, cli.output, || {
                plugin_request(&cli.command)
            }).expect("question");
            assert_eq!(question.request, expected);
        }
        assert!(Cli::try_parse_from([
            "synra", "plugin", "publisher", "decide", "@acme", "trusted"
        ]).is_err());
        assert!(Cli::try_parse_from([
            "synra", "plugin", "publisher", "decide", "@acme", "maybe",
            "--fingerprint", "AB12 CD34 EF56 7890"
        ]).is_err());
    }

    #[test]
    fn plugin_update_commands_parse_and_reach_the_control_request() {
        use clap::Parser as _;
        use crate::{Cli, Command};
        use synra_control::Request;
        for (args, expected) in [
            (vec!["registry"], Request::PluginRegistry { urls: None }),
            (
                vec!["registry", "https://registry.example", "static:https://cdn.example/plugins"],
                Request::PluginRegistry {
                    urls: Some(vec![
                        "https://registry.example".to_owned(),
                        "static:https://cdn.example/plugins".to_owned(),
                    ]),
                },
            ),
            (
                vec!["registry", "--clear"],
                Request::PluginRegistry { urls: Some(Vec::new()) },
            ),
            (
                vec!["policy", "auto-all"],
                Request::PluginUpdatePolicy { policy: Some("auto-all".to_owned()) },
            ),
            (vec!["check"], Request::PluginCheckUpdates { plugin_id: None }),
            (
                vec!["check", "@acme/hello"],
                Request::PluginCheckUpdates { plugin_id: Some("@acme/hello".to_owned()) },
            ),
            (
                vec!["update", "@acme/hello", "--version", "^1.1"],
                Request::PluginUpdate {
                    plugin_id: "@acme/hello".to_owned(),
                    version: Some("^1.1".to_owned()),
                },
            ),
        ] {
            let cli = Cli::try_parse_from(["synra", "plugin"].into_iter().chain(args)).expect("parse");
            assert!(matches!(cli.command, Command::Plugin(_)));
            let question = crate::question_for(&cli.command, cli.output, || {
                plugin_request(&cli.command)
            }).expect("question");
            assert_eq!(question.request, expected);
        }
        assert!(Cli::try_parse_from(["synra", "plugin", "policy", "yes"]).is_err());
        assert!(Cli::try_parse_from(["synra", "plugin", "registry", "--clear", "https://example.com"]).is_err());
    }

    #[test]
    fn enabling_and_disabling_a_plugin_ask_the_kernel() {
        // ★ The commands that did nothing and blamed the kernel.
        //
        // Every plugin action but `list` answered `None` from `plugin_request`, and a `None` there makes the CLI report
        // "this command needs a running kernel, and none is reachable" — a false sentence about a kernel that is running,
        // which sends the user to check the wrong thing. Both actions are in the documented command list.
        let request = |action: crate::args::PluginAction| {
            plugin_request(&Command::Plugin(crate::args::PluginArgs { action }))
        };

        assert!(matches!(
            request(crate::args::PluginAction::Enable { plugin_id: "@acme/x".to_owned() }),
            Some(Request::PluginSetEnabled { enabled: true, .. })
        ));
        assert!(matches!(
            request(crate::args::PluginAction::Disable { plugin_id: "@acme/x".to_owned() }),
            Some(Request::PluginSetEnabled { enabled: false, .. })
        ));
        // The identifier survives, because a request that enabled the wrong plugin would be worse than one that enabled
        // none at all.
        let Some(Request::PluginSetEnabled { plugin_id, .. }) =
            request(crate::args::PluginAction::Enable { plugin_id: "@acme/x".to_owned() })
        else {
            panic!("expected a plugin request");
        };
        assert_eq!(plugin_id, "@acme/x");

        // ★ And installing asks the kernel, with the path the user typed. It used to ask nothing on the grounds that
        // there was no install layer — and there was not, which made a command in the documented list answer "you need a
        // running kernel" while one was running.
        //
        // ★ A name with no path separators now goes to the registry. It used to be sent as a path and refused by the
        // installer with "not a directory", which made the command's documented "or a `@scope/name` for a registry" a lie.
        let Some(Request::PluginInstallPackage { package, version }) =
            request(crate::args::PluginAction::Install {
                source: "@acme/x".to_owned(),
                version: Some("1.0.0".to_owned()),
            })
        else {
            panic!("expected a registry install request");
        };
        assert_eq!(package, "@acme/x");
        assert_eq!(version.as_deref(), Some("1.0.0"));
        let Some(Request::PluginInstall { path }) = request(crate::args::PluginAction::Install {
            source: "./build".to_owned(),
            version: None,
        }) else {
            panic!("expected an install request");
        };
        assert_eq!(path, "./build");

        // And consent carries the capabilities the user named, because a request that dropped them would record a
        // decision nobody made — every capability denied.
        let Some(Request::PluginConsent { plugin_id, granted }) =
            request(crate::args::PluginAction::Consent {
                plugin_id: "@acme/x".to_owned(),
                allow: vec!["log:*".to_owned(), "platform:open-url".to_owned()],
            })
        else {
            panic!("expected a consent request");
        };
        assert_eq!(plugin_id, "@acme/x");
        assert_eq!(granted, ["log:*", "platform:open-url"]);

        // Removing asks the kernel now, and carries the data decision with it: the flag is the only difference between
        // "remove" and "remove and delete", and a request that could not express it would make `--data` a promise with
        // nothing behind it.
        let Some(Request::PluginRemove { plugin_id, remove_data }) = request(crate::args::PluginAction::Remove {
            plugin_id: "@acme/x".to_owned(),
            data: true,
        })
        else {
            panic!("expected a remove request");
        };
        assert_eq!(plugin_id, "@acme/x");
        assert!(remove_data, "the flag reaches the kernel");
    }

    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("parses")
    }

    #[test]
    fn the_data_root_follows_the_environment() {
        // The daemon's answer, so `doctor` checks the installation the user actually has rather than a directory
        // nobody uses — which would report a healthy installation on a broken machine.
        //
        // The value is passed rather than set: `std::env::set_var` is `unsafe` in edition 2024 and this workspace
        // forbids `unsafe`, so the decision is a function of its input and a test supplies the input. What is not
        // covered here is the `var_os` call itself, which is one line of std in `data_root`.
        assert_eq!(
            data_root_from(Some(std::ffi::OsString::from("/custom/synra"))),
            PathBuf::from("/custom/synra")
        );
    }

    #[test]
    fn following_without_a_kernel_says_so_rather_than_waiting_for_lines() {
        // ★ `--follow` used to be refused as unimplemented. It is implemented now, and the failure that remains is the
        // ordinary one: no kernel answers. That must be said **before** the follower starts waiting on a file, or a user
        // with no daemon sees a silent command that looks like it is following a log.
        let directory =
            std::env::temp_dir().join(format!("synra-cli-follow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a data directory");

        let mut out = Vec::new();
        let code = follow_in(
            &directory,
            &cli(&["synra", "logs", "--follow"]),
            &mut out,
            std::time::Duration::from_millis(5),
        );

        assert_eq!(code, 1, "an unreachable kernel is a failure");
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("no kernel is listening"),
            "the socket error should be named: {text}"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_empty_data_root_falls_back_rather_than_naming_the_current_directory() {
        // An unset variable and one set to nothing are the same intention everywhere else, and `PathBuf::from("")` is
        // the current directory — which would put the kernel's database wherever the user happened to be standing.
        let fallback = data_root_from(None);
        assert!(fallback.ends_with("synra"), "{fallback:?}");
        assert!(fallback.is_absolute(), "a relative data root depends on the cwd: {fallback:?}");
        assert_eq!(data_root_from(Some(std::ffi::OsString::new())), fallback);
    }

    #[test]
    fn the_root_is_read_from_the_variable_that_is_documented() {
        // The wiring, asserted once: `data_root` reads `SYNRA_DATA_DIR`. Asserted through the constant, so a rename in
        // one place and not the other is a failure here rather than a user's environment variable being ignored.
        assert_eq!(DATA_DIR_VAR, "SYNRA_DATA_DIR");
        assert!(data_root().is_absolute());
    }

    #[test]
    fn a_command_that_produced_output_succeeded() {
        // An empty device list is a successful answer to "which devices are there", and exiting non-zero for it would
        // make a script treat an ordinary situation as an error.
        assert_eq!(CommandOutcome::Lines(vec![]).exit_code(), 0);
        assert_eq!(CommandOutcome::Lines(vec!["a".to_owned()]).exit_code(), 0);
        assert_eq!(CommandOutcome::json("{}").exit_code(), 0);
        // And JSON carries no success of its own: a failing command that printed JSON returned zero before this, which
        // is the one signal a script reads.
        assert_eq!(CommandOutcome::json_failure("{}").exit_code(), 1);
        assert_eq!(CommandOutcome::Failed("no".to_owned()).exit_code(), 1);
    }

    #[test]
    fn the_text_is_what_a_caller_prints() {
        assert_eq!(CommandOutcome::Lines(vec!["a".to_owned(), "b".to_owned()]).text(), "a\nb");
        assert_eq!(CommandOutcome::json("{}").text(), "{}");
        assert_eq!(CommandOutcome::json_failure("{}").text(), "{}");
        assert_eq!(CommandOutcome::Failed("bad".to_owned()).text(), "bad");
    }

    #[test]
    fn a_failure_is_what_main_sends_to_the_error_stream() {
        assert!(CommandOutcome::Failed("no".to_owned()).is_failure());
        assert!(!CommandOutcome::json("{}").is_failure());
        assert!(CommandOutcome::json_failure("{}").is_failure());
        assert!(!CommandOutcome::Lines(vec![]).is_failure());
    }

    #[test]
    fn a_command_needing_a_kernel_that_is_not_running_says_where_it_looked() {
        // ★ Every command but `doctor` and `db` opens the socket, so a kernel that is not running is a transport failure
        // — and the sentence names the **path**, which is what the user needs. A generic "no kernel is reachable" would
        // hide that the client looked somewhere specific, and the commonest cause is that it looked in the wrong place:
        // that is what `SYNRA_DATA_DIR` is for.
        let outcome = dispatch(&cli(&["synra", "status"]));
        match outcome {
            CommandOutcome::Json { body, ok } => {
                assert!(!ok, "a command with no kernel is a failure");
                let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
                assert_eq!(value["code"], "transport_not_open");
                let message = value["message"].as_str().expect("a message");
                assert!(message.contains("kernel.sock"), "{message}");
            }
            other => panic!("expected a JSON failure, got {other:?}"),
        }
    }

    #[test]
    fn a_script_asking_for_json_gets_json_even_when_it_failed() {
        // So a caller does not have to tell prose from JSON to know it failed: the exit code is the primary signal and
        // this is the detail beside it.
        let outcome = dispatch(&cli(&["synra", "--output", "json", "status"]));
        match outcome {
            CommandOutcome::Json { body, ok } => {
                assert!(!ok, "a command with no kernel is a failure");
                let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
                assert_eq!(value["code"], "transport_not_open");
                assert!(
                    value["message"].as_str().expect("a message").contains("kernel.sock"),
                    "the message should name the path: {body}"
                );
            }
            other => panic!("expected JSON, got {other:?}"),
        }
    }

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
}
