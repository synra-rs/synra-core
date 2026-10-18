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

use std::path::PathBuf;

use crate::args::{Cli, Command, OutputFormat};
use crate::doctor::DoctorReport;
use synra_control::{Client, Request};
use synra_observe::diagnostics::{BundlePlan, BundleSources};
use synra_observe::doctor::{HostFacts, ProbeReport, ProbeTargets, run_probes};
use synra_store::Paths;

/// The environment variable that moves the data directory.
pub const DATA_DIR_VAR: &str = "SYNRA_DATA_DIR";

/// Where the kernel keeps its data.
///
/// The daemon's answer, so that `doctor` checks the installation the user actually has.
#[must_use]
pub fn data_root() -> PathBuf {
    data_root_from(std::env::var_os(DATA_DIR_VAR))
}

/// The data root for a given value of the environment variable.
///
/// # Why the value is a parameter
///
/// Reading an environment variable is not testable from inside a process: `std::env::set_var` is `unsafe` in edition
/// 2024, because another thread may be reading the environment at the same time, and this workspace forbids `unsafe`.
/// So the decision takes the value and the caller reads it — which leaves the interesting part, what a given value
/// *means*, as an ordinary function a test can call.
///
/// An empty value is not an answer: it falls back rather than naming the current directory, because an unset variable
/// and one set to nothing are the same intention everywhere else.
#[must_use]
pub fn data_root_from(configured: Option<std::ffi::OsString>) -> PathBuf {
    match configured {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir().join("synra"),
    }
}

/// What a command produced.
///
/// # Shape and success are two different things
///
/// A command's output can be lines or one JSON value, and either can be the result of a success or of a failure. So
/// the shape and the outcome are separate fields rather than separate variants: a `Json` variant on its own said
/// nothing about whether the command worked, and an exit code derived from the shape alone returned zero for a failing
/// command that happened to print JSON — which is the one signal a script reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// Lines for a person to read.
    ///
    /// A vector rather than printed, so the caller decides where it goes and a test asserts the text a user sees
    /// instead of capturing a stream.
    Lines(Vec<String>),
    /// One JSON value, for a script.
    Json {
        /// The value, as text.
        body: String,
        /// Whether the command succeeded.
        ok: bool,
    },
    /// Something the user has to fix.
    Failed(String),
}

impl CommandOutcome {
    /// A successful JSON result.
    #[must_use]
    pub fn json(body: impl Into<String>) -> Self {
        Self::Json { body: body.into(), ok: true }
    }

    /// A JSON result for a command that failed.
    ///
    /// A failure a script asked to read as JSON: it gets the detail *and* a non-zero exit code, rather than having to
    /// tell prose from JSON to know which happened.
    #[must_use]
    pub fn json_failure(body: impl Into<String>) -> Self {
        Self::Json { body: body.into(), ok: false }
    }

    /// What the process should exit with.
    ///
    /// `0` for output from a command that worked, `1` for one that did not. An empty list is a *successful* answer to
    /// "which devices are there", so lines alone are not a failure — but JSON alone is not a success either.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Lines(_) => 0,
            Self::Json { ok: true, .. } => 0,
            Self::Json { ok: false, .. } | Self::Failed(_) => 1,
        }
    }

    /// The text to print, whichever shape it is.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Lines(lines) => lines.join("\n"),
            Self::Json { body, .. } => body.clone(),
            Self::Failed(message) => message.clone(),
        }
    }

    /// Whether it is a failure, so `main` knows which stream to use.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        match self {
            Self::Lines(_) => false,
            Self::Json { ok, .. } => !*ok,
            Self::Failed(_) => true,
        }
    }
}

/// Runs a command.
///
/// # The two commands that never open the socket
///
/// `doctor` exists for the user whose kernel will not start, so it must work when nothing else does. `db` reads the
/// database directly, which is the point of it: a user whose kernel is misbehaving wants to look at the data without
/// asking the kernel about it.
///
/// Everything else is a question, and [`crate::channel`] is what turns one into a request and the answer into output.
#[must_use]
pub fn dispatch(cli: &Cli) -> CommandOutcome {
    // `--follow` never reaches here: it prints as lines arrive rather than returning one outcome, and `main` sends it to
    // [`follow`] before dispatch. That is a deliberate exception to the "return lines, let the caller print" rule — a
    // stream has no end to return.
    let question =
        match crate::channel::question_for(&cli.command, cli.output, || plugin_request(&cli.command))
        {
            Some(question) => question,
            None => {
                return match &cli.command {
                    Command::Doctor(args) => doctor_outcome(cli.output, args),
                    // ★ `db` reads the database directly, and did not.
                    //
                    // The subcommand was parsed, documented, and had argument tests — and every invocation ended in
                    // "this command reads the database directly, which is not implemented yet". Three verbs a user can
                    // see and none of them worked. The store side already existed; what was missing was this branch.
                    Command::Db(args) => crate::db::outcome(cli.output, args),
                    // ★ "No kernel is reachable" is true for a command that needs one and cannot find it, and false for
                    // one that never asks. Every plugin action maps to a request now, so this arm is the answer for a
                    // plugin action a future build adds before its request exists — and it says exactly that rather than
                    // blaming a missing kernel.
                    Command::Plugin(_) => CommandOutcome::Failed(
                        "this plugin action has no request in this build: it parses, but nothing sends it. \
                         `synra plugins` asks a running kernel; `synra doctor` needs none."
                            .to_owned(),
                    ),
                    _ => CommandOutcome::Failed(
                        "this command needs a running kernel, and none is reachable".to_owned(),
                    ),
                };
            }
        };

    match Client::connect(&data_root()) {
        Ok(mut client) => crate::channel::ask(&question, &mut client),
        // ★ The socket could not be opened, and the error names the path. A generic "no kernel" would hide that the
        // client looked somewhere specific — and the commonest cause is that it looked in the wrong place, which is
        // exactly what `SYNRA_DATA_DIR` is for.
        Err(error) => crate::channel::transport_failure(&error),
    }
}

/// Follows the kernel's log: prints the tail it answers with, then every line appended to the same file.
///
/// # Why this reads the file instead of opening a stream
///
/// Because the control protocol answers one request per connection, and the log file is on **this machine** — the socket
/// the client just used is a path inside the same data directory. A streaming request would add a second lifetime and a
/// second framing to the protocol to move bytes that are already local. What the user asked for is "keep showing me lines
/// as they appear", and reading the file the writer writes delivers exactly that.
///
/// # What this is not
///
/// Not a snapshot dressed up as a live log: the old `--follow` printed the tail and exited. This one prints the tail the
/// kernel answered with, then keeps reading. The one visible seam is that lines written between the kernel's answer and
/// the follower's first read are not printed — a window of milliseconds, and the alternative (a protocol for streaming)
/// was a larger promise than the command needed.
#[must_use]
pub fn follow(cli: &Cli, out: &mut dyn std::io::Write) -> u8 {
    follow_in(&data_root(), cli, out, synra_observe::logging::FOLLOW_POLL)
}

/// [`follow`], over a named data directory and poll interval — the shape a test can drive.
#[must_use]
pub fn follow_in(
    data_dir: &std::path::Path,
    cli: &Cli,
    out: &mut dyn std::io::Write,
    poll: std::time::Duration,
) -> u8 {
    let Command::Logs(args) = &cli.command else {
        return 2;
    };
    let request = Request::Logs {
        lines: usize::try_from(args.lines).unwrap_or(usize::MAX),
        verbose: args.verbose,
        trace: args.trace.clone(),
    };
    let mut client = match Client::connect(data_dir) {
        Ok(client) => client,
        Err(error) => {
            let outcome = crate::channel::transport_failure(&error);
            let _ = writeln!(out, "{}", outcome.text());
            return u8::from(outcome.is_failure());
        }
    };
    // The tail comes from the kernel, because asking it is also what raises the daemon's level for `--verbose`.
    let question = crate::channel::Question { request, shape: crate::channel::Shape::Prose };
    match crate::channel::ask(&question, &mut client) {
        CommandOutcome::Lines(lines) => {
            for line in lines {
                if writeln!(out, "{line}").is_err() {
                    return 1;
                }
            }
        }
        other => {
            let _ = writeln!(out, "{}", other.text());
            return u8::from(other.is_failure());
        }
    }
    // ★ Then the same file the daemon writes, followed by offset. `0` lines of history because the tail above already
    // printed it; the filters are the same ones the tail used, so `--verbose` and `--trace` keep their meaning.
    let paths = Paths::under(data_dir);
    let _ = synra_observe::logging::follow(
        paths.log_dir(),
        0,
        args.verbose,
        args.trace.as_deref(),
        poll,
        |line| writeln!(out, "{line}").and_then(|()| out.flush()).is_ok(),
    );
    0
}

/// The request a plugin subcommand makes, when it is one this build can serve.///
/// # What is asked and what is not
///
/// Every action has a request now, including `remove`: the kernel is the only process that may write to the plugin
/// directory, so it is asked for both halves of the removal. The data decision travels with the request rather than
/// being invented here — `plugin remove --data` is the destructive half, and off by default the data stays.
fn plugin_request(command: &Command) -> Option<Request> {
    use crate::args::PluginAction;

    let Command::Plugin(args) = command else {
        return None;
    };
    match &args.action {
        PluginAction::List { .. } => Some(Request::Plugins),
        PluginAction::Search { package } => {
            Some(Request::CatalogSearch { package: package.clone() })
        }
        // ★ These two did nothing at all, and said so wrongly.
        //
        // Every action but `list` answered `None`, and a `None` from here makes the CLI report "this command needs a
        // running kernel, and none is reachable" — a false sentence about a kernel that is running perfectly well, which
        // sends the user to check the wrong thing.
        PluginAction::Enable { plugin_id } => Some(Request::PluginSetEnabled {
            plugin_id: plugin_id.clone(),
            enabled: true,
        }),
        PluginAction::Disable { plugin_id } => Some(Request::PluginSetEnabled {
            plugin_id: plugin_id.clone(),
            enabled: false,
        }),
        // ★ Installing asks the kernel now, and it is the kernel that has to do it: verifying, writing into the plugin
        // directory and recording a row are three things only the process that owns the data directory may do. The
        // registry half is still absent — a `@scope/name` reaches the kernel and is refused as a path that is not a
        // directory, which `dispatch` reports in the kernel's words.
        PluginAction::Install { source, .. } => Some(Request::PluginInstall { path: source.clone() }),
        // ★ The decision the loader waits for. Without it a plugin is installed, listed, enable-able and permanently
        // unloadable: `load_one` refuses a plugin with no decisions on record, and the only writer was a test helper.
        PluginAction::Consent { plugin_id, allow } => Some(Request::PluginConsent {
            plugin_id: plugin_id.clone(),
            granted: allow.clone(),
        }),
        // ★ Removing is one act with two outcomes. The kernel removes the row and the artifact either way; `--data` is
        // the only thing that decides whether the sandbox goes too, and it defaults to off because a plugin the user may
        // reinstall should keep its settings.
        PluginAction::Remove { plugin_id, data } => Some(Request::PluginRemove {
            plugin_id: plugin_id.clone(),
            remove_data: *data,
        }),
    }
}

/// Runs the probes and formats the report.
fn doctor_outcome(format: Option<OutputFormat>, args: &crate::args::DoctorArgs) -> CommandOutcome {
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
fn write_bundle(destination: &str, raw: &ProbeReport) -> Result<Vec<String>, String> {
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

// `no_kernel` used to live here: every command but `doctor` printed "no kernel is reachable". It is gone because the
// commands now open the socket, and the sentence a user needs is the one the socket error carries — which names the
// **path the client looked at**. A generic message hid the commonest cause, which is that the client looked in the wrong
// place.

#[cfg(test)]
mod tests {

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
        assert!(matches!(
            request(crate::args::PluginAction::Install {
                source: "@acme/x".to_owned(),
                version: None,
            }),
            Some(Request::PluginInstall { .. })
        ));
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
