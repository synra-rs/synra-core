//! What a command asks the kernel, and how the answer becomes output.
//!
//! # Why this is separate from the command line's own types
//!
//! A command's arguments are the user's words — `--all`, `--text`, `--lines` — and a request's operands are the
//! kernel's. Mapping one to the other is a small function per command, and the smallness is the point: everything that
//! can be *decided* here is decided here, so the binary stays a thing you can read in one go.
//!
//! # Why the mapping is asserted rather than eyeballed
//!
//! A `--all` that did not reach `include_unpaired`, or a `--lines` that arrived as the default, is a command whose flag
//! is silently ignored — and the user's evidence is output that looks plausible. Each mapping has a test that asserts the
//! operand arrived, because that is the failure this layer can have.

use synra_control::{Client, Request, Response};
use synra_protocol::error::ErrorCode;

/// What to ask, and what to do with the answer.
///
/// The two halves are together because they are one decision: a request whose answer nobody formats is a request nobody
/// made, and a formatter without its request is a shape with nothing behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// What to send.
    pub request: Request,
    /// How to present the answer.
    pub shape: Shape,
}

/// How a command's answer becomes output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Shape {
    /// The kernel's JSON value, printed as it arrives.
    ///
    /// For a script, and for the one command whose whole answer is a document.
    Json,
    /// A short prose summary for a person, falling back to the JSON when the value is not one this build knows.
    Prose,
}

/// The request a command makes, or nothing when the command needs no kernel.
///
/// # Why `None` rather than an error
///
/// `doctor` and `db` do not talk to a running kernel: the first exists for the user whose kernel will not start, and the
/// second reads the database directly. Returning an error for them would make the caller distinguish two kinds of
/// "nothing", and a caller that got it wrong would report a missing kernel for a command that never needed one.
#[must_use]
pub fn question_for(
    command: &crate::args::Command,
    output: Option<crate::args::OutputFormat>,
    plugin_request: impl FnOnce() -> Option<Request>,
) -> Option<Question> {
    use crate::args::{Command, IntentAction, OutputFormat};

    // `--output` is a flag of the command line rather than of a subcommand, so the shape is decided once here instead of
    // being read off each set of arguments — which is what the first version did, and it read a field that does not
    // exist.
    let shape = match output {
        Some(OutputFormat::Json) => Shape::Json,
        _ => Shape::Prose,
    };

    match command {
        // ★ The shape follows `--output`, like every other command. The first version pinned `status` to JSON on the
        // reasoning that its summary is derived from the same value — and the effect was that a user asking for text got
        // a JSON document, which is the wrong answer to the question they asked.
        Command::Status => Some(Question { request: Request::Status, shape }),
        // ★ The command that names the missing producer: until this existed, pairing could be answered but never
        // asked for, so a device could only be paired by the other side starting the exchange.
        Command::Pair(args) => Some(Question {
            request: Request::Pair { device: args.device.clone() },
            shape,
        }),
        Command::Devices(args) => Some(Question {
            // ★ Both flags are carried, not dropped. A `--all` or a `--scan-ms` that did not arrive is a command whose
            // flag is silently ignored, and the output looks plausible either way — which is the failure mode a
            // client-side sleep would have: it would look like a scan and be a delay.
            //
            // `--cached` means "do not scan", and it wins over `--scan-ms` because it is the more specific request: a
            // client that said both asked for a scan and then said not to.
            request: Request::Devices {
                include_unpaired: args.all,
                scan_ms: if args.cached { None } else { args.scan_ms },
            },
            shape,
        }),
        Command::Send(args) => match (&args.text, &args.file) {
            (Some(text), _) => Some(Question {
                request: Request::SendText { to: args.to.clone(), text: text.clone() },
                shape,
            }),
            (None, Some(path)) => Some(Question {
                request: Request::SendFile { to: args.to.clone(), path: path.clone() },
                shape,
            }),
            // Neither, which `clap` refuses before this is reached — the two flags conflict and one is required. A
            // `None` here is a request nobody made rather than a refusal, because the caller's next step is the same:
            // print the usage.
            (None, None) => None,
        },
        Command::Logs(args) => Some(Question {
            request: Request::Logs {
                lines: usize::try_from(args.lines).unwrap_or(usize::MAX),
                // `--verbose` widens the filter, and `--trace` needs the wide one too: the lines that mention a trace id
                // are the debug ones, so a trace filter without it would find nothing.
                verbose: args.verbose || args.trace.is_some(),
                // ★ Passed through rather than folded into `verbose`. It used to be folded in — the id was dropped and
                // the command answered as if `--verbose` had been given, so a user asking to follow one action got every
                // line in the log and no indication that their filter had been ignored.
                trace: args.trace.clone(),
            },
            shape,
        }),
        Command::Plugin(_) => plugin_request().map(|request| Question { request, shape }),
        // ★ The three answers to a prompt, each one request.
        //
        // `share` prints an identifier and this is what makes it usable: without these, routing could be started from the
        // command line and never finished there, and the identifier was a value with no second command to spend it on.
        Command::Intent(args) => Some(Question {
            request: match &args.action {
                IntentAction::Show { intent } => Request::IntentSnapshot { intent: intent.clone() },
                IntentAction::Decide { intent, plugin, target } => Request::IntentDecide {
                    intent: intent.clone(),
                    plugin_id: plugin.clone(),
                    target: target.clone(),
                },
                IntentAction::Cancel { intent } => Request::IntentCancel { intent: intent.clone() },
            },
            shape,
        }),
        Command::Share(args) => Some(Question {
            request: Request::IntentDispatch {
                mime: args.mime.clone(),
                text: args.text.clone(),
            },
            shape,
        }),
        // The two commands that do not need a running kernel.
        Command::Doctor(_) | Command::Db(_) => None,
    }
}

/// Turns a kernel's response into output.
///
/// # Why a refusal is not a transport error
///
/// A refusal is the kernel answering: it is a result, and a script reads its code. A transport error is the absence of
/// an answer, and a script reads the exit code. Collapsing them would make "the device is offline" indistinguishable
/// from "no kernel is running", which are the two things a user most needs to tell apart.
#[must_use]
pub fn outcome_of(response: &Response, shape: Shape) -> crate::session::CommandOutcome {
    use crate::session::CommandOutcome;

    match response {
        Response::Ok { value } => match shape {
            Shape::Json => CommandOutcome::json(pretty(value)),
            Shape::Prose => CommandOutcome::Lines(prose(value)),
        },
        Response::Failed { code, message, .. } => {
            // The same shape for both output modes, so a caller that asked for JSON gets JSON *and* a non-zero exit
            // code rather than having to tell prose from JSON to know which happened.
            CommandOutcome::json_failure(
                serde_json::json!({ "code": code, "message": message }).to_string(),
            )
        }
        Response::Hello { version, kernel } => CommandOutcome::Lines(vec![
            format!("kernel {kernel}, protocol {version}"),
        ]),
        // ★ `non_exhaustive` means an arm for a shape this build does not know is required even in the crate that
        // declares it — and that requirement is the point: a response the kernel gained is one a client must decide
        // about rather than one that falls through to nothing. Here the decision is to print it, because a client older
        // than its kernel must still show the answer rather than an empty screen.
        other => CommandOutcome::Lines(vec![format!("{other:?}")]),
    }
}

/// The JSON a script reads.
fn pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// A short summary for a person.
///
/// # Why this falls back to JSON
///
/// A build of the client that does not know a command's shape must still print the answer rather than nothing. The
/// fallback is the JSON, which is ugly and complete — and complete is what a user filing a bug report needs.
fn prose(value: &serde_json::Value) -> Vec<String> {
    if let Some(lines) = value.get("lines").and_then(serde_json::Value::as_array) {
        return lines.iter().map(render_line).collect();
    }
    if let Some(plugins) = value.get("plugins").and_then(serde_json::Value::as_array) {
        if plugins.is_empty() {
            return vec!["no plugins are installed".to_owned()];
        }
        return plugins.iter().map(render_plugin).collect();
    }
    // ★ The devices report has three sources, and the renderer keeps them apart for the same reason the kernel does: a
    // paired device is one the user decided about, and a device merely heard on the network is an unauthenticated
    // datagram. A list that merged them would present the second as the first.
    if value.get("paired").is_some() && value.get("found").is_some() {
        return render_devices(value);
    }
    if let Some(state) = value.get("state").and_then(serde_json::Value::as_str) {
        let mut out = vec![format!("kernel {state}")];
        if let Some(version) = value.get("version").and_then(serde_json::Value::as_str) {
            out.push(format!("  version      {version}"));
        }
        if let Some(dir) = value.get("dataDir").and_then(serde_json::Value::as_str) {
            out.push(format!("  data         {dir}"));
        }
        if let Some(ports) = value.get("transportPort").and_then(serde_json::Value::as_u64) {
            out.push(format!("  transport    {ports}"));
        }
        if let Some(uptime) = value.get("uptimeMs").and_then(serde_json::Value::as_u64) {
            out.push(format!("  uptime       {}s", uptime / 1_000));
        }
        // The schema version against what this build understands, because the two disagreeing is the one database
        // problem a user can see coming rather than discover.
        if let Some(schema) = value.get("schemaVersion").and_then(serde_json::Value::as_u64) {
            let known = value.get("schemaKnown").and_then(serde_json::Value::as_u64).unwrap_or(0);
            out.push(format!("  schema       {schema} (this build knows {known})"));
        }
        // ★ The missing layers are printed, because `status` is the command a user runs to find out what is going on
        // and a summary that hid them would leave them wondering why the next command refuses.
        if let Some(missing) = value.get("notImplemented").and_then(serde_json::Value::as_array) {
            let names: Vec<&str> = missing.iter().filter_map(serde_json::Value::as_str).collect();
            if !names.is_empty() {
                out.push(format!("  not built    {}", names.join(", ")));
            }
        }
        return out;
    }
    if let Some(devices) = value.get("devices").and_then(serde_json::Value::as_array) {
        if devices.is_empty() {
            return vec!["no devices".to_owned()];
        }
        return devices.iter().map(render_device).collect();
    }
    vec![pretty(value)]
}

/// One log line, as it is.
fn render_line(value: &serde_json::Value) -> String {
    value.as_str().map_or_else(|| pretty(value), ToOwned::to_owned)
}

/// One device, as a row.
fn render_device(value: &serde_json::Value) -> String {
    let id = value.get("deviceId").and_then(serde_json::Value::as_str).unwrap_or("?");
    let name = value.get("displayName").and_then(serde_json::Value::as_str).unwrap_or("");
    let online = value.get("online").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let paired = value.get("paired").and_then(serde_json::Value::as_bool).unwrap_or(false);
    format!(
        "{id}  {name}  {}",
        match (paired, online) {
            (true, true) => "paired, online",
            (true, false) => "paired, offline",
            (false, true) => "not paired",
            (false, false) => "not paired, offline",
        }
    )
}

/// The devices report, as a person reads it.
///
/// # Why this device is printed first
///
/// Because it is the answer to the question a user has when the list is empty: *which device am I even on?* That
/// identifier is what every peer has recorded against them, and reading it out is how a pairing problem is diagnosed.
/// A list that showed only the other devices would leave the one fact the user can act on unsaid.
///
/// # Why an empty list says which kind of empty it is
///
/// Because "nothing is paired" and "nothing was found" are different situations with different next steps — one needs a
/// pairing, the other needs the other device to be switched on. A single "no devices" would leave the user to guess.
fn render_devices(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();

    if let Some(this) = value.get("self") {
        let name = this.get("displayName").and_then(serde_json::Value::as_str).unwrap_or("?");
        let id = this.get("deviceId").and_then(serde_json::Value::as_str).unwrap_or("?");
        let platform = this.get("platform").and_then(serde_json::Value::as_str).unwrap_or("?");
        out.push(format!("this device  {name} ({platform})"));
        out.push(format!("  {id}"));
    }

    let empty = |list: Option<&Vec<serde_json::Value>>| list.is_none_or(Vec::is_empty);
    let paired = value.get("paired").and_then(serde_json::Value::as_array);
    if empty(paired) {
        out.push("paired       none".to_owned());
    }
    else {
        out.push("paired".to_owned());
        for row in paired.into_iter().flatten() {
            let name = row.get("displayName").and_then(serde_json::Value::as_str).unwrap_or("?");
            let id = row.get("deviceId").and_then(serde_json::Value::as_str).unwrap_or("?");
            // The session state is what separates "recorded once" from "reachable now", and a user deciding what to do
            // needs the second. Absent means there is no session at all, which is a third thing.
            let state = row.get("linkState").and_then(serde_json::Value::as_str).unwrap_or("no session");
            let blocked = row.get("blocked").and_then(serde_json::Value::as_bool).unwrap_or(false);
            let suffix = if blocked { ", blocked" } else { "" };
            out.push(format!("  {name}  {state}{suffix}"));
            out.push(format!("    {id}"));
        }
    }

    // ★ Only present when the caller asked for it. A report that always printed this section would make a user who did
    // not ask wonder what the unapproved devices are doing in their list.
    if value.get("includeUnpaired").and_then(serde_json::Value::as_bool) == Some(true) {
        let found = value.get("found").and_then(serde_json::Value::as_array);
        if empty(found) {
            out.push("found        none on this network".to_owned());
        }
        else {
            out.push("found on this network".to_owned());
            for row in found.into_iter().flatten() {
                let name = row.get("displayName").and_then(serde_json::Value::as_str).unwrap_or("?");
                let address = row.get("address").and_then(serde_json::Value::as_str).unwrap_or("?");
                let trust = row.get("trust").and_then(serde_json::Value::as_str).unwrap_or("?");
                out.push(format!("  {name}  {address}  {trust}"));
            }
        }
    }

    out
}

/// One plugin, as a row.
fn render_plugin(value: &serde_json::Value) -> String {
    let id = value.get("id").and_then(serde_json::Value::as_str).unwrap_or("?");
    if let Some(problem) = value.get("problem").and_then(serde_json::Value::as_str) {
        return format!("{id}  ({problem})");
    }
    let version = value.get("version").and_then(serde_json::Value::as_str).unwrap_or("?");
    let title = value.get("title").and_then(serde_json::Value::as_str).unwrap_or("");
    format!("{id}  {version}  {title}")
}

/// Runs a question against a kernel and turns the answer into output.
///
/// # Why the handshake is here and not in the caller
///
/// Every command needs it, and a caller that forgot it would get a refusal about the handshake rather than about its
/// command — a message that names the wrong problem. Doing it here means the only way to ask a question is a way that
/// has said hello first.
#[must_use]
pub fn ask(question: &Question, client: &mut Client) -> crate::session::CommandOutcome {
    if let Err(error) = client.handshake() {
        return transport_failure(&error);
    }
    match client.ask(&question.request) {
        Ok(response) => outcome_of(&response, question.shape),
        Err(error) => transport_failure(&error),
    }
}

/// What the user sees when the kernel could not be reached.
///
/// # Why the error's own sentence is used
///
/// It names the path and says what to start, which is what the user needs. A generic "no kernel" would hide the fact
/// that the client looked somewhere specific — and the commonest cause is that it looked in the wrong place, which is
/// exactly what `SYNRA_DATA_DIR` is for.
#[must_use]
pub fn transport_failure(error: &synra_control::SocketError) -> crate::session::CommandOutcome {
    crate::session::CommandOutcome::json_failure(
        serde_json::json!({
            "code": ErrorCode::TransportNotOpen.as_str(),
            "message": error.to_string(),
            "retryable": error.is_retryable(),
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{
        Command, DbAction, DbArgs, DevicesArgs, IntentAction, LogsArgs, OutputFormat, PairArgs, SendArgs,
    };

    fn devices_args(all: bool) -> DevicesArgs {
        DevicesArgs { all, scan_ms: None, cached: false }
    }

    fn send_args(text: Option<&str>, file: Option<&str>) -> SendArgs {
        SendArgs {
            to: "dev_a".to_owned(),
            text: text.map(ToOwned::to_owned),
            file: file.map(ToOwned::to_owned),
            context: None,
        }
    }

    fn logs_args(lines: u32, trace: Option<&str>, verbose: bool) -> LogsArgs {
        LogsArgs {
            follow: false,
            trace: trace.map(ToOwned::to_owned),
            lines,
            verbose,
        }
    }

    // ── The mapping ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_devices_flag_reaches_the_request() {
        // ★ A `--all` that did not arrive is a command whose flag is silently ignored, and the output looks plausible
        // either way — so the assertion is on the operand rather than on the shape of the question.
        let question = question_for(&Command::Devices(devices_args(true)), None, || None)
            .expect("a question");
        assert_eq!(
            question.request,
            Request::Devices { include_unpaired: true, scan_ms: None }
        );

        let question = question_for(&Command::Devices(devices_args(false)), None, || None)
            .expect("a question");
        assert_eq!(
            question.request,
            Request::Devices { include_unpaired: false, scan_ms: None }
        );
    }

    #[test]
    fn text_and_a_file_become_their_own_requests() {
        // The two are different requests rather than one with an optional payload, because the kernel does different
        // things with them: text may go inline and a file never does.
        let text = question_for(&Command::Send(send_args(Some("hi"), None)), None, || None).expect("a question");
        assert_eq!(
            text.request,
            Request::SendText { to: "dev_a".to_owned(), text: "hi".to_owned() }
        );

        let file = question_for(&Command::Send(send_args(None, Some("/tmp/a"))), None, || None)
            .expect("a question");
        assert_eq!(
            file.request,
            Request::SendFile { to: "dev_a".to_owned(), path: "/tmp/a".to_owned() }
        );
    }

    #[test]
    fn a_send_with_neither_text_nor_a_file_asks_nothing() {
        // `clap` refuses this before it is reached, so a `None` here is a request nobody made rather than a refusal —
        // and the caller's next step is the same either way: print the usage.
        assert!(question_for(&Command::Send(send_args(None, None)), None, || None).is_none());
    }

    #[test]
    fn the_log_line_count_reaches_the_request() {
        // Off by a default is the silent failure here: `--lines 5` arriving as the default would print the wrong amount
        // and look like an answer.
        let question = question_for(&Command::Logs(logs_args(25, None, false)), None, || None).expect("a question");
        assert_eq!(question.request, Request::Logs { lines: 25, verbose: false, trace: None });
    }

    #[test]
    fn a_trace_filter_carries_the_id_and_asks_for_the_verbose_log() {
        // ★ This test used to assert only `verbose: true`, and its comment said "the filter is applied to what comes
        // back". Nothing applied it: the id was dropped in this very function, so `--trace` returned the whole log and
        // the user had no way to tell that their filter had been ignored.
        //
        // The id is carried now, and that is the half of the assertion that would have caught it.
        let question = question_for(&Command::Logs(logs_args(10, Some("trace-1"), false)), None, || None)
            .expect("a question");
        match question.request {
            Request::Logs { lines, verbose, trace } => {
                assert_eq!(lines, 10);
                // Widened, because a trace's lines are the debug ones.
                assert!(verbose, "a trace filter needs the verbose log to have anything to filter");
                // ★ And carried. Without this the filter has nothing to match on and the daemon answers with
                // everything, which is what used to happen.
                assert_eq!(trace.as_deref(), Some("trace-1"), "the trace id was dropped on the way to the request");
            }
            other => panic!("expected a logs request, got {other:?}"),
        }
    }

    #[test]
    fn every_request_the_cli_can_make_is_accounted_for() {
        // ★ The exhaustive half. A command added to the enum and not to the mapping is one that silently does nothing,
        // and the compiler cannot see it because the mapping has a `None` arm.
        let commands: Vec<(&str, Option<Question>)> = vec![
            ("status", question_for(&Command::Status, None, || None)),
            ("devices", question_for(&Command::Devices(devices_args(false)), None, || None)),
            ("send", question_for(&Command::Send(send_args(Some("x"), None)), None, || None)),
            ("logs", question_for(&Command::Logs(logs_args(1, None, false)), None, || None)),
            (
                "share",
                question_for(
                    &Command::Share(crate::args::ShareArgs {
                        text: "https://example.com".to_owned(),
                        mime: "text/uri-list".to_owned(),
                    }),
                    None,
                    || None,
                ),
            ),
            (
                "intent",
                question_for(
                    &Command::Intent(crate::args::IntentArgs {
                        action: crate::args::IntentAction::Show { intent: "abc".to_owned() },
                    }),
                    None,
                    || None,
                ),
            ),
            (
                "doctor",
                question_for(
                    &Command::Doctor(crate::args::DoctorArgs { failures_only: false, bundle: None }),
                    None,
                    || None,
                ),
            ),
            (
                "db",
                question_for(&Command::Db(DbArgs { action: DbAction::Dump { table: None } }), None, || None),
            ),
        ];
        for (name, question) in commands {
            let expected = !matches!(name, "doctor" | "db");
            assert_eq!(question.is_some(), expected, "{name}");
        }
    }

    #[test]
    fn each_answer_to_a_prompt_becomes_its_own_request() {
        // ★ The mapping, rather than the parsing. Three verbs that all reached `IntentSnapshot` would parse, print
        // something plausible, and never decide or cancel anything \u2014 and no argument test would notice.
        let ask = |action: crate::args::IntentAction| {
            question_for(
                &Command::Intent(crate::args::IntentArgs { action }),
                None,
                || None,
            )
            .map(|question| question.request)
        };

        assert!(matches!(
            ask(crate::args::IntentAction::Show { intent: "abc".to_owned() }),
            Some(Request::IntentSnapshot { .. })
        ));
        assert!(matches!(
            ask(crate::args::IntentAction::Decide {
                intent: "abc".to_owned(),
                plugin: None,
                target: None,
            }),
            Some(Request::IntentDecide { .. })
        ));
        assert!(matches!(
            ask(crate::args::IntentAction::Cancel { intent: "abc".to_owned() }),
            Some(Request::IntentCancel { .. })
        ));

        // And the two optional answers survive the trip. A `decide` that dropped them would be one where choosing between
        // several plugins, or answering "where", silently did the default instead.
        let Some(Request::IntentDecide { plugin_id, target, .. }) = ask(
            crate::args::IntentAction::Decide {
                intent: "abc".to_owned(),
                plugin: Some("@acme/opener".to_owned()),
                target: Some("0e5a1c34-0000-4000-8000-000000000001".to_owned()),
            },
        ) else {
            panic!("expected a decide request");
        };
        assert_eq!(plugin_id.as_deref(), Some("@acme/opener"));
        assert_eq!(target.as_deref(), Some("0e5a1c34-0000-4000-8000-000000000001"));
    }

    #[test]
    fn the_two_commands_that_need_no_kernel_say_so() {
        // ★ `doctor` exists for the user whose kernel will not start, and `db` reads the database directly. Sending them
        // over the socket would make the first fail in exactly the case it exists for.
        assert!(
            question_for(
                &Command::Doctor(crate::args::DoctorArgs { failures_only: false, bundle: None }),
                None,
                || None,
            )
            .is_none()
        );
        assert!(question_for(&Command::Db(DbArgs { action: DbAction::Integrity }), None, || None).is_none());
    }

    #[test]
    fn asking_for_json_asks_the_kernel_for_json_shaped_output() {
        // The shape is the request's, not the caller's alone: a command that asked for prose and printed JSON would be
        // one a script could not read.
        let prose = question_for(&Command::Devices(devices_args(false)), None, || None).expect("q");
        assert_eq!(prose.shape, Shape::Prose);
        let json =
            question_for(&Command::Devices(devices_args(false)), Some(OutputFormat::Json), || None)
                .expect("q");
        assert_eq!(json.shape, Shape::Json);
    }

    // ── The outcome ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_json_shape_prints_the_value_pretty() {
        let response = Response::ok(serde_json::json!({"devices": []}));
        match outcome_of(&response, Shape::Json) {
            crate::session::CommandOutcome::Json { body, ok } => {
                assert!(ok, "a success should not be a failure");
                assert!(body.contains('\n'), "not pretty-printed: {body}");
                assert!(body.contains("devices"), "{body}");
            }
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    #[test]
    fn a_prose_shape_summarises_a_status() {
        let response = Response::ok(serde_json::json!({
            "state": "running",
            "version": "0.1.0",
            "dataDir": "/tmp/synra",
            "transportPort": 47100,
            "uptimeMs": 5_000,
            "notImplemented": ["session"],
        }));
        match outcome_of(&response, Shape::Prose) {
            crate::session::CommandOutcome::Lines(lines) => {
                let text = lines.join("\n");
                assert!(text.contains("running"), "{text}");
                assert!(text.contains("0.1.0"), "{text}");
                assert!(text.contains("5s"), "{text}");
                // ★ The missing layer is printed: `status` is what a user runs to find out what is going on, and a
                // summary that hid it would leave them wondering why the next command refuses.
                assert!(text.contains("session"), "{text}");
            }
            other => panic!("expected lines, got {other:?}"),
        }
    }

    #[test]
    fn a_prose_shape_says_when_there_are_no_devices_rather_than_printing_nothing() {
        // A command that printed nothing would look like a command that failed.
        let response = Response::ok(serde_json::json!({"devices": []}));
        match outcome_of(&response, Shape::Prose) {
            crate::session::CommandOutcome::Lines(lines) => {
                assert_eq!(lines, vec!["no devices".to_owned()]);
            }
            other => panic!("expected lines, got {other:?}"),
        }
    }

    #[test]
    fn a_prose_shape_says_when_there_are_no_plugins() {
        let response = Response::ok(serde_json::json!({"plugins": [], "loaded": false}));
        match outcome_of(&response, Shape::Prose) {
            crate::session::CommandOutcome::Lines(lines) => {
                assert!(lines[0].contains("no plugins"), "{lines:?}");
            }
            other => panic!("expected lines, got {other:?}"),
        }
    }

    #[test]
    fn a_device_row_says_both_what_it_is_and_whether_it_is_reachable() {
        // ★ Two different questions, and a row that answered one would make a paired-but-offline device look usable.
        let row = render_device(&serde_json::json!({
            "deviceId": "dev_a", "displayName": "Laptop", "online": false, "paired": true
        }));
        assert!(row.contains("dev_a"), "{row}");
        assert!(row.contains("Laptop"), "{row}");
        assert!(row.contains("paired, offline"), "{row}");

        let row = render_device(&serde_json::json!({
            "deviceId": "dev_b", "online": true, "paired": false
        }));
        assert!(row.contains("not paired"), "{row}");
    }

    #[test]
    fn a_plugin_row_reports_a_problem_instead_of_hiding_it() {
        // A directory in the plugins directory that is not a plugin is something the user should see.
        let row = render_plugin(&serde_json::json!({
            "id": "@acme/hello", "version": "1.2.3", "title": "Hello"
        }));
        assert!(row.contains("@acme/hello"), "{row}");
        assert!(row.contains("1.2.3"), "{row}");

        let broken = render_plugin(&serde_json::json!({
            "id": "broken", "problem": "there is no manifest.json in this directory"
        }));
        assert!(broken.contains("manifest"), "{broken}");
    }

    #[test]
    fn a_prose_shape_falls_back_to_json_for_a_shape_it_does_not_know() {
        // ★ A client older than the kernel must print the answer rather than nothing. The fallback is ugly and complete,
        // and complete is what a user filing a bug report needs.
        let response = Response::ok(serde_json::json!({"somethingNew": {"a": 1}}));
        match outcome_of(&response, Shape::Prose) {
            crate::session::CommandOutcome::Lines(lines) => {
                assert!(lines.join("").contains("somethingNew"), "{lines:?}");
            }
            other => panic!("expected lines, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_is_a_failure_with_its_code_and_a_non_zero_exit() {
        // ★ A refusal is the kernel *answering*: a result, with a code a script reads. Collapsing it with a transport
        // error would make "the device is offline" indistinguishable from "no kernel is running".
        let response = Response::failed(
            ErrorCode::Unsupported.as_str(),
            "the session layer is not implemented yet",
            false,
        );
        match outcome_of(&response, Shape::Prose) {
            crate::session::CommandOutcome::Json { body, ok } => {
                assert!(!ok, "a refusal must not be a success");
                assert!(body.contains("unsupported"), "{body}");
                assert!(body.contains("session layer"), "{body}");
            }
            other => panic!("expected a JSON failure, got {other:?}"),
        }
        // The same shape whatever output was asked for, so a script does not have to tell prose from JSON.
        assert!(matches!(
            outcome_of(&response, Shape::Json),
            crate::session::CommandOutcome::Json { ok: false, .. }
        ));
    }

    #[test]
    fn a_hello_response_is_readable_rather_than_json() {
        let response = Response::Hello { version: 1, kernel: "0.1.0".to_owned() };
        match outcome_of(&response, Shape::Prose) {
            crate::session::CommandOutcome::Lines(lines) => {
                assert!(lines[0].contains("0.1.0"), "{lines:?}");
                assert!(lines[0].contains('1'), "{lines:?}");
            }
            other => panic!("expected lines, got {other:?}"),
        }
    }

    #[test]
    fn a_transport_failure_names_the_path_the_client_looked_at() {
        // ★ A generic "no kernel" would hide the fact that the client looked somewhere specific — and the commonest
        // cause is that it looked in the wrong place, which is exactly what `SYNRA_DATA_DIR` is for.
        let error = synra_control::SocketError::Connect {
            path: std::path::PathBuf::from("/tmp/synra/kernel.sock"),
            why: "no such file".to_owned(),
        };
        match transport_failure(&error) {
            crate::session::CommandOutcome::Json { body, ok } => {
                assert!(!ok);
                assert!(body.contains("kernel.sock"), "{body}");
                assert!(body.contains("transport_not_open"), "{body}");
            }
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    #[test]
    fn a_transport_failure_is_retryable_which_is_why_a_script_should_wait() {
        // `transport_not_open` is retryable in the kernel, and the client reads that rather than deciding. A kernel that
        // is still starting is the ordinary case.
        assert!(ErrorCode::TransportNotOpen.retryable());
    }


    #[test]
    fn the_pair_command_names_the_device_it_was_given() {
        // The command that names the missing producer: pairing could be answered before this existed, but never asked
        // for. The assertion is on the operand, because a device name that did not reach the request is a command whose
        // argument is silently ignored — and the output would look plausible either way.
        let question = question_for(
            &Command::Pair(PairArgs { device: "Laptop".to_owned() }),
            None,
            || None,
        )
        .expect("a question");
        assert_eq!(question.request, Request::Pair { device: "Laptop".to_owned() });
    }

    #[test]
    fn the_pair_command_honours_the_output_flag() {
        // A user asking for JSON gets JSON. Pinned to prose here would be the wrong answer to the question they asked,
        // which is the mistake `status` made once.
        let question = question_for(
            &Command::Pair(PairArgs { device: "Laptop".to_owned() }),
            Some(OutputFormat::Json),
            || None,
        )
        .expect("a question");
        assert_eq!(question.shape, Shape::Json);
    }
}
