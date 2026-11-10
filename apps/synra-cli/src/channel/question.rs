use synra_control::Request;

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
        Command::Status => Some(Question {
            request: Request::Status,
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
                request: Request::SendText {
                    to: args.to.clone(),
                    text: text.clone(),
                },
                shape,
            }),
            (None, Some(path)) => Some(Question {
                request: Request::SendFile {
                    to: args.to.clone(),
                    path: path.clone(),
                },
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
                IntentAction::Show { intent } => Request::IntentSnapshot {
                    intent: intent.clone(),
                },
                IntentAction::Decide {
                    intent,
                    plugin,
                    target,
                } => Request::IntentDecide {
                    intent: intent.clone(),
                    plugin_id: plugin.clone(),
                    target: target.clone(),
                },
                IntentAction::Cancel { intent } => Request::IntentCancel {
                    intent: intent.clone(),
                },
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

#[cfg(test)]
mod tests;
