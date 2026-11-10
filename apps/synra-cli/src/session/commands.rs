use crate::args::{Cli, Command};
use synra_control::{Client, Request};
use synra_store::Paths;

use super::{data_root, doctor_outcome, CommandOutcome};

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
                    // ★ Reinstalling is several requests over one container file. A `Question` carries one, so this one
                    // plugin action is dispatched here rather than through `question_for`.
                    Command::Plugin(args)
                        if matches!(&args.action, crate::args::PluginAction::Reinstall { .. }) =>
                    {
                        crate::channel::reinstall(args, cli.output)
                    }
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
pub(crate) fn plugin_request(command: &Command) -> Option<Request> {
    use crate::args::{PluginAction, PublisherAction};

    let Command::Plugin(args) = command else {
        return None;
    };
    match &args.action {
        PluginAction::Publisher { action } => Some(match action {
            PublisherAction::List => Request::PluginPublishers,
            PublisherAction::Decide { publisher_id, fingerprint, trust } => {
                Request::PluginPublisherDecide {
                    publisher_id: publisher_id.clone(),
                    fingerprint: fingerprint.clone(),
                    trust: trust.clone(),
                }
            }
        }),
        PluginAction::Registry { urls, clear } => Some(Request::PluginRegistry {
            urls: if *clear {
                Some(Vec::new())
            } else if urls.is_empty() {
                None
            } else {
                Some(urls.clone())
            },
        }),
        PluginAction::Policy { policy } => Some(Request::PluginUpdatePolicy { policy: policy.clone() }),
        PluginAction::Check { plugin_id } => Some(Request::PluginCheckUpdates {
            plugin_id: plugin_id.clone(),
        }),
        PluginAction::Update { plugin_id, version } => Some(Request::PluginUpdate {
            plugin_id: plugin_id.clone(),
            version: version.clone(),
        }),
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
        PluginAction::Install { source, version } => Some(if registry_reference(source) {
            Request::PluginInstallPackage {
                package: source.clone(),
                version: version.clone(),
            }
        }
        else {
            Request::PluginInstall { path: source.clone() }
        }),
        // ★ Reinstalling is a sequence of installs, not one request: the container's list is read here and each source is
        // sent to the kernel in turn. It is handled in `dispatch` before this mapping is asked, because `Question` holds
        // one request and this act has as many as the container lists.
        PluginAction::Reinstall { .. } => None,
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

/// Whether an install argument names a registry package rather than a path.
///
/// # The rule
///
/// An existing path is a path, whatever it is called. A relative or absolute path that does not exist is still a path —
/// the installer's "there is no such directory" is the useful answer. Everything else that has no separator is a package
/// name, and a scoped name (`@scope/name`) is the one package form that contains a slash.
///
/// `--version` only means something for a package, and it is carried rather than applied here: the kernel is the side that
/// knows which versions a registry offers.
pub(crate) fn registry_reference(source: &str) -> bool {
    if std::path::Path::new(source).exists() {
        return false;
    }
    if source.starts_with('.') || source.starts_with('/') || source.contains(":/") || source.contains(":\\") {
        return false;
    }
    source.starts_with('@') || !source.contains(['/', '\\'])
}
