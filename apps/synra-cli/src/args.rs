//! The command surface: what a user types, and what it means.
//!
//! # Why the parser is a value
//!
//! The command line is a contract with a person, and the failures it produces are the ones a person reads: a missing
//! flag, an unknown subcommand, two flags that contradict each other. Every one of those is decidable from the
//! arguments alone, so putting them in a type worth testing means the failures are tested rather than discovered by
//! whoever types the command wrong.
//!
//! It is also what keeps `main.rs` short. The design document requires it to be at most sixty lines with the logic in
//! this crate's library, because a `main` that grew would be a `main` that holds the one part of a CLI nobody writes
//! tests for.
//!
//! # Flags that contradict each other are refused
//!
//! `send --text "hi" --file a.txt` is not "one of them wins". It is a user who meant one thing and typed two, and
//! guessing produces a message that goes somewhere they did not intend. `clap`'s `conflicts_with` makes it an error
//! with both flags in the message.
//!
//! # The subcommands mirror the kernel's aggregates
//!
//! `devices`, `status`, `send`, `plugin`, `logs`, `doctor`, `db`. Not one command per Tauri command — the interface
//! has forty because it drives every screen, and a person on a terminal wants seven. The mapping is the aggregate,
//! which is why a new kernel feature tends to land inside an existing group rather than adding a command.

use clap::{Args, Parser, Subcommand};

/// The kernel's command-line host.
///
/// It exists for two reasons, and the second is the one that matters: it is a usable tool, and it is the **proof that
/// the kernel needs no interface**. If a command here cannot work without Tauri, the kernel's boundary has broken —
/// which is why it shares nothing with the application but the kernel's own public API.
#[derive(Debug, Parser)]
#[command(
    name = "synra",
    version,
    about = "The Synra kernel's command-line host",
    long_about = "Talks to a running kernel over its local socket, or runs one in-process for the commands that \
                  do not need a link.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Where to write a machine-readable result instead of prose.
    #[arg(long, global = true, value_name = "FORMAT")]
    pub output: Option<OutputFormat>,

    /// The subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// How a result is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable, which is the default.
    Text,
    /// One JSON value, for a script.
    ///
    /// For a caller that is another program. The alternative is parsing the prose, which is a parser that breaks
    /// whenever a sentence changes.
    Json,
}

/// What the user asked for.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List the devices this kernel has seen.
    Devices(DevicesArgs),
    /// Ask a device to pair with this one.
    Pair(PairArgs),
    /// Show the kernel's state and its links.
    Status,
    /// Send text or a file to a device.
    Send(SendArgs),
    /// Manage plugins.
    Plugin(PluginArgs),
    /// Show the kernel's log.
    Logs(LogsArgs),
    /// Hand something to the kernel to route.
    Share(ShareArgs),
    /// Answer a prompt about something being routed.
    Intent(IntentArgs),
    /// Check that this machine can run the kernel.
    Doctor(DoctorArgs),
    /// Read the database directly.
    Db(DbArgs),
}

/// Options for `share`.
///
/// # Why this is its own group rather than a flag on `send`
///
/// Because the two are opposites. `send` names a device and delivers to it; `share` names nothing, and the kernel asks
/// every plugin which one can handle it. A flag on `send` would suggest the destination is a detail of the same act, and
/// it is the whole difference.
#[derive(Debug, Args)]
pub struct ShareArgs {
    /// What to route: a link, a line of text, a path.
    #[arg(value_name = "TEXT")]
    pub text: String,

    /// What it is, for a plugin that cares.
    ///
    /// Defaults to `text/plain`, which is what a bare argument is. A link is `text/uri-list`, and passing that is how a
    /// caller says so rather than the kernel guessing from the contents — a string that merely looks like a URL is not
    /// one, and a plugin that opened it would be acting on a guess.
    #[arg(long, value_name = "MIME", default_value = "text/plain")]
    pub mime: String,
}

/// Options for `intent`.
#[derive(Debug, Args)]
pub struct IntentArgs {
    /// What to do with it.
    #[command(subcommand)]
    pub action: IntentAction,
}

/// The three answers a prompt can get.
///
/// # Why `show` is one of them
///
/// Because `share` returns an identifier and nothing else, and a caller who has an identifier needs to be able to look it
/// up again — a prompt is answered in a later command, possibly by a different program. Without `show` the identifier
/// `share` prints is a value with no use.
#[derive(Debug, Subcommand)]
pub enum IntentAction {
    /// Ask what has become of an intent.
    Show {
        /// Which intent, as `share` printed it.
        #[arg(value_name = "INTENT")]
        intent: String,
    },
    /// Decide it: take the candidate the board settled on, or one the user names.
    Decide {
        /// Which intent.
        #[arg(value_name = "INTENT")]
        intent: String,
        /// Which plugin, when the user was choosing between several.
        ///
        /// Omitted takes the candidate the board already settled on, which is the ordinary case: one plugin claimed the
        /// share and there is nothing to choose between.
        #[arg(long, value_name = "PLUGIN")]
        plugin: Option<String>,
        /// Where to run it, when the plugin that claimed the share did not say.
        ///
        /// A device identifier, as `devices` prints it. This is the answer to the question a plugin leaves open by
        /// suggesting nowhere.
        #[arg(long, value_name = "DEVICE")]
        target: Option<String>,
    },
    /// Abandon it.
    Cancel {
        /// Which intent.
        #[arg(value_name = "INTENT")]
        intent: String,
    },
}

/// Options for `devices`.
#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// Include devices that are not paired.
    ///
    /// Off by default: a paired device is one the user has decided about, and a list that mixes in everything heard
    /// on the network is a list where the interesting entries are the hard ones to find.
    #[arg(long)]
    pub all: bool,

    /// Scan for a while before listing.
    #[arg(long, value_name = "MS", conflicts_with = "cached")]
    pub scan_ms: Option<u64>,

    /// List only what the kernel already knows, without scanning.
    #[arg(long)]
    pub cached: bool,
}

/// Options for `pair`.
#[derive(Debug, Args)]
pub struct PairArgs {
    /// The device to ask. A device id, a display name if it is unambiguous, or `host:port`.
    ///
    /// # Why this blocks
    ///
    /// Because the answer is a person on the other device deciding, and there is nothing to print until they have. The
    /// wait is bounded by the kernel's pairing window — the same one the other side shows a countdown for — so this
    /// cannot hang for ever, and the kernel clears its own waiting state when the window closes.
    #[arg(value_name = "DEVICE")]
    pub device: String,
}

/// Options for `send`.
#[derive(Debug, Args)]
pub struct SendArgs {
    /// The device to send to. A device id, or a display name if it is unambiguous.
    #[arg(long, value_name = "DEVICE")]
    pub to: String,

    /// Text to send.
    #[arg(long, value_name = "TEXT", conflicts_with = "file")]
    pub text: Option<String>,

    /// A file to send.
    #[arg(long, value_name = "PATH")]
    pub file: Option<String>,

    /// An identifier grouping this with a conversation, for the receiver's interface.
    #[arg(long, value_name = "ID")]
    pub context: Option<String>,
}

impl SendArgs {
    /// What was asked for.
    ///
    /// # Why this is a method rather than a field
    ///
    /// `clap` can require one of a group, but it cannot say "exactly one and say which" in the error. A user who
    /// typed neither gets a sentence naming both flags instead of a usage line, and that is the difference between
    /// reading the help and re-typing the line.
    ///
    /// # Errors
    ///
    /// [`PayloadError::NothingToSend`] when neither was given, and [`PayloadError::Both`] when both were — the
    /// second is unreachable through `clap` and is here because a caller building `SendArgs` in code would not go
    /// through the parser.
    pub fn payload(&self) -> Result<Payload<'_>, PayloadError> {
        match (&self.text, &self.file) {
            (Some(text), None) => Ok(Payload::Text(text)),
            (None, Some(path)) => Ok(Payload::File(path)),
            (None, None) => Err(PayloadError::NothingToSend),
            (Some(_), Some(_)) => Err(PayloadError::Both),
        }
    }
}

/// What a `send` would carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    /// Text.
    Text(&'a str),
    /// A file, by path.
    File(&'a str),
}

/// Why a `send` cannot proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PayloadError {
    /// Neither `--text` nor `--file`.
    #[error("a send needs `--text` or `--file`")]
    NothingToSend,

    /// Both, which the parser refuses and a caller building the arguments in code would not.
    #[error("a send takes `--text` or `--file`, and not both")]
    Both,
}

/// Options for `plugin`.
#[derive(Debug, Args)]
pub struct PluginArgs {
    /// What to do.
    #[command(subcommand)]
    pub action: PluginAction,
}

/// What to do with a plugin.
#[derive(Debug, Subcommand)]
pub enum PluginAction {
    /// List the installed plugins.
    List {
        /// Include plugins that are installed but disabled.
        #[arg(long)]
        all: bool,
    },
    /// Search a registry for a plugin.
    ///
    /// ★ Why this is not `install --dry-run`.
    ///
    /// Because searching and installing fail for different reasons and a person runs them at different times: a search is
    /// what somebody does while deciding, and it is the command that shows the design's *offline mode* — a cached catalogue
    /// with its age — rather than refusing. Burying it in an install flag would make "what is available" a question only
    /// somebody already installing could ask.
    Search {
        /// The package, as a registry spells it, such as `@acme/chat`.
        package: String,
    },
    /// Install a plugin from a path or a registry.
    Install {
        /// A path to a package, or a `@scope/name` for a registry.
        source: String,
        /// A version, when installing from a registry.
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
    },
    /// Enable a plugin.
    Enable {
        /// The plugin.
        plugin_id: String,
    },
    /// Disable a plugin.
    Disable {
        /// The plugin.
        plugin_id: String,
    },
    /// Remove a plugin.
    Remove {
        /// The plugin.
        plugin_id: String,
        /// Also delete its data.
        ///
        /// Off by default: removing a plugin the user may reinstall should keep its settings, and one they do not
        /// trust is what this flag is for.
        #[arg(long)]
        data: bool,
    },
}

/// Options for `logs`.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Keep printing as lines arrive.
    #[arg(long, short)]
    pub follow: bool,

    /// Show only the lines for one trace.
    #[arg(long, value_name = "TRACE_ID")]
    pub trace: Option<String>,

    /// How many lines of history to show first.
    #[arg(long, value_name = "COUNT", default_value_t = 100)]
    pub lines: u32,

    /// Show the lowest-severity lines too.
    ///
    /// Off by default, and it is the setting that decides whether the output is readable: a kernel at debug level
    /// prints more in a second than a person reads in a minute.
    #[arg(long)]
    pub verbose: bool,
}

/// Options for `doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Only report the probes that failed.
    #[arg(long)]
    pub failures_only: bool,

    /// Write a diagnostic bundle here.
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<String>,
}

/// Options for `db`.
#[derive(Debug, Args)]
pub struct DbArgs {
    /// What to read.
    #[command(subcommand)]
    pub action: DbAction,
}

/// What to read from the database.
#[derive(Debug, Subcommand)]
pub enum DbAction {
    /// Dump the tables a debugger wants, as JSON.
    Dump {
        /// One table, or every table.
        #[arg(long, value_name = "TABLE")]
        table: Option<String>,
    },
    /// Check the database for damage.
    ///
    /// The same check the kernel runs at start-up, exposed because a user who suspects their database is the one who
    /// needs to run it — and because a support conversation goes faster with the answer than with a guess.
    Integrity,
    /// Write a consistent copy of the database to a path.
    ///
    /// # Why this is a command rather than a note in the documentation
    ///
    /// Because copying the file is the obvious thing to do and it does not work: a live database also has a
    /// write-ahead log, and a plain copy of the main file is a database that may not open at all. The design document
    /// lists restore-from-backup as the recovery path when the integrity check fails, so the step has to exist before
    /// the moment somebody needs it.
    Backup {
        /// Where to write it. Must not already exist.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn parsed(args: &[&str]) -> Cli {
        parse(args).expect("parses")
    }

    // ── The command surface ───────────────────────────────────────────────────────────────────────

    #[test]
    fn the_parser_is_internally_consistent() {
        // `clap`'s own check for a command tree it cannot describe: two flags with one long name, a subcommand with a
        // required argument that has no help, and so on. It is a build failure rather than something a user finds.
        Cli::command().debug_assert();
    }

    #[test]
    fn every_documented_command_exists() {
        // The design document's list, as an executable statement. A command in the document and not here is one a
        // user types and gets an error for.
        for args in [
            vec!["synra", "devices"],
            vec!["synra", "status"],
            vec!["synra", "pair", "dev_a"],
            vec!["synra", "send", "--to", "dev_a", "--text", "hi"],
            vec!["synra", "send", "--to", "dev_a", "--file", "a.txt"],
            vec!["synra", "plugin", "list"],
            vec!["synra", "plugin", "install", "@synra-plugin/chat"],
            vec!["synra", "plugin", "enable", "@synra-plugin/chat"],
            vec!["synra", "plugin", "disable", "@synra-plugin/chat"],
            vec!["synra", "plugin", "remove", "@synra-plugin/chat"],
            vec!["synra", "logs"],
            vec!["synra", "doctor"],
            vec!["synra", "db", "dump"],
                vec!["synra", "share", "https://example.com"],
                vec!["synra", "intent", "show", "01a140ce-0000-7000-8000-000000000000"],
        ] {
            assert!(parse(&args).is_ok(), "{args:?} should parse");
        }
    }

    #[test]
    fn an_unknown_command_is_refused() {
        assert!(parse(&["synra", "devices_"]).is_err());
        // `pair` is a real command now, so it is refused for a different reason: it needs a device to ask. The two are
        // distinct failures and both belong here, because a user who types a bare `pair` should be told what is missing
        // rather than that the command does not exist.
        assert!(parse(&["synra", "pair"]).is_err(), "pairing needs a device");
        assert!(parse(&["synra"]).is_err(), "a bare invocation needs a subcommand");
    }

    #[test]
    fn the_help_subcommand_is_disabled() {
        // `clap` adds a `help` subcommand by default, and it collides with a future command of that name while
        // shadowing the flag. The flag is what a user already reaches for.
        let command = Cli::command();
        let names: Vec<&str> = command.get_subcommands().map(|sub| sub.get_name()).collect();
        assert!(!names.contains(&"help"), "{names:?}");
        assert!(parse(&["synra", "--help"]).is_err(), "`--help` exits rather than parsing");
    }

    // ── Output format ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_output_format_is_global_and_defaults_to_prose() {
        // Global so it can go before or after the subcommand: a user who types it in the wrong place should not have
        // to be told where it goes.
        assert!(parsed(&["synra", "status"]).output.is_none());
        assert_eq!(parsed(&["synra", "--output", "json", "status"]).output, Some(OutputFormat::Json));
        assert_eq!(parsed(&["synra", "status", "--output", "json"]).output, Some(OutputFormat::Json));
        assert_eq!(parsed(&["synra", "--output", "text", "status"]).output, Some(OutputFormat::Text));
    }

    #[test]
    fn an_unknown_output_format_is_refused() {
        // A typo that silently fell back to prose would make a script parse the wrong thing.
        assert!(parse(&["synra", "--output", "yaml", "status"]).is_err());
    }

    // ── Devices ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn devices_defaults_to_paired_only_and_no_scan() {
        // A paired device is one the user has decided about, and a list mixing in everything heard on the network is
        // one where the interesting entries are hard to find.
        let cli = parsed(&["synra", "devices"]);
        let Command::Devices(args) = cli.command else {
            panic!("expected devices");
        };
        assert!(!args.all);
        assert!(!args.cached);
        assert_eq!(args.scan_ms, None);
    }

    #[test]
    fn devices_accepts_a_scan_and_a_cache_read_but_not_both() {
        // Scanning and reading the cache are opposite requests. Accepting both would mean one of them silently losing.
        let Command::Devices(scan) = parsed(&["synra", "devices", "--scan-ms", "2500"]).command else {
            panic!("expected devices");
        };
        assert_eq!(scan.scan_ms, Some(2_500));

        let Command::Devices(cached) = parsed(&["synra", "devices", "--cached"]).command else {
            panic!("expected devices");
        };
        assert!(cached.cached);

        assert!(parse(&["synra", "devices", "--scan-ms", "2500", "--cached"]).is_err());
    }

    // ── Send ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn send_requires_a_target_and_a_payload() {
        // Both are required, and they are required in different places: the target by `clap`, because "which device"
        // is a flag a user plainly has to give, and the payload by `SendArgs::payload`, because "one of two flags"
        // with a sentence naming both is a better message than a usage line.
        assert!(parse(&["synra", "send", "--text", "hi"]).is_err(), "no target");
        assert!(
            parse(&["synra", "send", "--to", "dev_a"]).is_ok(),
            "the parser accepts it, and `payload` is what refuses it"
        );
        let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a"]).command else {
            panic!("expected send");
        };
        assert_eq!(args.payload(), Err(PayloadError::NothingToSend));
    }

    #[test]
    fn send_refuses_both_payloads_at_the_parser() {
        // Not "one of them wins": a user who typed both meant one thing, and guessing produces a message that goes
        // somewhere they did not intend.
        let error = parse(&["synra", "send", "--to", "dev_a", "--text", "hi", "--file", "a.txt"])
            .expect_err("should be refused");
        let text = error.to_string();
        assert!(text.contains("text"), "{text}");
        assert!(text.contains("file"), "{text}");
    }

    #[test]
    fn send_carries_text() {
        let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a", "--text", "hi"]).command else {
            panic!("expected send");
        };
        assert_eq!(args.to, "dev_a");
        assert_eq!(args.payload(), Ok(Payload::Text("hi")));
    }

    #[test]
    fn send_carries_a_file() {
        let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a", "--file", "a.txt"]).command else {
            panic!("expected send");
        };
        assert_eq!(args.payload(), Ok(Payload::File("a.txt")));
    }

    #[test]
    fn a_payload_built_in_code_is_checked_too() {
        // `clap` cannot be reached by a caller building the arguments directly, and the two shapes it refuses are the
        // two that would otherwise be decided by whichever field a caller read first.
        let neither = SendArgs {
            to: "dev_a".to_owned(),
            text: None,
            file: None,
            context: None,
        };
        assert_eq!(neither.payload(), Err(PayloadError::NothingToSend));

        let both = SendArgs {
            to: "dev_a".to_owned(),
            text: Some("hi".to_owned()),
            file: Some("a.txt".to_owned()),
            context: None,
        };
        assert_eq!(both.payload(), Err(PayloadError::Both));
    }

    #[test]
    fn send_accepts_a_context() {
        let Command::Send(args) = parsed(&[
            "synra", "send", "--to", "dev_a", "--text", "hi", "--context", "c1",
        ])
        .command
        else {
            panic!("expected send");
        };
        assert_eq!(args.context.as_deref(), Some("c1"));
    }

    #[test]
    fn an_empty_payload_is_text_rather_than_nothing() {
        // `--text ""` is a user sending an empty message, which is a thing people do. Treating it as "no payload"
        // would refuse a valid invocation.
        let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a", "--text", ""]).command else {
            panic!("expected send");
        };
        assert_eq!(args.payload(), Ok(Payload::Text("")));
    }

    // ── Plugins ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn plugin_list_defaults_to_enabled_plugins() {
        let Command::Plugin(args) = parsed(&["synra", "plugin", "list"]).command else {
            panic!("expected plugin");
        };
        let PluginAction::List { all } = args.action else {
            panic!("expected list");
        };
        assert!(!all, "a disabled plugin is not one the user is looking for by default");
    }

    #[test]
    fn plugin_install_takes_a_path_or_a_registry_name() {
        let Command::Plugin(args) = parsed(&["synra", "plugin", "install", "./chat.synra"]).command else {
            panic!("expected plugin");
        };
        let PluginAction::Install { source, version } = args.action else {
            panic!("expected install");
        };
        assert_eq!(source, "./chat.synra");
        assert_eq!(version, None);

        let Command::Plugin(args) =
            parsed(&["synra", "plugin", "install", "@synra-plugin/chat", "--version", "1.0.0"]).command
        else {
            panic!("expected plugin");
        };
        let PluginAction::Install { version, .. } = args.action else {
            panic!("expected install");
        };
        assert_eq!(version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn plugin_remove_keeps_the_data_unless_asked() {
        // Removing a plugin the user may reinstall should keep its settings; one they do not trust is what the flag is
        // for.
        let Command::Plugin(args) = parsed(&["synra", "plugin", "remove", "@synra-plugin/chat"]).command else {
            panic!("expected plugin");
        };
        let PluginAction::Remove { data, .. } = args.action else {
            panic!("expected remove");
        };
        assert!(!data);

        let Command::Plugin(args) =
            parsed(&["synra", "plugin", "remove", "@synra-plugin/chat", "--data"]).command
        else {
            panic!("expected plugin");
        };
        let PluginAction::Remove { data, .. } = args.action else {
            panic!("expected remove");
        };
        assert!(data);
    }

    #[test]
    fn a_plugin_action_needs_its_plugin() {
        assert!(parse(&["synra", "plugin", "enable"]).is_err());
        assert!(parse(&["synra", "plugin", "remove"]).is_err());
        assert!(parse(&["synra", "plugin", "install"]).is_err());
    }

    // ── Logs ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn logs_defaults_to_a_hundred_lines_and_no_follow() {
        let Command::Logs(args) = parsed(&["synra", "logs"]).command else {
            panic!("expected logs");
        };
        assert_eq!(args.lines, 100);
        assert!(!args.follow);
        assert!(!args.verbose);
        assert_eq!(args.trace, None);
    }

    #[test]
    fn logs_follows_and_filters() {
        let Command::Logs(args) =
            parsed(&["synra", "logs", "--follow", "--trace", "t1", "--lines", "10", "--verbose"]).command
        else {
            panic!("expected logs");
        };
        assert!(args.follow);
        assert!(args.verbose);
        assert_eq!(args.trace.as_deref(), Some("t1"));
        assert_eq!(args.lines, 10);
    }

    #[test]
    fn logs_follow_has_a_short_form() {
        // Because it is the flag a user types most, and typing `--follow` while watching a log is friction.
        let Command::Logs(args) = parsed(&["synra", "logs", "-f"]).command else {
            panic!("expected logs");
        };
        assert!(args.follow);
    }

    #[test]
    fn a_line_count_that_is_not_a_number_is_refused() {
        assert!(parse(&["synra", "logs", "--lines", "many"]).is_err());
        assert!(parse(&["synra", "logs", "--lines", "-1"]).is_err());
    }

    // ── Doctor and db ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn doctor_reports_everything_by_default() {
        // A user running `doctor` wants the whole picture; `--failures-only` is for a script.
        let Command::Doctor(args) = parsed(&["synra", "doctor"]).command else {
            panic!("expected doctor");
        };
        assert!(!args.failures_only);
        assert_eq!(args.bundle, None);
    }

    #[test]
    fn doctor_can_write_a_bundle_and_be_quiet() {
        let Command::Doctor(args) =
            parsed(&["synra", "doctor", "--failures-only", "--bundle", "/tmp/d.json"]).command
        else {
            panic!("expected doctor");
        };
        assert!(args.failures_only);
        assert_eq!(args.bundle.as_deref(), Some("/tmp/d.json"));
    }

    #[test]
    fn db_dump_takes_an_optional_table() {
        let Command::Db(args) = parsed(&["synra", "db", "dump"]).command else {
            panic!("expected db");
        };
        let DbAction::Dump { table } = args.action else {
            panic!("expected dump");
        };
        assert_eq!(table, None);

        let Command::Db(args) = parsed(&["synra", "db", "dump", "--table", "plugins"]).command else {
            panic!("expected db");
        };
        let DbAction::Dump { table } = args.action else {
            panic!("expected dump");
        };
        assert_eq!(table.as_deref(), Some("plugins"));
    }

    #[test]
    fn db_integrity_needs_nothing() {
        let Command::Db(args) = parsed(&["synra", "db", "integrity"]).command else {
            panic!("expected db");
        };
        assert!(matches!(args.action, DbAction::Integrity));
    }

    #[test]
    fn payload_errors_explain_themselves() {
        for error in [PayloadError::NothingToSend, PayloadError::Both] {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn share_asks_the_kernel_to_route_rather_than_to_send() {
        // ★ The two are opposites and the difference is the whole feature: `send` names a device and delivers to it,
        // `share` names nothing and asks every plugin which one can handle it. A `share` that quietly became a `send`
        // would look identical from the command line and do something else entirely.
        let Command::Share(args) = parsed(&["synra", "share", "https://example.com"]).command else {
            panic!("share is a command");
        };
        assert_eq!(args.text, "https://example.com");
        // The default is `text/plain`, which is what a bare argument is. A link is `text/uri-list`, and the caller says
        // so rather than the kernel guessing from the contents.
        assert_eq!(args.mime, "text/plain");

        let Command::Share(args) =
            parsed(&["synra", "share", "--mime", "text/uri-list", "https://example.com"]).command
        else {
            panic!("share is a command");
        };
        assert_eq!(args.mime, "text/uri-list");
    }

    #[test]
    fn the_three_answers_to_a_prompt_each_parse() {
        // ★ `share` prints an identifier and these are the commands that spend it. Before them, routing could be
        // started from the command line and never finished there — the identifier was a value with no second command.
        let Command::Intent(args) =
            parsed(&["synra", "intent", "show", "01a140ce-0000-7000-8000-000000000000"]).command
        else {
            panic!("intent is a command");
        };
        assert!(matches!(args.action, IntentAction::Show { .. }));

        let Command::Intent(args) = parsed(&["synra", "intent", "decide", "abc"]).command else {
            panic!("intent is a command");
        };
        // Both optional: omitting them is the ordinary case — one plugin claimed the share and named where to run it.
        assert!(matches!(
            args.action,
            IntentAction::Decide { plugin: None, target: None, .. }
        ));

        // And naming them is how a user answers a share that left either open.
        let Command::Intent(args) = parsed(&[
            "synra",
            "intent",
            "decide",
            "abc",
            "--plugin",
            "@acme/opener",
            "--target",
            "0e5a1c34-0000-4000-8000-000000000001",
        ])
        .command
        else {
            panic!("intent is a command");
        };
        match args.action {
            IntentAction::Decide { plugin, target, .. } => {
                assert_eq!(plugin.as_deref(), Some("@acme/opener"));
                assert_eq!(target.as_deref(), Some("0e5a1c34-0000-4000-8000-000000000001"));
            }
            other => panic!("expected decide, got {other:?}"),
        }

        let Command::Intent(args) = parsed(&["synra", "intent", "cancel", "abc"]).command else {
            panic!("intent is a command");
        };
        assert!(matches!(args.action, IntentAction::Cancel { .. }));
    }

    // ── The main.rs bound ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_parser_lives_in_the_library_rather_than_in_main() {
        // The design document requires `main.rs` to be at most sixty lines with the logic here, and a CI guard checks
        // the count. This asserts the half that can be asserted from inside: that the whole command surface is
        // reachable without `main`.
        assert!(Cli::command().get_name() == "synra");
        // Counted rather than named, so adding a command without adding it here is a failure — and the count is what
        // makes the list above (`every_documented_command_exists`) meaningful: a command that parses but is not on the
        // command surface would be one clap never dispatches to.
        assert_eq!(Cli::command().get_subcommands().count(), 10);
    }
}
