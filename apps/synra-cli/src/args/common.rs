//! Core CLI command types and payload validation.

use clap::{Args, Parser, Subcommand};

use super::misc::{DbArgs, DoctorArgs, LogsArgs};
use super::plugins::PluginArgs;

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
    /// Show the kernel's state and its links.
    Status,
    /// Inspect or explicitly repair this device identity and revoke its old pairings.
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


