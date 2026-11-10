//! Plugin-related CLI subcommands.

use clap::{Args, Subcommand};

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
    /// List known signing keys or decide whether to trust one.
    Publisher {
        /// What to do with the publisher key.
        #[command(subcommand)]
        action: PublisherAction,
    },
    /// Read or replace the ordered registry sources. Use --clear to disable registry access.
    Registry {
        /// HTTPS npm URLs or static: URLs, in fallback order. Omit to read the current setting.
        #[arg(value_name = "URL", conflicts_with = "clear")]
        urls: Vec<String>,
        /// Remove the registry setting.
        #[arg(long)]
        clear: bool,
    },
    /// Read or set the background update policy.
    Policy {
        /// Omit to read the policy; notify-only is the default.
        #[arg(value_parser = ["never", "notify-only", "auto-minor", "auto-all"])]
        policy: Option<String>,
    },
    /// Check one installed plugin or all of them now, without installing anything.
    Check {
        /// Omit to check all installed plugins.
        plugin_id: Option<String>,
    },
    /// Update an installed plugin from its configured registry.
    Update {
        /// The installed plugin identifier.
        plugin_id: String,
        /// An exact version or range; omit to use latest. Updates must advance the version.
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
    },
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
    /// Reinstall the plugins a `.synrabackup` container lists, from the sources it recorded.
    ///
    /// # Why this is a command rather than part of `db import`
    ///
    /// Because the import needs the kernel stopped (it replaces the database) and installing needs it running (it verifies
    /// and writes through the pipeline the kernel owns). Making one command do both would mean the import had to start a
    /// kernel it does not own; splitting them is the honest shape of the two acts.
    Reinstall {
        /// The container whose plugin list to follow.
        #[arg(value_name = "PATH")]
        from: std::path::PathBuf,
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
    /// Record what a plugin may do.
    ///
    /// # Why the capabilities are named rather than confirmed
    ///
    /// Because a command line has no way to ask. The interface shows what a plugin declares and the user ticks it; here
    /// the user names what they allow, and everything declared but not named is recorded as **denied** — the same
    /// decision, written down where a script can make it too.
    Consent {
        /// The plugin.
        plugin_id: String,
        /// A capability to allow, repeated for each one. Naming none denies everything the plugin asks for.
        #[arg(long = "allow", value_name = "CAPABILITY")]
        allow: Vec<String>,
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

/// Explicit decisions about previously verified signing keys.
#[derive(Debug, Subcommand)]
pub enum PublisherAction {
    /// List publishers, their key fingerprints and this device's decisions.
    List,
    /// Trust, revoke, or clear a decision for the displayed key. Does not grant plugin capabilities.
    Decide {
        /// A publisher this device has met through a verified package.
        publisher_id: String,
        /// The decision to record.
        #[arg(value_parser = ["seen", "trusted", "revoked"])]
        trust: String,
        /// The fingerprint shown by publisher list; quote it when it contains spaces.
        #[arg(long, value_name = "FINGERPRINT")]
        fingerprint: String,
    },
}


