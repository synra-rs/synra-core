//! Logs, diagnostics and database CLI subcommands.

use clap::{Args, Subcommand};

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
    /// Replace the database with a backup.
    ///
    /// # Why the old file is kept
    ///
    /// Because the reason to run this is usually that the current database looks damaged, and "looks damaged" is a
    /// diagnosis. The file that was there is moved aside rather than deleted, so a wrong diagnosis is recoverable; the
    /// command says where it went.
    ///
    /// The kernel must be stopped: replacing a database under a process that has it open is how a recovery becomes a
    /// second failure, so this refuses while a kernel is listening.
    Restore {
        /// The backup to restore from.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
    },
    /// Write a `.synrabackup` container: the database, its configuration, and the plugin list.
    ///
    /// # Why a container in addition to `backup`
    ///
    /// Because the single-file backup answers "restore this device", and a person handing a backup to a support
    /// conversation may also want to read what was installed and what was switched off. The container carries those as
    /// plain JSON beside the database, and its import is the same restore path — one recovery mechanism, two wrappers.
    Export {
        /// Where to write it. Must not already exist.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
    },
    /// Replace the database with the one inside a `.synrabackup` container.
    ///
    /// The plugins it lists are not reinstalled: their artifacts are deliberately not in the container, so the command
    /// reports them and leaves the decision to the user.
    Import {
        /// The container to import.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
    },
}


