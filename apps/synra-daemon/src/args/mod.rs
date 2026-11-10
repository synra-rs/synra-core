//! The daemon's flags and resolved startup plan.
//!
//! # Why the flags are a struct
//!
//! So the daemon can be started from a test with a plan, and so a flag that contradicts another is refused by `clap`
//! rather than by whichever branch runs first.

use clap::Parser;

pub use crate::lock::{ClaimFile, encode_claim, refresh_claim, remove_claim, write_claim};
use crate::plan::{DATA_DIR_VAR, DaemonOptions, DaemonPlan, PlanError, default_data_root};

/// The kernel's windowless host.
#[derive(Debug, Parser)]
#[command(
    name = "synra-daemon",
    version,
    about = "Runs the Synra kernel with no interface",
    long_about = "Runs the kernel without a window and keeps serving after any client disconnects. It exists to \
                  prove the kernel needs no interface, and as the shape a user gets when they want the kernel to \
                  outlive the application."
)]
pub struct DaemonArgs {
    /// Where the data lives.
    ///
    /// Defaults to the same answer `synra` uses, from the same environment variable, so `synra doctor` checks the
    /// installation this daemon actually runs.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<std::path::PathBuf>,

    /// The transport port.
    #[arg(long, value_name = "PORT", default_value_t = crate::plan::DEFAULT_LISTEN_PORT)]
    pub listen_port: u16,

    /// The discovery port.
    #[arg(long, value_name = "PORT", default_value_t = crate::plan::DEFAULT_DISCOVERY_PORT)]
    pub discovery_port: u16,

    /// Run without claiming the data directory.
    ///
    /// For looking at a live installation: a user who wants to see what a running daemon thinks should not have to
    /// stop it. Two daemons writing one database is not something this flag makes safe, and the flag's name says what
    /// it is for rather than what it does.
    #[arg(long, conflicts_with = "exclusive")]
    pub diagnostic: bool,

    /// Exit when the last client disconnects, rather than keeping running.
    ///
    /// What a user wants when running one from a terminal to watch it.
    #[arg(long)]
    pub exit_with_last_client: bool,

    /// Claim the data directory exclusively, which is the default.
    ///
    /// The opposite of `--diagnostic`, spelled out so a script can be explicit rather than relying on a default.
    #[arg(long)]
    pub exclusive: bool,

    /// Print the start-up plan and exit.
    ///
    /// For a script and for a user who wants to know which directories and ports a start would use without starting
    /// one.
    #[arg(long)]
    pub dry_run: bool,
}

impl DaemonArgs {
    /// The options these flags describe.
    #[must_use]
    pub fn options(&self) -> DaemonOptions {
        DaemonOptions {
            data_dir: self.data_dir.clone().unwrap_or_else(default_data_root),
            listen_port: self.listen_port,
            discovery_port: self.discovery_port,
            // `--diagnostic` means not exclusive. `--exclusive` is the default spelled out, so it cannot turn a
            // diagnostic run back into a claiming one — `clap` refuses both at once.
            exclusive: !self.diagnostic,
            linger: !self.exit_with_last_client,
        }
    }
}

/// The flags, with the plan checked.
#[derive(Debug)]
pub struct Parsed {
    /// What the daemon will do.
    pub plan: DaemonPlan,
    /// Whether to print the plan and stop.
    pub dry_run: bool,
}

impl Parsed {
    /// Checks the flags and resolves the plan.
    ///
    /// # Errors
    ///
    /// [`PlanError`] when the ports or directories are unusable.
    pub fn resolve(args: &DaemonArgs) -> Result<Self, PlanError> {
        Ok(Self { plan: DaemonPlan::resolve(&args.options())?, dry_run: args.dry_run })
    }
}

/// The environment variable that moves the data directory, re-exported for a caller that wants to set it.
pub const ENV_DATA_DIR: &str = DATA_DIR_VAR;

#[cfg(test)]
mod tests;
