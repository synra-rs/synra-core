//! `synra-plugin` — the plugin author's tool.
//!
//! Parse, decide, carry out, report. Everything decidable lives in the library, which is what keeps this file short —
//! the crate docs say why that is a design requirement rather than a preference.

use clap::Parser;
use std::process::ExitCode;
use synra_plugin_cli::args::{Cli, Command};
use synra_plugin_cli::{build_plugin, execute, is_dry_run, new_plugin, pack_plugin, sign_plugin, verify_plugin};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let dry_run = is_dry_run(&cli);

    // The decision first, then the listing, then whatever it decided to do — so an author reads what is about to happen
    // before it happens.
    let decision = match &cli.command {
        Command::New(args) => new_plugin(args),
        Command::Build(args) => build_plugin(args),
        Command::Sign(args) => sign_plugin(args),
        Command::Verify(args) => Ok(verify_plugin(args)),
        Command::Pack(args) => pack_plugin(args),
    };

    let decision = match decision {
        Ok(decision) => decision,
        Err(message) => {
            eprintln!("synra-plugin: {message}");
            return ExitCode::FAILURE;
        }
    };

    for line in decision.lines() {
        println!("{line}");
    }

    let executed = execute(&decision, dry_run);
    for line in &executed.lines {
        println!("{line}");
    }

    if executed.is_failure() {
        ExitCode::from(executed.code)
    }
    else {
        ExitCode::from(decision.exit_code())
    }
}