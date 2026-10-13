//! `synra-plugin` — the plugin author's tool.
//!
//! Read the arguments, decide, write. Everything decidable lives in the library, which is what keeps this file short —
//! the crate docs say why that is a design requirement rather than a preference.

use clap::Parser;
use std::process::ExitCode;
use synra_plugin_cli::args::{Cli, Command};
use synra_plugin_cli::{Outcome, new_plugin, verify_plugin};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match &cli.command {
        Command::New(args) => match new_plugin(args) {
            Ok(outcome) => outcome,
            Err(message) => {
                eprintln!("synra-plugin: {message}");
                return ExitCode::FAILURE;
            }
        },
        Command::Verify(args) => verify_plugin(args),
    };

    for line in outcome.lines() {
        println!("{line}");
    }

    // A scaffold's files are written last, so an author sees the whole listing before anything touches their disk.
    if let Outcome::Scaffold { root, files, .. } = &outcome {
        for (path, contents) in files {
            let path = &root.join(path);
            if let Some(parent) = path.parent()
                && let Err(error) = std::fs::create_dir_all(parent)
            {
                eprintln!("synra-plugin: {}: {error}", parent.display());
                return ExitCode::FAILURE;
            }
            if let Err(error) = std::fs::write(path, contents) {
                eprintln!("synra-plugin: {}: {error}", path.display());
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::from(outcome.exit_code())
}