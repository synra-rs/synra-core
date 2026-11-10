use clap::Parser as _;

use super::Cli;

mod commands;
mod devices;
mod diagnostics;
mod intents;
mod plugins;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(args)
}

fn parsed(args: &[&str]) -> Cli {
    parse(args).expect("parses")
}
