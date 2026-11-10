use clap::Parser;

use crate::args::Cli;

fn cli(args: &[&str]) -> Cli {
    Cli::try_parse_from(args).expect("parses")
}

mod plugins;
mod data;
mod outcomes;
mod doctor;
