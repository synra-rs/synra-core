//! `synra` — the kernel's command-line host.
//!
//! Three things only: read the arguments, dispatch, set the exit code. Everything decidable in a test lives in the
//! library, which is what keeps this file short — the crate docs say why that is a design requirement rather than a
//! preference.

use clap::Parser;
use std::process::ExitCode;
use synra_cli::args::Cli;
use synra_cli::{Command, dispatch, follow};

fn main() -> ExitCode {
    let cli = Cli::parse();
    // ★ `logs --follow` is the one command that prints as it runs, so it cannot return a `CommandOutcome` without
    // buffering a stream that is meant to be unbounded. Everything decidable about it lives in `follow`; this branch is
    // the wiring, and the branch is the whole of the exception.
    if let Command::Logs(args) = &cli.command
        && args.follow
    {
        return ExitCode::from(follow(&cli, &mut std::io::stdout()));
    }
    let outcome = dispatch(&cli);
    // A failure goes to the error stream, so a script redirecting one does not lose it and a user piping to a pager
    // does not have it buried among the output.
    if outcome.is_failure() {
        eprintln!("{}", outcome.diagnostic_text());
    }
    else {
        println!("{}", outcome.text());
    }
    ExitCode::from(outcome.exit_code())
}
