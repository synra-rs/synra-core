//! Generates or checks all files derived from the workspace WIT contract.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut check = false;
    let mut path = None;
    for argument in std::env::args().skip(1) {
        if argument == "--check" {
            check = true;
        } else if argument.starts_with('-') || path.is_some() {
            eprintln!("usage: wit-codegen [--check] [contract.wit]");
            return ExitCode::FAILURE;
        } else {
            path = Some(PathBuf::from(argument));
        }
    }
    let path = path.unwrap_or_else(|| PathBuf::from("wit/synra-plugin.wit"));
    match wit_codegen::generate::synchronize(&path, check) {
        Ok(paths) => {
            for path in paths {
                println!(
                    "{} {}",
                    if check { "checked" } else { "generated" },
                    path.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("wit-codegen: {error}");
            ExitCode::FAILURE
        }
    }
}
