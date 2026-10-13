//! `wit-codegen` — derives the capability table from the WIT contract.
//!
//! Parse, render, write. Everything decidable lives in the library, which is what keeps this file short.

use std::process::ExitCode;
use wit_codegen::{Contract, emit_rust, emit_text, emitted_paths};

fn main() -> ExitCode {
    let contract_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wit/synra-plugin.wit".to_owned());

    let text = match std::fs::read_to_string(&contract_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("wit-codegen: {contract_path}: {error}");
            return ExitCode::FAILURE;
        }
    };

    let contract = match Contract::parse(&text) {
        Ok(contract) => contract,
        Err(error) => {
            // The parser refuses a host function with no gate, so a failure here is a contract that would have shipped
            // an ungated host call — the one outcome this tool exists to make impossible.
            eprintln!("wit-codegen: {contract_path}: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Resolved against the contract's directory rather than the working directory: `cargo run` sets the working
    // directory to the package's own, so a path relative to the repository root would land in a directory nobody
    // looks in — silently.
    let contract_dir = std::path::Path::new(&contract_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let [rust_relative, text_relative] = emitted_paths();
    let rust_path = contract_dir.join(rust_relative).display().to_string();
    let text_path = contract_dir.join(text_relative).display().to_string();
    let rust = match emit_rust(&contract) {
        Ok(rust) => rust,
        Err(error) => {
            eprintln!("wit-codegen: {error}");
            return ExitCode::FAILURE;
        }
    };

    if std::env::args().any(|arg| arg == "--check") {
        // The CI gate: a table that is not what the contract says is a build failure rather than a diff nobody reads.
        let current = std::fs::read_to_string(&rust_path).unwrap_or_default();
        if current != rust {
            eprintln!("wit-codegen: {rust_path} is out of date; run `wit-codegen`");
            return ExitCode::FAILURE;
        }
        println!("{rust_path} is up to date");
        return ExitCode::SUCCESS;
    }

    for (path, body) in [(&rust_path, rust), (&text_path, emit_text(&contract))] {
        if let Some(parent) = std::path::Path::new(path).parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            eprintln!("wit-codegen: {}: {error}", parent.display());
            return ExitCode::FAILURE;
        }
        if let Err(error) = std::fs::write(path, body) {
            eprintln!("wit-codegen: {path}: {error}");
            return ExitCode::FAILURE;
        }
        println!("wrote {path}");
    }

    for line in contract.summary_lines() {
        println!("{line}");
    }
    ExitCode::SUCCESS
}