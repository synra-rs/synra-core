//! Checks physical line counts for Rust and WIT sources in the Git worktree.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::Path;
use std::process::{Command, ExitCode};

const LIMIT: usize = 300;
const GENERATED: &[&str] = &[
    "crates/synra-plugin-host/src/generated/capability_table.rs",
    "crates/synra-plugin-host/src/generated/host_trait.rs",
    "crates/synra-plugin-host/wit/synra-plugin.wit",
    "crates/synra-plugin-sdk/src/generated/imports.rs",
    "crates/synra-plugin-sdk/wit/synra-plugin.wit",
    "tools/synra-plugin-cli/wit/synra-plugin.wit",
    "tools/synra-wit-codegen/wit/synra-plugin.wit",
    "wit/synra-plugin.wit",
];

pub(super) fn check(root: &Path) -> ExitCode {
    match scan(root) {
        Ok((checked, true)) => {
            println!("Checked {checked} source files (limit {LIMIT} lines)");
            ExitCode::SUCCESS
        }
        Ok((_, false)) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("source-size: {error}");
            ExitCode::FAILURE
        }
    }
}

fn scan(root: &Path) -> Result<(usize, bool), String> {
    let listing = Command::new("git")
        .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not run git: {error}"))?;
    if !listing.status.success() {
        return Err(String::from_utf8_lossy(&listing.stderr).trim_end().to_owned());
    }
    let listing = String::from_utf8(listing.stdout).map_err(|error| error.to_string())?;
    let paths: BTreeSet<_> = listing.split_terminator('\0').collect();
    let mut checked = 0;
    let mut passed = true;
    for path in paths {
        if GENERATED.contains(&path) || !is_source(Path::new(path)) {
            continue;
        }
        let source = match std::fs::read(root.join(path)) {
            Ok(source) => source,
            // A tracked file can be deleted from the worktree before staging.
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{path}: {error}")),
        };
        checked += 1;
        let count = physical_lines(&source);
        if count > LIMIT {
            eprintln!("{path}: {count} lines (limit {LIMIT})");
            passed = false;
        }
    }
    Ok((checked, passed))
}

fn is_source(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| {
        extension.eq_ignore_ascii_case("rs") || extension.eq_ignore_ascii_case("wit")
    })
}

fn physical_lines(source: &[u8]) -> usize {
    let breaks = source.iter().enumerate().filter(|&(index, byte)| {
        *byte == b'\n' || (*byte == b'\r' && source.get(index + 1) != Some(&b'\n'))
    });
    breaks.count() + usize::from(!matches!(source.last(), None | Some(b'\r' | b'\n')))
}
