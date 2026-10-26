//! `api-guard` — checks the crates that make a promise against the rules that promise is made of.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use api_guard::{CRATES, Source, check};

fn main() -> ExitCode {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".".to_owned());

    let mut violations = Vec::new();
    let mut checked = 0usize;

    for (name, boundary) in CRATES {
        let directory = Path::new(&root).join("crates").join(name).join("src");
        let files = match rust_files(&directory) {
            Ok(files) => files,
            Err(error) => {
                eprintln!("api-guard: {name}: {error}");
                return ExitCode::FAILURE;
            }
        };
        for file in files {
            let source = match Source::read(&file) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!("api-guard: {error}");
                    return ExitCode::FAILURE;
                }
            };
            checked += 1;
            violations.extend(check(&source, *boundary));
        }
    }

    for violation in &violations {
        println!("{violation}");
    }

    if violations.is_empty() {
        println!("api-guard: {checked} file(s) checked, no violations");
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "api-guard: {} violation(s) in {checked} file(s). STABILITY.md defines the unpublished workspace boundaries.",
        violations.len()
    );
    ExitCode::FAILURE
}

/// Every `.rs` file under a directory.
fn rust_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current).map_err(|error| format!("{}: {error}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", current.display()))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            match kind {
                kind if kind.is_dir() => stack.push(path),
                kind if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") => {
                    out.push(path)
                }
                _ => {}
            }
        }
    }
    out.sort();
    Ok(out)
}
