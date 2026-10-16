//! The command line: walk the directories given, print every problem, and say how many there were.
//!
//! Kept separate from `lib.rs` so the checks themselves can be called — `guards` runs them as one of its checks, and a
//! binary crate cannot be depended on.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let roots: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if roots.is_empty() {
        eprintln!("doc-links: give it one or more directories to walk");
        return ExitCode::FAILURE;
    }

    let mut anchors = BTreeMap::new();
    let mut files = 0usize;
    let mut problems = Vec::new();
    for root in &roots {
        for file in doc_links::markdown_files(root) {
            files += 1;
            problems.extend(doc_links::check_file(&file, root, &mut anchors));
        }
    }
    for problem in &problems {
        println!("{}", problem.render());
    }
    println!("doc-links: {files} file(s), {} problem(s)", problems.len());
    if problems.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
