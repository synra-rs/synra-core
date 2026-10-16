//! The command line: read the claims out of a set of documents and count them in the code.
//!
//! Kept apart from `lib.rs` so `guards` can call the checks rather than shelling out to a binary that shares its target
//! directory.

use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use doc_claims::{Outcome, check, claims_in, documents};

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(docs) = arguments.next() else {
        eprintln!("doc-claims: doc-claims <documents> <code root>...");
        return ExitCode::FAILURE;
    };
    let roots: Vec<PathBuf> = arguments.map(PathBuf::from).collect();
    if roots.is_empty() {
        eprintln!("doc-claims: give it at least one code root to count in");
        return ExitCode::FAILURE;
    }

    let mut checked = Vec::new();
    for document in documents(Path::new(&docs)) {
        let Ok(text) = std::fs::read_to_string(&document) else {
            continue;
        };
        for claim in claims_in(&document, &text) {
            checked.push(check(&claim, &roots));
        }
    }

    let mut wrong = 0usize;
    let mut uncheckable = 0usize;
    for entry in &checked {
        let where_ = format!("{}:{}", entry.claim.file.display(), entry.claim.line);
        let names = entry.claim.tokens.join("`/`");
        match &entry.outcome {
            Outcome::Agrees { found } => println!("ok          {where_}  `{names}` = {found}"),
            Outcome::Disagrees { found } => {
                wrong += 1;
                println!(
                    "DISAGREES   {where_}  `{names}`: the document says {}, the code has {found}",
                    entry.claim.claimed
                );
            }
            Outcome::Uncheckable { token } => {
                uncheckable += 1;
                println!("UNCHECKABLE {where_}  `{token}` is a pattern, not a name");
            }
        }
    }
    println!(
        "doc-claims: {} claim(s): {wrong} disagree, {uncheckable} not checkable",
        checked.len()
    );
    if wrong == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
