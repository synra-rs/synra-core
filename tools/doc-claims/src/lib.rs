//! `doc-claims` — the "the codebase has N of these" claims in the documents, counted.
//!
//! # Why this exists
//!
//! Because the design documents make dozens of claims of the form *"`X` appears nowhere in the codebase"* or *"`X` is
//! there twice"*, and each one is a claim that **rots**. A name a document said did not exist gets written a round later,
//! and nothing in the repository notices: the sentence keeps saying zero, and the reader has no reason to doubt it.
//!
//! It has happened twice in one session. `FixtureWidget` was said to have **zero** hits and had one; `config.json` was said to be
//! "a path constant nobody reads" and had become a nine-file module with five hundred lines of tests.
//!
//! # What it checks, and what it refuses to
//!
//! A claim names one or more `backticked` tokens and a count. A token that is a **plain name** — an identifier, a path, a
//! type — is counted in the code and compared. A token that is a **pattern** — `Command::new("npm"|"cargo")`,
//! `impl From<..> for IpcError` — is not something a substring search answers, and this reports it as
//! [`Outcome::Uncheckable`] rather than quietly passing it.
//!
//! That third outcome is the point. A checker that silently skips what it cannot parse reports `ok` for a document it did
//! not read, which is the failure this whole family of tools exists to avoid.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

use std::path::PathBuf;

mod parse;
mod scan;

use parse::tokens_are_countable;

pub use parse::{claims_in, is_searchable};
pub use scan::{count_in_code, documents};

/// A claim a document makes about how much of something the code contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The document, as given.
    pub file: PathBuf,
    /// The line the claim starts on.
    pub line: usize,
    /// How many the document says there are.
    pub claimed: usize,
    /// The code tokens it names, as written.
    pub tokens: Vec<String>,
}

/// What checking a claim came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The code has as many as the document says.
    Agrees {
        /// The count both agree on.
        found: usize,
    },
    /// The code has a different number.
    Disagrees {
        /// What the code actually has.
        found: usize,
    },
    /// The token is a pattern rather than a name, so a substring search cannot answer it.
    Uncheckable {
        /// The token that could not be reduced to a search.
        token: String,
    },
}

/// What one claim came to, ready to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// The claim it answers.
    pub claim: Claim,
    /// What the check found.
    pub outcome: Outcome,
}

/// Checks one claim against the code.
///
/// A claim naming several tokens — `` `A`/`B` `` — is about them **together**, so the counts are added. A claim naming a
/// pattern is refused rather than guessed at.
#[must_use]
pub fn check(claim: &Claim, roots: &[PathBuf]) -> Checked {
    for token in &claim.tokens {
        if !is_searchable(token) {
            return Checked {
                claim: claim.clone(),
                outcome: Outcome::Uncheckable { token: token.clone() },
            };
        }
    }
    if claim.tokens.iter().any(|token| token.is_empty()) {
        return Checked { claim: claim.clone(), outcome: Outcome::Uncheckable { token: String::new() } };
    }
    if !tokens_are_countable(&claim.tokens) {
        return Checked {
            claim: claim.clone(),
            outcome: Outcome::Uncheckable { token: claim.tokens.join("`/`") },
        };
    }
    let found: usize = claim.tokens.iter().map(|token| count_in_code(roots, token)).sum();
    let outcome = if found == claim.claimed {
        Outcome::Agrees { found }
    } else {
        Outcome::Disagrees { found }
    };
    Checked { claim: claim.clone(), outcome }
}

#[cfg(test)]
mod tests;
