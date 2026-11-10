//! `doc-links` — every markdown link and anchor in a set of documents, checked.
//!
//! The command-line front end is `main.rs`, two dozen lines that walk the arguments and print what this returns.
//!
//! # Why this exists
//!
//! Because a broken link points at something that **looks right and is not there**, which is worse than a missing
//! sentence: a reader follows it, lands nowhere, and cannot tell whether the document is wrong or the tool is. The design
//! documents are one repository, the user documents another, and between them they hold dozens of files whose
//! cross-references have been edited by hand for a hundred rounds with nothing checking them.
//!
//! # What it checks
//!
//! * a link to a file that does not exist, resolved relative to the document that contains it;
//! * a `#anchor` that matches no heading in the file it names — including the same-file form, `#section`;
//! * an anchor written the way GitHub writes one: lowercased, punctuation dropped, spaces turned into hyphens, and a
//!   numeric suffix on a heading that repeats.
//!
//! # What it deliberately does not check
//!
//! * an external `http`/`https` link — reaching one needs a network, which is the difference between a check that can run
//!   on every commit and one that runs when somebody remembers;
//! * `mailto:` or any other scheme, because none of them is a file;
//! * whether an anchor *should* exist, which is a question about the prose rather than about the reference.

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

mod check;
mod markdown;

pub use check::{Problem, check_file, is_external, markdown_files};
pub use markdown::{Link, anchor_of, anchors_in, links_in};

#[cfg(test)]
mod tests;
