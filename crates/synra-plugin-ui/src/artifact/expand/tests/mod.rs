//! The expansion plan, driven with hostile archives.
//!
//! Every rule here has a case that must be refused, and the cases are the four attacks rather than invented ones: a
//! `..` in a name, an absolute path, a link, and a bomb. A suite that only ever planned a well-formed archive would
//! pass against a `plan` that returned everything it was given.

use super::super::limits::{ArtifactError, PathRefusal, MAX_ARTIFACT_PATH_LEN};
use super::*;

/// A small archive that passes.
fn good() -> Vec<Entry> {
    vec![
        Entry::directory("assets"),
        Entry::file("index.html", 1_024),
        Entry::file("assets/app.js", 4_096),
    ]
}

mod paths_and_links;
mod bounds;
mod planning;
