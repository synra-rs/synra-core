//! The UI artifact's tests.

use super::*;

fn index(files: &[(&str, u64)]) -> UiArtifactIndex {
    UiArtifactIndex {
        entry: "index.html".to_owned(),
        default_page: None,
        files: files.iter().map(|(path, size)| ((*path).to_owned(), *size)).collect(),
    }
}

fn artifact(files: &[(&str, u64)]) -> UiArtifact {
    UiArtifact::build(index(files)).expect("builds")
}

/// A listing with an entry document.
fn with_entry(extra: &[(&str, u64)]) -> UiArtifactIndex {
    let mut files = vec![("index.html", 100u64)];
    files.extend_from_slice(extra);
    index(&files)
}

// ── Building ──────────────────────────────────────────────────────────────────────────────────

mod construction;
mod paths;
mod resolution;
mod types;
