//! Finds code and documents in the workspace tree.

use std::path::{Path, PathBuf};

/// Counts a token in every code file under the given roots.
///
/// Code only, and that is not a shortcut: the documents themselves contain the token — that is what a claim about it looks
/// like — so counting them would make every claim self-defeatingly wrong. The extensions are the ones this workspace
/// writes.
#[must_use]
pub fn count_in_code(roots: &[PathBuf], token: &str) -> usize {
    let mut total = 0usize;
    for root in roots {
        total += count_in(root, token);
    }
    total
}

/// The occurrences of a token under one root.
fn count_in(root: &Path, token: &str) -> usize {
    let mut total = 0;
    visit_files(root, &["target", "node_modules", ".git", "dist", "vendor"], |path| {
        if is_code(&path)
            && let Ok(text) = std::fs::read_to_string(path)
        {
            total += text.matches(token).count();
        }
    });
    total
}

/// Whether a file is source code this tool counts in.
fn is_code(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "rs" | "ts" | "tsx" | "toml" | "wit"))
}

/// Every markdown document under a directory, walking it.
#[must_use]
pub fn documents(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    visit_files(root, &["node_modules", ".git", "target"], |path| {
        if path.extension().is_some_and(|extension| extension == "md") {
            found.push(path);
        }
    });
    found.sort();
    found
}

fn visit_files(root: &Path, excluded: &[&str], mut visit: impl FnMut(PathBuf)) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if !excluded.contains(&entry.file_name().to_string_lossy().as_ref()) {
                    stack.push(path);
                }
            } else {
                visit(path);
            }
        }
    }
}
