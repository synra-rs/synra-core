use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{anchors_in, links_in};

/// Why a reference is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The file it names is not there.
    MissingFile {
        /// The document that contains the link.
        from: PathBuf,
        /// The line the link is on.
        line: usize,
        /// What it pointed at.
        target: String,
    },
    /// The file is there and the heading is not.
    MissingAnchor {
        /// The document that contains the link.
        from: PathBuf,
        /// The line the link is on.
        line: usize,
        /// The file whose headings were searched, which is the target or the document itself.
        into: PathBuf,
        /// The anchor it asked for.
        anchor: String,
    },
}

impl Problem {
    /// One line, in the shape `path:line: what is wrong`.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::MissingFile { from, line, target } => {
                format!("{}:{line}: there is no `{target}`", from.display())
            }
            Self::MissingAnchor { from, line, into, anchor } => format!(
                "{}:{line}: `{}` has no heading `#{anchor}`",
                from.display(),
                into.display()
            ),
        }
    }
}

/// Whether a target is one this tool has no business resolving.
///
/// A scheme of any kind — `http`, `https`, `mailto`, `tel`, `data` — or a bare fragment, which `links_in` splits out before
/// this is asked.
#[must_use]
pub fn is_external(target: &str) -> bool {
    match target.split_once(':') {
        // A Windows drive letter is one character, and `C:\x` is a path rather than a scheme.
        Some((scheme, _)) => scheme.len() > 1,
        None => false,
    }
}

/// Every `.md` file under a directory, sorted, skipping build output and VCS metadata.
#[must_use]
pub fn markdown_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name == "node_modules" || name == ".git" || name == "target" || name == ".vitepress" {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "md") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Where a link points, trying the shapes a documentation site uses.
///
/// ★ Why this is more than `base.join(target)`.
///
/// The first run of this tool over the real corpus reported **110** problems, and almost all of them were links like
/// `/zh/plugins/manifest` — a path relative to the **site root**, which a static-site generator turns into a page, not a
/// path relative to the document that contains it. Resolving those against the document's own directory found nothing, so
/// the tool reported a broken link on nearly every line of two repositories.
///
/// A checker that reports everything is worth exactly as much as one that reports nothing, and it is worse in practice
/// because the honest response is to stop reading its output. So the resolution has three shapes, in order:
///
/// 1. the path as written, relative to the document (or to the root when it starts with `/`);
/// 2. the same path with `.md` appended, which is what a pretty URL like `/zh/plugins/manifest` names;
/// 3. `index.md` inside it, which is what a URL like `/zh/plugins/` names;
/// 4. and, for an absolute path, the same path under `public/`, where a site keeps the files it serves verbatim.
fn resolve(raw: &str, from: &Path, root: &Path) -> Option<PathBuf> {
    let (base, target) = match raw.strip_prefix('/') {
        Some(rest) => (root.to_path_buf(), rest.to_owned()),
        None => (from.to_path_buf(), raw.to_owned()),
    };
    let direct = base.join(&target);
    if direct.exists() {
        return Some(direct);
    }
    if direct.extension().is_none() {
        let with_md = direct.with_extension("md");
        if with_md.is_file() {
            return Some(with_md);
        }
    }
    let index = direct.join("index.md");
    if index.is_file() {
        return Some(index);
    }
    if raw.starts_with('/') {
        let public = root.join("public").join(&target);
        if public.exists() {
            return Some(public);
        }
    }
    None
}

/// Checks one document against the filesystem, with anchors read from disk.
///
/// Anchors are cached by path because the same target is usually linked many times, and re-reading a file per link would make
/// this quadratic in the size of the corpus for no gain.
#[must_use]
pub fn check_file(
    path: &Path,
    root: &Path,
    anchors: &mut BTreeMap<PathBuf, Option<BTreeSet<String>>>,
) -> Vec<Problem> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let base = path.parent().unwrap_or(Path::new("."));
    let mut problems = Vec::new();

    for link in links_in(&text) {
        if link.target.is_empty() {
            // A same-file anchor, `#section`, which `split_target` keeps as an empty target.
            if let Some(anchor) = &link.anchor
                && !anchors_of(path, anchors).contains(anchor)
            {
                    problems.push(Problem::MissingAnchor {
                        from: path.to_path_buf(),
                        line: link.line,
                        into: path.to_path_buf(),
                    anchor: anchor.clone(),
                });
            }
            continue;
        }
        if is_external(&link.target) || link.target.starts_with("mailto:") {
            continue;
        }
        let Some(resolved) = resolve(&link.target, base, root) else {
            problems.push(Problem::MissingFile {
                from: path.to_path_buf(),
                line: link.line,
                target: link.target.clone(),
            });
            continue;
        };
        // A directory link is a link to a place, not to a heading; nothing to check.
        if let Some(anchor) = &link.anchor
            && resolved.is_file()
            && !anchors_of(&resolved, anchors).contains(anchor)
        {
                problems.push(Problem::MissingAnchor {
                    from: path.to_path_buf(),
                    line: link.line,
                    into: resolved,
                anchor: anchor.clone(),
            });
        }
    }
    problems
}

/// A file's anchors, read once and remembered.
fn anchors_of(path: &Path, cache: &mut BTreeMap<PathBuf, Option<BTreeSet<String>>>) -> BTreeSet<String> {
    cache
        .entry(path.to_path_buf())
        .or_insert_with(|| std::fs::read_to_string(path).ok().map(|text| anchors_in(&text)))
        .clone()
        .unwrap_or_default()
}
