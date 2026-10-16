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

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

/// A reference from one document to somewhere, as it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The target as written inside the parentheses, without any anchor.
    pub target: String,
    /// The `#anchor`, without the `#`, when there was one.
    pub anchor: Option<String>,
    /// The line it was written on, so a problem can point at it.
    pub line: usize,
}

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

/// Every link in one document's text.
///
/// # What it reads
///
/// The inline form, `[text](target)`, and the reference form, `[text][label]` with `[label]: target` defined somewhere. It
/// skips fenced code blocks and inline code spans, because a document about markdown *contains* markdown, and a checker
/// that read its own examples would report the examples rather than the documents.
#[must_use]
pub fn links_in(markdown: &str) -> Vec<Link> {
    let mut found = Vec::new();
    let stripped = strip_code(markdown);
    let definitions = reference_definitions(&stripped);

    for (index, line) in stripped.lines().enumerate() {
        let line_number = index + 1;
        // Inline.
        for target in targets_after(line, "](") {
            found.push(split_target(&target, line_number));
        }
        // Reference.
        for label in labels_after(line) {
            if let Some(target) = definitions.get(&label.to_lowercase()) {
                found.push(split_target(target, line_number));
            }
        }
    }
    found
}

/// Splits `path#anchor` into its two halves.
fn split_target(raw: &str, line: usize) -> Link {
    let trimmed = raw.trim().trim_matches(|c| c == '<' || c == '>');
    // A title after the target — `(path "Title")` — is not part of the path.
    let without_title = trimmed.split_once('"').map_or(trimmed, |(before, _)| before.trim());
    match without_title.split_once('#') {
        Some((target, anchor)) => Link {
            target: target.to_owned(),
            anchor: (!anchor.is_empty()).then(|| anchor.to_owned()),
            line,
        },
        None => Link { target: without_title.to_owned(), anchor: None, line },
    }
}

/// Replaces fenced blocks and code spans with spaces, keeping the line structure.
///
/// This is what `links_in` wants and what `anchors_in` must **not** use: a link written inside backticks is an example
/// rather than a link, while a heading's anchor keeps the words inside its backticks. `## What `is` it?` anchors as
/// `#what-is-it`, and blanking the span would compute `#what--it` — a wrong answer that only shows up as a link reported
/// broken against a heading that is right there.
fn strip_code(markdown: &str) -> String {
    strip_fences(markdown, true)
}

/// The same, leaving inline code spans alone.
fn strip_fences_only(markdown: &str) -> String {
    strip_fences(markdown, false)
}

/// Blanks fenced blocks, and code spans too when asked.
fn strip_fences(markdown: &str, spans: bool) -> String {
    let mut out = String::with_capacity(markdown.len());
    let mut fence: Option<String> = None;

    for line in markdown.lines() {
        let trimmed = line.trim_start();
        let marker = if trimmed.starts_with("```") {
            Some("```")
        } else if trimmed.starts_with("~~~") {
            Some("~~~")
        } else {
            None
        };
        if let Some(open) = &fence {
            if marker == Some(open.as_str()) {
                fence = None;
            }
            out.push('\n');
            continue;
        }
        if let Some(open) = marker {
            fence = Some(open.to_owned());
            out.push('\n');
            continue;
        }
        if spans {
            out.push_str(&strip_spans(line));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Blanks out `` `code spans` `` on one line.
fn strip_spans(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_span = false;
    for character in line.chars() {
        if character == '`' {
            in_span = !in_span;
            out.push(' ');
        } else if in_span {
            out.push(' ');
        } else {
            out.push(character);
        }
    }
    out
}

/// The targets of `](` inline links on one line.
fn targets_after(line: &str, needle: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find(needle) {
        let after = &rest[at + needle.len()..];
        match after.find(')') {
            Some(end) => {
                found.push(after[..end].to_owned());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    found
}

/// The labels of `[text][label]` references on one line.
fn labels_after(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("][") {
        let after = &rest[at + 2..];
        match after.find(']') {
            Some(end) => {
                let label = after[..end].trim();
                if !label.is_empty() {
                    found.push(label.to_owned());
                }
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    found
}

/// The `[label]: target` definitions in a document.
fn reference_definitions(markdown: &str) -> BTreeMap<String, String> {
    let mut definitions = BTreeMap::new();
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix('[') else {
            continue;
        };
        let Some((label, after)) = rest.split_once("]:") else {
            continue;
        };
        let target = after.split_whitespace().next().unwrap_or_default();
        if !label.is_empty() && !target.is_empty() {
            definitions.insert(label.to_lowercase(), target.to_owned());
        }
    }
    definitions
}

/// Turns a heading into the anchor GitHub gives it.
///
/// Lowercased; anything that is not alphanumeric, a space or a hyphen is dropped; spaces become hyphens. The character class
/// is Unicode-aware, which matters here: a heading written in Chinese keeps its characters rather than collapsing to
/// nothing, and an anchor that collapsed would report every link to it as broken.
#[must_use]
pub fn anchor_of(heading: &str) -> String {
    let mut out = String::with_capacity(heading.len());
    for character in heading.trim().chars() {
        if character.is_alphanumeric() || character == '-' || character == '_' {
            out.extend(character.to_lowercase());
        } else if character.is_whitespace() {
            out.push('-');
        }
    }
    out
}

/// Every anchor a document defines, with the repeat-suffixes GitHub adds.
#[must_use]
pub fn anchors_in(markdown: &str) -> BTreeSet<String> {
    let stripped = strip_fences_only(markdown);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut anchors = BTreeSet::new();

    for line in stripped.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            continue;
        }
        let heading = trimmed.trim_start_matches('#');
        // `#hashtag` is not a heading, and neither is `#######` — markdown allows six levels.
        if heading.starts_with('#') || !heading.starts_with(' ') {
            continue;
        }
        if line.trim_start().chars().take_while(|c| *c == '#').count() > 6 {
            continue;
        }
        let base = anchor_of(heading);
        if base.is_empty() {
            continue;
        }
        let count = seen.entry(base.clone()).or_insert(0);
        if *count == 0 {
            anchors.insert(base);
        } else {
            anchors.insert(format!("{base}-{count}"));
        }
        *count += 1;
    }
    anchors
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory that removes itself.
    struct Tree(PathBuf);

    impl Tree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-doc-links-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temporary tree");
            Self(path)
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a directory");
            }
            std::fs::write(&path, contents).expect("a file");
            path
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_link_to_a_file_that_is_there_is_not_a_problem() {
        let tree = Tree::new("ok");
        tree.write("a.md", "See [the other](b.md).\n");
        tree.write("b.md", "# The other\n");

        let mut cache = BTreeMap::new();
        let problems = check_file(&tree.0.join("a.md"), &tree.0, &mut cache);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_link_to_a_file_that_is_not_there_is_reported() {
        // ★ The failure this exists for: a reference that reads correctly and points nowhere.
        let tree = Tree::new("missing");
        let a = tree.write("a.md", "See [the other](gone.md).\n");

        let mut cache = BTreeMap::new();
        let problems = check_file(&a, &tree.0, &mut cache);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].render().contains("there is no `gone.md`"), "{}", problems[0].render());
        // And it says which line, so the reader can go there.
        assert!(problems[0].render().ends_with(":1: there is no `gone.md`"), "{}", problems[0].render());
    }

    #[test]
    fn an_anchor_that_matches_no_heading_is_reported() {
        let tree = Tree::new("anchor");
        let a = tree.write("a.md", "See [it](b.md#not-a-heading).\n");
        tree.write("b.md", "# Present\n");

        let mut cache = BTreeMap::new();
        let problems = check_file(&a, &tree.0, &mut cache);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].render().contains("has no heading `#not-a-heading`"), "{}", problems[0].render());
    }

    #[test]
    fn an_anchor_written_the_way_github_writes_one_is_found() {
        let tree = Tree::new("slug");
        let a = tree.write("a.md", "See [it](b.md#the-design-principles).\n");
        tree.write("b.md", "## The design principles\n");

        let mut cache = BTreeMap::new();
        assert!(check_file(&a, &tree.0, &mut cache).is_empty());
    }

    #[test]
    fn a_heading_in_chinese_keeps_its_characters_rather_than_collapsing() {
        // ★ The anchors in these documents are mostly Chinese, so a slugger that dropped non-ASCII would report every one
        // of them as broken — a checker that fails on the corpus it was written for.
        assert_eq!(anchor_of("下一步做什么"), "下一步做什么");
        assert_eq!(anchor_of("为什么 这样"), "为什么-这样");
        assert_eq!(anchor_of("What `is` it?"), "what-is-it");
    }

    #[test]
    fn a_same_file_anchor_is_checked_against_that_file() {
        let tree = Tree::new("same");
        let a = tree.write("a.md", "# Present\n\nSee [below](#absent).\n");

        let mut cache = BTreeMap::new();
        let problems = check_file(&a, &tree.0, &mut cache);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(matches!(&problems[0], Problem::MissingAnchor { .. }), "{problems:?}");
    }

    #[test]
    fn a_heading_keeps_the_words_inside_its_backticks() {
        // ★ The bug the real corpus found, which no synthetic case had.
        //
        // `strip_code` blanks a code span, and that is right for links — a link written in backticks is an example. It is
        // wrong for a heading: GitHub's anchor keeps the words, so `### 10-2 ★★ `can_handle` 的边界`
        // anchors as `10-2--can_handle-的边界`. Blanking the span computed `10-2---的边界` instead, and the
        // tool reported a broken anchor against a heading sitting on the page.
        assert!(anchors_in("## What `is` it?\n").contains("what-is-it"));
        assert_eq!(anchor_of("10-2 ★★ `can_handle` 的批量"), "10-2--can_handle-的批量");
    }

    #[test]
    fn a_heading_that_repeats_gets_the_suffix_github_gives_it() {
        let anchors = anchors_in("# Notes\n\n## Again\n\n## Again\n\n## Again\n");
        assert!(anchors.contains("notes"));
        assert!(anchors.contains("again"));
        assert!(anchors.contains("again-1"), "{anchors:?}");
        assert!(anchors.contains("again-2"), "{anchors:?}");
    }

    #[test]
    fn a_link_inside_a_code_block_is_not_a_link() {
        // ★ The documents are about markdown, so they contain markdown examples. Reading those would report the examples
        // rather than the documents, and the fix would be to delete the examples.
        let text = "Real [one](a.md).\n\n```markdown\n[example](nowhere.md)\n```\n\nAnd `[inline](also-nowhere.md)`.\n";
        let found = links_in(text);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].target, "a.md");
    }

    #[test]
    fn an_external_link_is_left_alone() {
        // Reaching one needs a network, which is the difference between a check that runs on every commit and one that runs
        // when somebody remembers.
        assert!(is_external("https://example.com"));
        assert!(is_external("mailto:someone@example.com"));
        assert!(is_external("tel:+1234"));
        // And a Windows path is not a scheme.
        assert!(!is_external(r"C:\Projects\thing.md"));
        assert!(!is_external("docs/guide.md"));
    }

    #[test]
    fn a_reference_definition_is_followed() {
        let text = "See [the guide][g].\n\n[g]: guide.md\n";
        let found = links_in(text);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].target, "guide.md");
    }

    #[test]
    fn a_title_after_a_target_is_not_part_of_the_path() {
        let found = links_in("See [it](guide.md \"The guide\").\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].target, "guide.md");
    }

    #[test]
    fn walking_a_tree_finds_the_markdown_and_skips_the_build_output() {
        let tree = Tree::new("walk");
        tree.write("a.md", "# A\n");
        tree.write("nested/b.md", "# B\n");
        tree.write("node_modules/c.md", "# C\n");
        tree.write("notes.txt", "not markdown\n");

        let files = markdown_files(&tree.0);
        let names: Vec<String> = files.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["a.md", "b.md"], "{names:?}");
    }

    #[test]
    fn a_link_to_a_directory_is_not_searched_for_headings() {
        let tree = Tree::new("directory");
        tree.write("sub/other.md", "# Other\n");
        let a = tree.write("a.md", "See [the folder](sub).\n");

        let mut cache = BTreeMap::new();
        assert!(check_file(&a, &tree.0, &mut cache).is_empty());
    }
}
