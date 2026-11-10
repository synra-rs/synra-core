use std::collections::BTreeMap;
use std::path::PathBuf;

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
