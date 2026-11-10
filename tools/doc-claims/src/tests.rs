// ★ Every fixture name here is **invented**, and that is a rule rather than a preference.
//
// The first version used names the documents actually make claims about, and the tool then reported those very
// claims as false: it counts the whole codebase, its own tests are part of the codebase, and **a comment counts
// too**. A checker whose fixtures — or whose prose — are the names it checks measures itself.

use std::path::{Path, PathBuf};
use super::{Claim, Outcome, check, claims_in, count_in_code, is_searchable};

/// A temporary tree that removes itself.
struct Tree(PathBuf);

impl Tree {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-doc-claims-{label}-{}", std::process::id()));
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
fn a_claim_that_names_one_token_is_read() {
    let claims = claims_in(Path::new("doc.md"), "全仓 0 命中 `FixtureThing`。\n");
    assert_eq!(claims.len(), 1, "{claims:?}");
    assert_eq!(claims[0].claimed, 0);
    assert_eq!(claims[0].tokens, vec!["FixtureThing"]);
}

#[test]
fn a_claim_about_the_original_state_is_not_a_claim_about_now() {
    // ★ The corpus found this one too: the observability document records *"原状：全仓 0 处 …"* — what
    // was true before the logging layer was written — and counting it against today's code reports an accurately
    // historical sentence as wrong.
    assert!(claims_in(Path::new("doc.md"), "原状：全仓 0 处 `tracing_subscriber`；
").is_empty());
    // And a claim about now is still read, which is what keeps this from skipping everything.
    assert_eq!(claims_in(Path::new("doc.md"), "全仓 0 处 `tracing_subscriber`；
").len(), 1);
}

#[test]
fn a_claim_that_wraps_onto_the_next_line_is_read() {
    // ★ Which is how most of them are written, because these sentences are long.
    let text = "★ **`fixture_ref` / `FixtureRef` 全仓 0 命中** ——\n还有一句解释。\n";
    let claims = claims_in(Path::new("doc.md"), text);
    assert_eq!(claims.len(), 1, "{claims:?}");
    assert_eq!(claims[0].tokens, vec!["fixture_ref", "FixtureRef"]);
}

#[test]
fn a_number_that_is_not_about_the_whole_codebase_is_not_a_claim() {
    // Only "全仓 N" is checkable from here; "这个文件 3 处" is about somewhere this tool was not pointed.
    assert!(claims_in(Path::new("doc.md"), "这个文件 3 处 `X`。\n").is_empty());
    assert!(claims_in(Path::new("doc.md"), "两处 `X`。\n").is_empty());
}

#[test]
fn a_token_that_is_a_pattern_is_refused_rather_than_guessed_at() {
    // ★ The third outcome, and the reason it exists: a checker that silently skips what it cannot parse reports `ok`
    // for a document it did not read.
    assert!(!is_searchable("Command::new(\"npm\"|\"cargo\")"));
    assert!(!is_searchable("impl From<..> for IpcError"));
    assert!(is_searchable("std::sync::Mutex"));
    assert!(is_searchable("crates/synra-store/src/paths.rs"));
    assert!(is_searchable("fixture_hook"));

    let claim = Claim {
        file: PathBuf::from("doc.md"),
        line: 1,
        claimed: 0,
        tokens: vec!["impl From<..> for IpcError".to_owned()],
    };
    let checked = check(&claim, &[]);
    assert!(matches!(checked.outcome, Outcome::Uncheckable { .. }), "{checked:?}");
}

#[test]
fn the_count_comes_from_the_code_and_not_from_the_document() {
    // ★ The reason `count_in_code` walks code only. The document *contains* the token — that is what a claim about it
    // looks like — so counting the documents would make every claim self-defeatingly wrong.
    let tree = Tree::new("count");
    tree.write("doc.md", "全仓 0 命中 `FixtureWidget`。\n");
    tree.write("crates/a/src/lib.rs", "// FixtureWidget is mentioned here\n");

    let roots = vec![tree.0.join("crates")];
    let claims = claims_in(&tree.0.join("doc.md"), "全仓 0 命中 `FixtureWidget`。\n");
    let checked = check(&claims[0], &roots);

    assert_eq!(checked.outcome, Outcome::Disagrees { found: 1 }, "{checked:?}");
}

#[test]
fn a_claim_that_agrees_is_reported_as_agreeing() {
    let tree = Tree::new("agrees");
    tree.write("crates/a/src/lib.rs", "let x = FixtureThing::new();\n");

    let roots = vec![tree.0.join("crates")];
    let claims = claims_in(Path::new("doc.md"), "全仓 0 命中 `FixtureAbsent`。\n");
    assert_eq!(check(&claims[0], &roots).outcome, Outcome::Agrees { found: 0 });

    let claims = claims_in(Path::new("doc.md"), "全仓 1 命中 `FixtureThing`。\n");
    assert_eq!(check(&claims[0], &roots).outcome, Outcome::Agrees { found: 1 });
}

#[test]
fn two_tokens_are_counted_together_because_the_claim_is_about_both() {
    let tree = Tree::new("together");
    tree.write("crates/a/src/lib.rs", "let a = FixtureWidget::new();\nlet b = FixtureThing::new();\n");

    let roots = vec![tree.0.join("crates")];
    let claims = claims_in(Path::new("doc.md"), "全仓 2 处 `FixtureWidget`/`FixtureThing`；\n");
    assert_eq!(check(&claims[0], &roots).outcome, Outcome::Agrees { found: 2 });
}

#[test]
fn a_claim_about_bare_english_words_is_refused() {
    // ★ The corpus found this one, and it is the difference between a tool that reports nothing and one that
    // reports six thousand nonsense hits.
    //
    // *"全仓 0 处 `ui`/`devices`/`config`"* is a claim about **files** a front end would have. `devices` is also a
    // word this codebase uses for a real thing, so counting the word found 6,334 matches and the claim was reported as
    // wrong by an enormous margin. A substring search cannot tell an identifier from an English word, so the honest
    // answer is that it cannot answer.
    let tree = Tree::new("words");
    tree.write("crates/a/src/lib.rs", "let devices = 1;\nlet config = 2;\n");

    let roots = vec![tree.0.join("crates")];
    let claims = claims_in(Path::new("doc.md"), "全仓 0 处 `ui`/`devices`/`config`；\n");
    assert!(
        matches!(check(&claims[0], &roots).outcome, Outcome::Uncheckable { .. }),
        "{:?}",
        check(&claims[0], &roots)
    );
    // And a name with a marker in it is countable, which is what keeps this from refusing everything.
    let claims = claims_in(Path::new("doc.md"), "全仓 0 处 `fixture_hook`；\n");
    assert_eq!(check(&claims[0], &roots).outcome, Outcome::Agrees { found: 0 });
}

#[test]
fn build_output_is_not_code() {
    let tree = Tree::new("skip");
    tree.write("crates/a/target/debug/thing.rs", "FixtureWidget\n");
    tree.write("crates/a/node_modules/x.ts", "FixtureWidget\n");

    assert_eq!(count_in_code(&[tree.0.join("crates")], "FixtureWidget"), 0);
}
