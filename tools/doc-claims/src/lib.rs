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

use std::path::Path;
use std::path::PathBuf;

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

/// Whether a token can be searched for literally.
///
/// A pattern is anything with syntax in it: a call, an alternation, a generic, a quote. Those are how a document says
/// "this shape of code" rather than "this name", and counting them is a different job than the one this tool does.
#[must_use]
pub fn is_searchable(token: &str) -> bool {
    let trimmed = token.trim();
    !trimmed.is_empty()
        && !trimmed.contains(['(', ')', '"', '\'', '|', '<', '>', '*', '!', '='])
        && trimmed.chars().all(|c| {
            c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '.' | '/' | '#' | '@')
        })
}

/// The claims in one document.
#[must_use]
pub fn claims_in(file: &Path, markdown: &str) -> Vec<Claim> {
    let lines: Vec<&str> = markdown.lines().collect();
    let mut found = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        let Some((claimed, at)) = count_claim(line) else {
            continue;
        };
        if is_historical(line, at) {
            continue;
        }
        // ★ The tokens come from the claim's own **sentence**, on both sides of the count.
        //
        // Both sides, because the documents use both orders: *"`FixtureThing` 全仓 0 命中"* names its subject first and
        // *"全仓 0 处 `fixture_a`/`fixture_b`"* names it after. The first version read only what followed the count and so found
        // nothing in half the corpus — which it reported as a claim with no tokens rather than as a failure, the quietest
        // possible wrong answer.
        //
        // And a sentence rather than a line, because one line often carries two claims and a file path: the real line
        // *"`FixtureThing` 全仓 0 命中；`FixtureWidget` 只有 **1** 命中…（`apps/…/serve.rs:36`）"* would otherwise count the
        // wrong names together. The window ends at the next sentence mark, so the path in the parenthesis is outside it.
        let sentence = sentence_around(line, at);
        let mut tokens = backticked(sentence);
        // ★ Only when the sentence ran to the end of the line, which is what a wrap looks like.
        //
        // Reading the next line regardless pulled in the **next claim's** names: line 710 of the storage document ends its
        // sentence with a `；` and the next line opens with `FixtureThing` 全仓 0 命中`, so a claim about `fixture_a`/`fixture_b`
        // was reported as a claim about four names, three of which belong to a different sentence.
        if sentence_ends_at_line_end(line, at)
            && let Some(next) = lines.get(index + 1)
        {
            tokens.extend(backticked(next));
        }
        if !tokens.is_empty() {
            found.push(Claim { file: file.to_path_buf(), line: index + 1, claimed, tokens });
        }
    }
    found
}

/// The count in a `N hits` / `N places` phrase, and where the rest of the sentence starts.
fn count_claim(line: &str) -> Option<(usize, usize)> {
    for marker in ["命中", "处"] {
        let mut from = 0usize;
        while let Some(at) = line[from..].find(marker) {
            let marker_at = from + at;
            // Walk back over whitespace and then the number — in that order, because `全仓 0 命中` has a space between the
            // digit and the word, and reading the digits first finds nothing.
            let before = line[..marker_at].trim_end();
            let digits: String = before
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            // And require the phrase to be about the whole codebase, which is what makes it checkable from here.
            if !digits.is_empty() {
                let without = before[..before.len() - digits.len()].trim_end();
                if without.ends_with("全仓") {
                    let claimed = digits.parse().ok()?;
                    return Some((claimed, marker_at + marker.len()));
                }
            }
            from = marker_at + marker.len();
        }
    }
    None
}

/// Whether the sentence a claim sits in runs to the end of its line, which is how a wrap looks.
fn sentence_ends_at_line_end(line: &str, at: usize) -> bool {
    let sentence = sentence_around(line, at);
    line.trim_end().ends_with(sentence.trim_end())
}

/// Whether a claim is about the **original** state rather than the present one.
///
/// ★ Why this matters, and why it is not a detail.
///
/// The documents record what things were like before a change — *"原状：全仓 0 处 `tracing_subscriber`"* means "the
/// original state was zero hits" — and the code has had eight since. Counting that against the code reports a document as
/// wrong for being **accurately historical**, which is the kind of false positive that teaches a reader to ignore the tool.
fn is_historical(line: &str, at: usize) -> bool {
    let before = &line[..at];
    before.contains("原状") || before.contains("当时") || before.contains("修前")
}

/// Whether a claim naming this token can be counted at all.
///
/// ★ Why a bare English word cannot.
///
/// *"全仓 0 处 `ui`/`devices`/`config`"* is a claim about **files** — the stores a front end would have — and counting the
/// words finds six thousand hits, because `devices` is a word this codebase uses for a real thing. A substring search cannot
/// tell an identifier from an English word, so it must say so rather than answer wrongly. A token with a `_`, a `::`, a
/// `.`, a `/`, a `#`, a digit or an uppercase letter is a name; a lowercase word with none of those is a word.
fn tokens_are_countable(tokens: &[String]) -> bool {
    !tokens.is_empty()
        && tokens.iter().all(|token| {
            token.chars().any(|c| {
                c.is_uppercase()
                    || c.is_ascii_digit()
                    || matches!(c, '_' | ':' | '.' | '/' | '#' | '@' | '-')
            }) || !token.chars().all(|c| c.is_ascii_lowercase())
        })
}

/// The sentence a position sits in, so a claim's tokens are its own.
fn sentence_around(line: &str, at: usize) -> &str {
    const ENDS: [char; 5] = ['。', '；', '，', '—', ':'];
    let start = line[..at]
        .char_indices()
        .rev()
        .find(|(_, c)| ENDS.contains(c))
        .map_or(0, |(index, c)| index + c.len_utf8());
    let end = line[at..].find(ENDS).map_or(line.len(), |index| at + index);
    &line[start..end]
}

/// The backticked tokens in a piece of text.
fn backticked(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        match after.find('`') {
            Some(end) => {
                let token = after[..end].trim();
                if !token.is_empty() {
                    tokens.push(token.to_owned());
                }
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    tokens
}

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
    let mut total = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if matches!(name.as_ref(), "target" | "node_modules" | ".git" | "dist" | "vendor") {
                    continue;
                }
                stack.push(path);
            } else if is_code(&path)
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                total += text.matches(token).count();
            }
        }
    }
    total
}

/// Whether a file is source code this tool counts in.
fn is_code(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "rs" | "ts" | "tsx" | "toml" | "wit"))
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

/// Every markdown document under a directory, walking it.
#[must_use]
pub fn documents(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if matches!(entry.file_name().to_string_lossy().as_ref(), "node_modules" | ".git" | "target") {
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

#[cfg(test)]
mod tests {
    // ★ Every fixture name here is **invented**, and that is a rule rather than a preference.
    //
    // The first version used names the documents actually make claims about, and the tool then reported those very
    // claims as false: it counts the whole codebase, its own tests are part of the codebase, and **a comment counts
    // too**. A checker whose fixtures — or whose prose — are the names it checks measures itself.
    use super::*;

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
}
