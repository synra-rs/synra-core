//! Extracts countable claims from prose.

use std::path::Path;

use super::Claim;

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
pub(super) fn tokens_are_countable(tokens: &[String]) -> bool {
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
