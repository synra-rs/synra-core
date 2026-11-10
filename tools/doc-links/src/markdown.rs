use std::collections::{BTreeMap, BTreeSet};

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
