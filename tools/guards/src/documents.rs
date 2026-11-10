use std::path::Path;

use super::total_checks;

/// Every link in this workspace's documents, and in the two documentation repositories beside it.
///
/// """ + S + """ Why this is outside the guard list rather than in it.
///
/// Because it has three answers rather than two. The documents live in **three** repositories: this one and two siblings, and
/// a checkout of this repository alone is normal. When a sibling is absent the honest answer is `SKIP` with the reason — not
/// `ok`, which would say the links were checked and found good when nothing was read. That is the failure this file already
/// records once, in guard 5: a check that reported `ok` for months while looking for a symbol that does not exist.
///
/// """ + S + """ And why a document check belongs in a guard at all.
///
/// Because a broken link is a claim that something exists, made in a document nobody re-reads. The twenty-eighth file in a
/// design tree is not opened by the person editing the third, so a rename in one is invisible in the other — and the reader
/// who follows it cannot tell whether the document is wrong or their tool is.
pub(super) fn check_document_links(root: &Path) -> bool {
    let Some(parent) = root.parent() else {
        println!("SKIP  the workspace has no parent directory, so the sibling documents cannot be looked for");
        return true;
    };

    let mut roots = vec![root.to_path_buf()];
    let mut absent = Vec::new();
    for sibling in ["design-docs", "docs"] {
        let path = parent.join(sibling);
        if path.is_dir() {
            roots.push(path);
        } else {
            absent.push(sibling);
        }
    }

    let mut anchors = std::collections::BTreeMap::new();
    let mut files = 0usize;
    let mut problems = Vec::new();
    for directory in &roots {
        for file in doc_links::markdown_files(directory) {
            files += 1;
            problems.extend(doc_links::check_file(&file, directory, &mut anchors));
        }
    }

    if !absent.is_empty() {
        // Named, and still reported alongside whatever was found: a skip is a fact about this checkout, not a result.
        println!("SKIP  not checked out, so their links were not read: {}", absent.join(", "));
    }
    if problems.is_empty() {
        println!("ok    every link in {files} document(s) resolves");
        true
    } else {
        println!("FAIL  {} document link(s) point at something that is not there", problems.len());
        for problem in problems.iter().take(20) {
            println!("        {}", problem.render());
        }
        if problems.len() > 20 {
            println!("        ... and {} more", problems.len() - 20);
        }
        false
    }
}

/// Every "the codebase has N of these" claim in the documents, counted.
///
/// """ + S + """ Why a claim needs checking at all.
///
/// Because a document saying *"`X` appears nowhere"* is a claim that **rots the moment somebody writes `X`**, and nothing
/// notices: the sentence keeps saying zero and the reader has no reason to doubt it. Twice in one session: a type said to
/// have no hits had one, and a file said to be an unread path constant had become a nine-file module with five hundred
/// lines of tests.
///
/// """ + S + """ And why it counts three things rather than two.
///
/// A claim whose token is a **pattern** — `Command::new("npm"|"cargo")` — cannot be answered by a substring search, and a
/// claim naming a bare English word (`devices`) would count thousands of hits that mean nothing. Both are reported by
/// `doc-claims` as uncheckable and counted here as neither passing nor failing, because a checker that silently skips what
/// it cannot read reports `ok` for a document it did not read.
pub(super) fn check_document_claims(root: &Path) -> bool {
    let Some(parent) = root.parent() else {
        println!("SKIP  the workspace has no parent directory, so the sibling documents cannot be read");
        return true;
    };

    let mut documents = vec![root.to_path_buf()];
    let mut absent = Vec::new();
    // The documents that make claims about the code live in the design repository; the user documentation and the API
    // reference are checked for links, not for counts.
    let design = parent.join("design-docs");
    if design.is_dir() {
        documents.push(design);
    } else {
        absent.push("design-docs");
    }

    // The code the claims are about: this workspace and the shell beside it, which is where the contract's commands live.
    let mut code = vec![root.to_path_buf()];
    let shell = parent.join("synra-rust-app").join("src-tauri");
    if shell.is_dir() {
        code.push(shell);
    }

    let mut checked = Vec::new();
    for directory in &documents {
        for document in doc_claims::documents(directory) {
            let Ok(text) = std::fs::read_to_string(&document) else {
                continue;
            };
            for claim in doc_claims::claims_in(&document, &text) {
                checked.push(doc_claims::check(&claim, &code));
            }
        }
    }

    if !absent.is_empty() {
        println!("SKIP  not checked out, so their claims were not counted: {}", absent.join(", "));
    }

    let wrong: Vec<&doc_claims::Checked> = checked
        .iter()
        .filter(|entry| matches!(entry.outcome, doc_claims::Outcome::Disagrees { .. }))
        .collect();
    let uncheckable = checked
        .iter()
        .filter(|entry| matches!(entry.outcome, doc_claims::Outcome::Uncheckable { .. }))
        .count();

    if wrong.is_empty() {
        // The uncheckable count is printed rather than hidden: it is the part of the corpus nothing verifies.
        println!(
            "ok    {} documented count(s) agree with the code ({uncheckable} not checkable)",
            checked.len() - uncheckable
        );
        true
    } else {
        println!("FAIL  {} documented count(s) no longer describe the code", wrong.len());
        for entry in &wrong {
            let where_ = format!("{}:{}", entry.claim.file.display(), entry.claim.line);
            let names = entry.claim.tokens.join("`/`");
            if let doc_claims::Outcome::Disagrees { found } = entry.outcome {
                println!(
                    "        {where_}  `{names}`: the document says {}, the code has {found}",
                    entry.claim.claimed
                );
            }
        }
        false
    }
}

/// A count the documents give for `tools/guards` must be the count it has.
///
/// """ + S + """ Why this is worth a check of its own.
///
/// The documents stated this number **three times in three different values** — 5, then 8, then the truth of 10 — because
/// a sentence that says "it has N checks" is a fact about a list that keeps growing, and nothing was comparing the two. The
/// first fix was to correct the number; the second was to correct it again; this is the one that stops it.
///
/// A document may still say how many checks there are, and if it does, it has to be right. Leaving the number out is also
/// allowed — the rules are listed, and the list is what a reader needs. What is not allowed is a fourth wrong value.
pub(super) fn check_document_guard_counts(root: &Path) -> bool {
    let Some(parent) = root.parent() else {
        println!("SKIP  the workspace has no parent directory, so the documents cannot be read");
        return true;
    };
    let documents = parent.join("design-docs");
    if !documents.is_dir() {
        println!("SKIP  the design repository is not checked out, so no count could be compared");
        return true;
    }

    // The number this binary actually runs: the list plus the checks that need three answers rather than two.
    let actual = total_checks();
    let mut wrong = Vec::new();
    for path in doc_links::markdown_files(&documents) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if !line.contains("tools/guards") {
                continue;
            }
            for claimed in counts_before_a_unit(line) {
                if claimed != actual {
                    let relative = path.strip_prefix(&documents).unwrap_or(&path);
                    wrong.push(format!(
                        "{}:{} says `tools/guards` has {claimed}, and it has {actual}",
                        relative.display(),
                        index + 1
                    ));
                }
            }
        }
    }

    if wrong.is_empty() {
        println!("ok    every stated guard count matches the {actual} this binary runs");
        true
    } else {
        println!("FAIL  a document states a guard count that is no longer true");
        for line in wrong {
            println!("        {line}");
        }
        false
    }
}

/// The numbers on a line that are followed by a counting unit, as in `8 条` or `10 项`.
fn counts_before_a_unit(line: &str) -> Vec<usize> {
    let mut found = Vec::new();
    for unit in ["条", "项"] {
        let mut from = 0usize;
        while let Some(at) = line[from..].find(unit) {
            let unit_at = from + at;
            let before = line[..unit_at].trim_end();
            let digits: String = before
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if let Ok(value) = digits.parse::<usize>() {
                // ★ `第 6 条` is an ordinal — "the sixth one" — and not a count of anything.
                //
                // The corpus found this immediately: the check reported that a document claiming six guards was wrong,
                // when the sentence said "the sixth check". A rule that cannot tell a number from an index reports the
                // documents that are being *specific*.
                let before_the_number = &before[..before.len() - digits.len()].trim_end();
                if !before_the_number.ends_with('第') {
                    found.push(value);
                }
            }
            from = unit_at + unit.len();
        }
    }
    found
}
