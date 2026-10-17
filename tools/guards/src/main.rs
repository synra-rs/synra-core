//! `guards` — the architectural invariants, as executable checks.
//!
//! # Why this exists
//!
//! An invariant that lives only in a document is violated within three months. Each check here is one of the rules the
//! design set, written so that it either passes or fails on every run rather than being re-derived by hand.
//!
//! # Why a Rust binary and not a shell script
//!
//! The workspace is Rust and only Rust: a `.sh` file would be the first thing in the repository in another language, and
//! it would then need a shell to be present on every machine that checks out the tree. This runs wherever `cargo` does.
//!
//! # What it does not do
//!
//! It does not prove the invariants are *sufficient* — it catches the specific ways they have been broken before:
//!
//! 1. the kernel acquiring a GUI dependency;
//! 2. the protocol layer acquiring IO;
//! 3. a `main.rs` growing logic instead of calling the library;
//! 4. a crate reaching for `directories` outside the one module allowed to;
//! 5. a host function bypassing the capability gate.
//!
//! It also runs the MSRV check, because `rust-version` in `Cargo.toml` is a promise and an unchecked promise is a
//! number somebody typed — and builds the **sibling app**, because this workspace and that one are separate repositories
//! and a change to a `pub` signature here has twice left that one unable to build while everything here stayed green.

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning. A test that has to write a file and
// read it back is a test that will `expect` something, and an assertion about the *contents* of a list is an index.
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

use std::path::{Path, PathBuf};
use std::process::Command;

/// One check, and what it is for.
struct Guard {
    /// The rule, as a sentence a failure message can use.
    rule: &'static str,
    /// The document section it comes from, so a reader can check the reasoning.
    source: &'static str,
    /// Returns the offending lines, or an empty list when the rule holds.
    run: fn(&Path) -> Vec<String>,
}

fn guards() -> Vec<Guard> {
    vec![
        Guard {
            rule: "the kernel must not depend on a GUI toolkit",
            source: "05 §1.1",
            run: guard_no_gui,
        },
        Guard {
            rule: "the protocol layer must not depend on IO",
            source: "06 §2.1",
            run: guard_protocol_has_no_io,
        },
        Guard {
            rule: "a bin must be a shell: main.rs has no logic",
            source: "06 §7.1",
            run: guard_bins_are_thin,
        },
        Guard {
            rule: "only Paths::discover may call `directories`",
            source: "06 §7.1",
            run: guard_directories_is_contained,
        },
        Guard {
            rule: "every host function must go through the capability gate",
            source: "10 §3.1",
            run: guard_host_functions_are_gated,
        },
        Guard {
            rule: "only the sandbox may delete a directory tree",
            source: "11 §D2",
            run: guard_directory_deletion_is_contained,
        },
        Guard {
            rule: "the daemon does not dial while holding the host lock",
            source: "11 §C4",
            run: guard_daemon_dials_without_the_lock,
        },
    ]
}

fn main() -> std::process::ExitCode {
    let root = match workspace_root() {
        Some(root) => root,
        None => {
            eprintln!("guards: run this from inside the workspace (no [workspace] Cargo.toml above)");
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut failures = 0;
    for guard in guards() {
        let offenders = (guard.run)(&root);
        if offenders.is_empty() {
            println!("ok    {}", guard.rule);
            continue;
        }
        failures += 1;
        println!("FAIL  {}  ({})", guard.rule, guard.source);
        for line in offenders {
            println!("        {line}");
        }
    }

    println!();
    // Five checks outside the list, because each needs three answers rather than two — `ok`, `SKIP` with a reason, and
    // `FAIL` — and the `Guard` shape has no room for the middle one.
    let app_ok = check_sibling_app(&root);
    let msrv_ok = check_msrv(&root);
    let links_ok = check_document_links(&root);
    let claims_ok = check_document_claims(&root);
    let counts_ok = check_document_guard_counts(&root);

    if failures == 0 && app_ok && msrv_ok && links_ok && claims_ok && counts_ok {
        println!("{} guard(s) passed", total_checks());
        std::process::ExitCode::SUCCESS
    }
    else {
        if failures > 0 {
            println!("{failures} guard(s) failed");
        }
        std::process::ExitCode::FAILURE
    }
}

/// How many checks this binary runs: the list, plus the ones that need three answers rather than two.
///
/// ★ **One number, in one place.** There were two, and they disagreed: the line above said the list plus five, and the
/// document-count check compared the documents against the list plus four — counting every check but itself. A document
/// stating the real total would have been reported as wrong, and the number that was printed was not the number that was
/// checked. Nothing noticed because the documents stopped stating a count in round 112; a disagreement that only shows up
/// once somebody writes the number down again is still a disagreement.
fn total_checks() -> usize {
    guards().len() + 5
}

/// The sibling app, built against this crate's public API.
///
/// # ★ Why this is a guard and not a line in a document
///
/// Because it was a line in a document, and the rule was broken anyway. `synra-rust-app` is a **separate workspace** that
/// depends on this one by path, so nothing here compiles it — and twice now a change to a `pub` signature in this
/// workspace left the app unable to build while every check in this workspace stayed green:
///
/// 1. `PluginSet::new` gained a host argument, and the app's `main.rs` kept calling it with one;
/// 2. `orchestrate::cancel` gained a `local_device` argument, and the app's intent commands kept calling it with three.
///
/// The second lasted three rounds. Both were invisible for the same reason: the two workspaces are separate, so the only
/// thing that could have noticed was a person remembering to look — which is exactly the kind of check this tool exists to
/// replace. A rule that depends on memory has now failed twice.
///
/// # Why `--no-default-features`
///
/// Because the default feature pulls in the Tauri shell, which needs a webview toolchain to build and is present on a
/// developer's machine and not on a CI box. What this checks is the **API**, and the library and the binary compile
/// without the shell — which is where both breaks were.
///
/// # The three answers
///
/// `ok`, `SKIP` with a reason, and `FAIL`. A core-only clone has no app to break and says so; "I could not check" is not
/// "I checked and it is fine", and a guard that conflates them is one people learn to ignore.
///
/// # What it costs
///
/// A build of the app, which is the most expensive thing in this tool by a wide margin — seconds against an already-built
/// target, minutes against a cold one. That is the price of the only check that has ever caught this class of mistake, and
/// it is paid on every `cargo run -p guards`. If it ever becomes the reason somebody stops running the guards, the honest
/// change is to make it opt-in and say so here, not to delete it and go back to remembering.
fn check_sibling_app(root: &Path) -> bool {
    let Some(app) = root.parent().map(|parent| parent.join("synra-rust-app").join("src-tauri")) else {
        println!("SKIP  the sibling app is not checked out, so nothing is built against this API");
        return true;
    };
    if !app.join("Cargo.toml").is_file() {
        println!("SKIP  no sibling app at {} — a core-only clone has no app to break", app.display());
        return true;
    }

    let output = Command::new("cargo")
        .arg("build")
        .arg("--no-default-features")
        .current_dir(&app)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            println!("ok    the sibling app builds against this crate's public API");
            true
        }
        Ok(output) => {
            println!("FAIL  the sibling app no longer builds against this crate's public API");
            let stderr = String::from_utf8_lossy(&output.stderr);
            // The `error[...]` lines name the call that no longer fits, which is the whole answer: a reader needs the
            // signature and the site, not the whole transcript.
            for line in stderr
                .lines()
                .filter(|line| line.starts_with("error") && !line.contains("could not compile"))
                .take(6)
            {
                println!("        {line}");
            }
            false
        }
        Err(error) => {
            // Cargo missing is not the app failing to build. Reported as a skip for the same reason the MSRV check
            // reports a missing component as one: a guard that cries wolf is one people learn to ignore.
            println!("SKIP  cargo could not be launched to build the sibling app: {error}");
            true
        }
    }
}

/// The declared MSRV, checked by building with that toolchain.
///
/// # Why this is a check and not a number
///
/// `rust-version` is what a downstream user with an older compiler is promised. A promise nobody runs is one that rots
/// the first time a dependency raises its own floor, and the failure then lands on that user rather than here.
fn check_msrv(root: &Path) -> bool {
    let Some(msrv) = declared_msrv(root) else {
        println!("FAIL  the MSRV could not be read from Cargo.toml");
        return false;
    };
    let toolchain = format!("+{msrv}");

    let output = Command::new("cargo")
        .arg(&toolchain)
        .arg("check")
        .arg("--workspace")
        .arg("--all-targets")
        .current_dir(root)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            println!("ok    the workspace builds on its declared MSRV ({msrv})");
            true
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // A toolchain whose components are only *partly* installed is not an MSRV failure: `cargo +X` then tries to
            // fetch the missing pieces, and a machine without network reports a download error instead. Reporting that as
            // "does not build on the MSRV" is a false accusation, and a guard that cries wolf is one people learn to
            // ignore. The distinction is the point: "could not check" and "checked and failed" are different answers.
            //
            // Every wording rustup has used is listed, because the first version of this check recognised only one of
            // them and reported a network timeout as a build failure — the exact mistake it exists to avoid.
            if ["component download failed", "error downloading file", "could not download file"]
                .iter()
                .any(|phrase| stderr.contains(phrase))
            {
                println!("SKIP  the MSRV check needs a component that is not installed ({msrv})");
                println!("        install it once with `rustup toolchain install {msrv}` while online");
                return true;
            }
            println!("FAIL  the workspace does not build on its declared MSRV ({msrv})");
            for line in stderr.lines().filter(|line| line.starts_with("error")).take(5) {
                println!("        {line}");
            }
            false
        }
        Err(error) => {
            // A missing toolchain is a failure rather than a skip: "could not check" and "checked and passed" are
            // different answers, and only one of them is a promise kept.
            println!("FAIL  the MSRV check could not run: {error}");
            println!("        install it with `rustup toolchain install {msrv}`");
            false
        }
    }
}

/// The `rust-version` the workspace manifest declares.
fn declared_msrv(root: &Path) -> Option<String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
    manifest.lines().find_map(|line| {
        line.trim()
            .strip_prefix("rust-version")
            .and_then(|rest| rest.split('"').nth(1))
            .map(str::to_owned)
    })
}

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
fn check_document_links(root: &Path) -> bool {
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
fn check_document_claims(root: &Path) -> bool {
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
fn check_document_guard_counts(root: &Path) -> bool {
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

/// The workspace root: the nearest ancestor whose `Cargo.toml` declares `[workspace]`.
fn workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file()
            && std::fs::read_to_string(&manifest).is_ok_and(|text| text.contains("[workspace]"))
        {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Every `.rs` file under a directory, skipping build output and VCS metadata.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            found.extend(rust_files(&path));
        }
        else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    found
}

/// The package names `cargo tree` reports for the given packages, as a lowercased set.
fn tree_of(root: &Path, packages: &[&str]) -> Vec<String> {
    let mut command = Command::new(env!("CARGO"));
    command.arg("tree").arg("--prefix").arg("none").arg("--no-dedupe");
    for package in packages {
        command.arg("-p").arg(package);
    }
    command.current_dir(root);
    match command.output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.trim().to_lowercase())
            .filter(|line| !line.is_empty())
            .collect(),
        // A `cargo tree` that cannot run is reported as a failure by its caller rather than silently passing: a guard
        // that passes when its tool is missing is worse than no guard.
        Err(error) => vec![format!("cargo tree could not be run: {error}")],
    }
}

/// Reports every dependency line matching one of `banned`.
fn banned_dependencies(root: &Path, packages: &[&str], banned: &[&str]) -> Vec<String> {
    banned_lines(&tree_of(root, packages), packages, banned)
}

/// Which of a `cargo tree`'s lines name a banned dependency.
///
/// ★ Why the matching is its own function.
///
/// Because it is the half that can be **wrong in silence**. A guard that returns no violations looks exactly like a guard whose
/// comparison never matches — which is what guard 5 in this file did for months, scanning for a macro that appears nowhere, and
/// reporting `ok` every run. `cargo tree` needs a registry and a network, so a test cannot drive the whole guard; it can drive
/// this, and this is where a mistake would live.
fn banned_lines(lines: &[String], packages: &[&str], banned: &[&str]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| {
            banned
                .iter()
                .any(|name| line.split_whitespace().next() == Some(*name) || line.starts_with(name))
        })
        .map(|line| format!("{} -> {line}", packages.join(", ")))
        .collect()
}

/// 1. The kernel, the transport and the plugin host must not pull in a GUI toolkit.
fn guard_no_gui(root: &Path) -> Vec<String> {
    banned_dependencies(
        root,
        &["synra-core", "synra-net", "synra-protocol", "synra-plugin-host"],
        &["tauri", "wry", "tao"],
    )
}

/// 2. The protocol layer must stay free of IO: it is the part both ends agree on, and a runtime there would decide it.
fn guard_protocol_has_no_io(root: &Path) -> Vec<String> {
    banned_dependencies(root, &["synra-protocol"], &["tokio", "wasmtime", "rusqlite", "hyper"])
}

/// 3. A `main.rs` reads flags and calls the library.
///
/// The limit is a line count rather than a judgement because a judgement is what the rule is trying to replace: a shell
/// that has grown past this is a shell that has grown logic.
fn guard_bins_are_thin(root: &Path) -> Vec<String> {
    const LIMIT: usize = 60;
    ["apps/synra-cli", "apps/synra-daemon", "tools/synra-plugin-cli"]
        .iter()
        .filter_map(|crate_dir| {
            let main = root.join(crate_dir).join("src/main.rs");
            let text = std::fs::read_to_string(&main).ok()?;
            let count = text.lines().count();
            (count > LIMIT).then(|| format!("{crate_dir}/src/main.rs is {count} lines (limit {LIMIT})"))
        })
        .collect()
}

/// 4. `directories` decides where a platform keeps things, and there is exactly one place that may ask it.
fn guard_directories_is_contained(root: &Path) -> Vec<String> {
    let allowed = Path::new("crates/synra-store/src/paths.rs");
    rust_files(&root.join("crates"))
        .into_iter()
        .filter(|path| path.strip_prefix(root).is_ok_and(|relative| relative != allowed))
        .filter(|path| {
            std::fs::read_to_string(path).is_ok_and(|text| text.contains("directories::"))
        })
        .map(|path| {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            format!("{} uses `directories::`", relative.display())
        })
        .collect()
}

/// 6. A path that deletes a whole directory must be the sandbox's own.
///
/// """ + S + """ Why this one is new, and what it is for.
///
/// `11 §D2` says the kernel must never silently delete a user's data, and the document's evidence for it was a
/// hand-counted number plus the phrase *"all of them are in test code"* — which is not something anybody can check without
/// first deciding what test code is. Counting it properly found **71** call sites rather than 42, and exactly two in
/// production: `sandbox.rs`, removing the sandbox's own cache and root.
///
/// So the rule is written down here with the allow-list it needs. A call site is test code when the file's name says so or
/// the path is a `tests` directory, or when it sits **below** the file's first `#[cfg(test)]` — which is where a Rust test
/// module goes. Everything else is production, and production may only delete a directory in the one place whose whole job
/// is to own one.
fn guard_directory_deletion_is_contained(root: &Path) -> Vec<String> {
    /// The only production file allowed to remove a directory tree, and why: a sandbox owns directories to delete them.
    const ALLOWED: &[&str] = &["crates/synra-store/src/sandbox.rs", "crates/synra-store/src/plugin_files.rs"];

    let mut offenders = Vec::new();
    for base in ["crates", "apps", "tools"] {
        for path in rust_files(&root.join(base)) {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            let relative = relative.to_string_lossy().replace('\\', "/");
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            // Test code, by the two rules above.
            if name.contains("test") || relative.split('/').any(|part| part == "tests") {
                continue;
            }
            if ALLOWED.contains(&relative.as_str()) {
                continue;
            }
            // ★ And a checker cannot check itself: this file contains the name it looks for, in the code that does the
            // looking and in the paragraph explaining it. Counting those as call sites makes the ruler part of what it
            // measures, which is the same mistake as a fixture named after the thing a document makes a claim about.
            //
            // Only this file, and not the other tools: they mention nothing, and `tools/synra-plugin-cli` is a real program
            // that is worth checking.
            if relative.ends_with("tools/guards/src/main.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !text.contains("remove_dir_all") {
                continue;
            }
            // ★ The marker has to be **code**, not a comment about the marker.
            //
            // The first version of this guard failed on its own documentation: the paragraph above contains the literal
            // `#[cfg(test)]`, so the boundary was found in prose and the two `remove_dir_all` calls in the guard's own test
            // helper were read as production code. A rule that cannot tell a mention from a use will always find one.
            let boundary = text
                .lines()
                .position(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.starts_with("//") && trimmed.starts_with("#[cfg(test)]")
                })
                .unwrap_or(usize::MAX);
            for (index, line) in text.lines().enumerate() {
                // ★ A mention is not a use, in the scan too and not only in the boundary above.
                //
                // A module that explains why it does **not** call this has to name it, and the first file to need that
                // was found by this guard reporting its own documentation — a comment is not a call site, and a rule
                // that cannot tell them apart makes writing the reason down a lint error.
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if index < boundary && line.contains("remove_dir_all") {
                    offenders.push(format!("{relative}:{} removes a directory tree", index + 1));
                }
            }
        }
    }
    offenders
}

/// 7. A command that dials while holding the host's lock makes every other command wait for a network.
///
/// # ★ The rule this checks, and why it can be checked at all
///
/// `Host::dial` and `Host::send` are each **two** things in one call — the network, and the bookkeeping that needs
/// `&mut self`. A caller that already holds the host's lock therefore holds it across the network. That was true in four
/// command paths until rounds 118 and 119 split both, and the halves — `synra_core::dial_peer`, `Host::adopt`,
/// `Host::may_send`, `Host::count_sent` — exist so that it need not be true again.
///
/// The compositions stay, because a caller that holds no lock should be able to dial in one line. This guard is what keeps
/// them out of the daemon's production paths: inside `apps/synra-daemon`, a `.dial(` or a `host.send(` in code that is not
/// test code is a call that would reacquire the lock across a network operation.
fn guard_daemon_dials_without_the_lock(root: &Path) -> Vec<String> {
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("apps/synra-daemon/src")) {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let relative = relative.to_string_lossy().replace('\\', "/");
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        // Test code, by the same three rules the deletion guard uses. The daemon's own transport test dials, which is
        // right for a test: it holds no cross-command lock, so there is nothing for a listing to wait behind.
        if name.contains("test") || relative.split('/').any(|part| part == "tests") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // ★ The marker has to be code, not a comment about the marker — the same rule, and for the same reason, as the
        // guard above: a rule that cannot tell a mention from a use will always find one.
        let boundary = text
            .lines()
            .position(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && trimmed.starts_with("#[cfg(test)]")
            })
            .unwrap_or(usize::MAX);
        for (index, line) in text.lines().enumerate() {
            if index >= boundary {
                continue;
            }
            if line.contains(".dial(") || line.contains("host.send(") {
                offenders.push(format!(
                    "{relative}:{} holds the host lock across a network operation",
                    index + 1
                ));
            }
        }
    }
    offenders
}

/// 5. A host function reachable without the gate is a capability the manifest never granted.
///
/// # ★ This guard used to check for a macro that does not exist
///
/// It scanned every `.rs` file for the string `ungated_host_fn!`, allowing
/// `crates/synra-plugin-host/src/host_funcs/env.rs`. Both halves were wrong:
///
/// * `ungated_host_fn!` appears nowhere in the workspace except this function, which was looking for it. The scan could
///   not match, so the check could not fail.
/// * `crates/synra-plugin-host/src/host_funcs/env.rs` does not exist — there is no `host_funcs` directory at all.
///
/// It reported `ok` on every run for months, as one of the five guards. That is worse than having no guard: a missing
/// check is a gap someone may notice, while a green check is evidence that the gap has been closed.
///
/// # What is actually true
///
/// Host functions are not registered by a macro. `crates/synra-plugin-host/build.rs` regenerates
/// `src/generated/capability_table.rs` from `wit/synra-plugin.wit` on every build, so the table cannot drift from the
/// contract and cannot be hand-edited into a weaker state.
///
/// The property that remains worth checking is the one the table encodes: **every function is gated, except reads of
/// the environment**. A `None` in that table is a call any plugin may make, so each one has to be justified. The guard
/// reads the generated table and requires every ungated entry to be one of the three families that only report facts.
///
/// The runtime tests in `host_surface.rs` assert the same property from the compiled table. This runs earlier and
/// without compiling, which is the point of this tool — but it is the same rule, checked the same way, rather than a
/// check for an absent symbol.
fn guard_host_functions_are_gated(root: &Path) -> Vec<String> {
    // The three prefixes a call may have and still be ungated. Each one answers a question about the environment; none
    // of them acts. Anything else ungated is an action any plugin could take, which is the failure this catches.
    const UNGATED_FAMILIES: &[&str] = &["env-", "platform-capabilities", "plugin-id"];

    let table = root.join("crates/synra-plugin-host/src/generated/capability_table.rs");
    let Ok(text) = std::fs::read_to_string(&table) else {
        return vec![format!(
            "{} is missing; the capability table is the only record of which host calls are gated",
            table.display()
        )];
    };

    let mut problems = Vec::new();
    let mut ungated = 0usize;
    let mut gated = 0usize;

    for line in text.lines() {
        // An entry looks like `("synra:plugin/host#log", Some("log:*")),` or `("synra:plugin/host#env-locale", None),`.
        let Some(rest) = line.trim().strip_prefix("(\"") else {
            continue;
        };
        let Some((name, gate)) = rest.split_once("\", ") else {
            continue;
        };
        let short = name.rsplit('#').next().unwrap_or(name);

        if gate.starts_with("None") {
            ungated += 1;
            if !UNGATED_FAMILIES.iter().any(|family| short == *family || short.starts_with(family)) {
                problems.push(format!(
                    "{short} is ungated and is not a read of the environment; an ungated host call is one every plugin may make"
                ));
            }
        } else if gate.starts_with("Some(") {
            gated += 1;
        }
    }

    // A table that parsed to nothing means the format changed and this check silently stopped looking — the exact
    // failure this guard was rewritten to stop having.
    if gated == 0 || ungated == 0 {
        problems.push(format!(
            "the capability table parsed to {gated} gated and {ungated} ungated entries, which cannot be right; \
             the guard has stopped reading it"
        ));
    }

    problems
}

#[cfg(test)]
mod tests {
    //! Every guard, made to **fail** on purpose.
    //!
    //! # """ + S + """ Why this module exists
    //!
    //! Because a guard that cannot fail is worse than no guard, and this file has already had one. Guard 5 used to scan for
    //! `ungated_host_fn!`, a macro that appears nowhere in the workspace, and allowed a file that does not exist — so it
    //! reported `ok` on every run for months. Its own documentation says the lesson: *"a missing check is a gap someone may
    //! notice, while a green check is evidence that the gap has been closed."*
    //!
    //! None of the seven had a test. Each one below drives a guard against a **synthetic tree** that breaks its rule, and
    //! asserts that it says so. What they cannot prove is that a guard finds *every* violation; what they prove is the
    //! property that failure depended on and nobody had checked — that the comparison matches at all.

    use std::path::{Path, PathBuf};

    use super::*;

    /// A tree that removes itself.
    struct Root(PathBuf);

    impl Root {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-guards-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temporary root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Writes a file, creating its directories.
        fn write(&self, relative: &str, contents: &str) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a directory");
            }
            std::fs::write(path, contents).expect("a file");
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A `cargo tree` line, as `tree_of` produces them: trimmed and lowercased.
    fn line(text: &str) -> String {
        text.trim().to_lowercase()
    }

    #[test]
    fn the_gui_guard_fires_on_a_banned_dependency() {
        let lines = [line("synra-core"), line("tauri 2.0.0"), line("serde 1")];
        let found = banned_lines(&lines, &["synra-core"], &["tauri", "wry", "tao"]);

        assert_eq!(found.len(), 1, "the tauri line is a violation: {found:?}");
        assert!(found[0].contains("tauri"), "{found:?}");
        // And a tree without one is quiet, so the guard is not simply reporting everything.
        assert!(banned_lines(&[line("synra-core"), line("serde 1")], &["synra-core"], &["tauri"]).is_empty());
    }

    #[test]
    fn the_io_guard_fires_on_a_runtime_in_the_protocol_layer() {
        // The guard's own subject: `synra-protocol` is the part both ends agree on, and a runtime there would decide it.
        let lines = [line("synra-protocol"), line("tokio 1.40.0"), line("serde 1")];
        let found = banned_lines(&lines, &["synra-protocol"], &["tokio", "wasmtime", "rusqlite", "hyper"]);

        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("tokio"), "{found:?}");
    }

    #[test]
    fn the_thin_bin_guard_fires_on_a_main_that_has_grown() {
        let root = Root::new("thin");
        // Exactly one line over the limit, so the test fails if the comparison is off by one in either direction.
        let over = "fn main() {}\n".repeat(61);
        root.write("apps/synra-cli/src/main.rs", &over);

        let found = guard_bins_are_thin(root.path());
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("61 lines"), "{found:?}");

        // And a main at the limit is accepted.
        let root = Root::new("thin-ok");
        root.write("apps/synra-cli/src/main.rs", &"fn main() {}\n".repeat(60));
        assert!(guard_bins_are_thin(root.path()).is_empty());
    }

    #[test]
    fn the_directories_guard_fires_outside_the_one_file_allowed_to_ask() {
        let root = Root::new("directories");
        root.write("crates/synra-store/src/paths.rs", "let x = directories::BaseDirs::new();");
        root.write("crates/synra-core/src/elsewhere.rs", "let x = directories::BaseDirs::new();");

        let found = guard_directories_is_contained(root.path());
        assert_eq!(found.len(), 1, "only the second file: {found:?}");
        assert!(found[0].contains("elsewhere.rs"), "{found:?}");
        // And the allowed file is what is exempt, rather than the scan missing everything.
        assert!(found.iter().all(|line| !line.contains("paths.rs")), "{found:?}");
    }

    #[test]
    fn the_deletion_guard_fires_outside_the_one_file_allowed_to_own_a_tree() {
        // ★ This guard had no test until round 120, which is the defect the module's own documentation names: a criterion
        // that cannot fail is not a criterion, and this one had never been shown to fail.
        let root = Root::new("deletion");
        root.write("crates/synra-core/src/elsewhere.rs", "fn f() { let _ = remove_dir_all(p); }");

        let found = guard_directory_deletion_is_contained(root.path());
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("elsewhere.rs"), "{found:?}");
    }

    #[test]
    fn the_deletion_guard_reads_a_mention_as_a_mention() {
        // ★ A module that explains why it does not delete a tree names the call it does not make. The first such file
        // was reported by this guard, which made writing the reason down a violation — the same confusion as the
        // `#[cfg(test)]` boundary above, one line further down.
        let root = Root::new("deletion-mention");
        root.write(
            "crates/synra-core/src/explains.rs",
            "/// # Why not `remove_dir_all`\n///\n/// Because the guard forbids it.\nfn f() {}",
        );

        let found = guard_directory_deletion_is_contained(root.path());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_deletion_guard_allows_the_sandbox_and_test_code() {
        // The control, and it is the half that matters: a guard that fired on everything would pass the test above and be
        // useless. These are the exemptions the rule names — the sandbox, a file whose name says test, a `tests`
        // directory, and code below a `#[cfg(test)]` marker that is actually a marker.
        let root = Root::new("deletion-allowed");
        root.write("crates/synra-store/src/sandbox.rs", "fn f() { let _ = remove_dir_all(p); }");
        root.write("crates/synra-core/src/tests.rs", "fn f() { let _ = remove_dir_all(p); }");
        root.write("crates/synra-core/tests/it.rs", "fn f() { let _ = remove_dir_all(p); }");
        root.write(
            "crates/synra-core/src/below.rs",
            "fn production() {}\n#[cfg(test)]\nmod t { fn f() { let _ = remove_dir_all(p); } }",
        );

        let found = guard_directory_deletion_is_contained(root.path());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_dial_guard_fires_on_a_command_that_dials_under_the_lock() {
        // The shape rounds 118 and 119 removed: the guard's subject is a command that takes the host's lock and then
        // performs the network operation while still holding it.
        let root = Root::new("dial");
        root.write(
            "apps/synra-daemon/src/runtime/commands.rs",
            "fn f() { let mut host = l(); host.dial(a, None, n)?; drop(host); }",
        );

        let found = guard_daemon_dials_without_the_lock(root.path());
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("commands.rs"), "{found:?}");
    }

    #[test]
    fn the_dial_guard_allows_the_two_halves_and_test_code() {
        // The control, and it is the Interesting half: the halves are precisely what a fixed call site uses, so a guard
        // that flagged `dial_peer` would forbid the fix it exists to protect.
        let root = Root::new("dial-allowed");
        root.write(
            "apps/synra-daemon/src/runtime/commands.rs",
            "fn f() { let d = synra_core::dial_peer(&a, b, c, None, n)?; host.adopt(d, n)?; }",
        );
        root.write(
            "apps/synra-daemon/src/transport/tests.rs",
            "fn f() { let mut host = l(); host.dial(a, None, n); }",
        );
        root.write("apps/synra-daemon/src/x_test.rs", "fn f() { host.dial(a, None, n); }");

        let found = guard_daemon_dials_without_the_lock(root.path());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_gate_guard_fires_on_an_ungated_action() {
        let root = Root::new("gate");
        // The table's real shape: `("synra:plugin/host#name", Some("cap"))` or `, None)` for an ungated call.
        root.write(
            "crates/synra-plugin-host/src/generated/capability_table.rs",
            "pub const GATE: &[(&str, Option<&str>)] = &[\n    (\"synra:plugin/host#log\", Some(\"log:*\")),\n    (\"synra:plugin/host#env-locale\", None),\n    (\"synra:plugin/host#device-send\", None),\n];\n",
        );

        let found = guard_host_functions_are_gated(root.path());
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("device-send"), "{found:?}");
        // The three families that only report facts are allowed to be ungated, and `env-locale` is one of them.
        assert!(found.iter().all(|line| !line.contains("env-locale")), "{found:?}");
    }

    #[test]
    fn the_gate_guard_fires_when_it_cannot_read_the_table_at_all() {
        // """ + S + """ The failure guard 5 actually had, in its other form: a file it was told to read that is not there.
        // A guard that returns nothing because its subject is missing is a guard that has stopped checking.
        let root = Root::new("gate-missing");
        let found = guard_host_functions_are_gated(root.path());

        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("is missing"), "{found:?}");
    }

    #[test]
    fn the_gate_guard_fires_when_the_table_parses_to_nothing() {
        // The anti-silence check: a table whose format changed would otherwise parse to zero entries and report `ok`.
        let root = Root::new("gate-format");
        root.write(
            "crates/synra-plugin-host/src/generated/capability_table.rs",
            "pub const GATE: &[(&str, Option<&str>)] = &[];\n",
        );
        let found = guard_host_functions_are_gated(root.path());

        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("stopped reading"), "{found:?}");
    }
}
