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

use std::path::Path;

mod documents;
mod policy;
mod source_size;
mod workspace;

use documents::{check_document_claims, check_document_guard_counts, check_document_links};
use policy::capabilities::guard_host_functions_are_gated;
use policy::dependencies::{guard_no_gui, guard_protocol_has_no_io};
use policy::rust_source::{
    guard_bins_are_thin, guard_daemon_dials_without_the_lock, guard_directories_is_contained,
    guard_directory_deletion_is_contained,
};
use workspace::{check_msrv, check_sibling_app, workspace_root};

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

    if std::env::args_os().nth(1).is_some_and(|arg| arg == "--source-size") {
        return source_size::check(&root);
    }

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

#[cfg(test)]
mod tests;
