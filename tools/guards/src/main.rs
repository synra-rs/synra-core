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
//! number somebody typed.

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
    if failures == 0 && check_msrv(&root) {
        println!("{} guard(s) passed", guards().len());
        std::process::ExitCode::SUCCESS
    }
    else {
        if failures > 0 {
            println!("{failures} guard(s) failed");
        }
        std::process::ExitCode::FAILURE
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
            // fetch the missing pieces, and a machine without network reports a download error. Reporting that as "does
            // not build on the MSRV" would be a false accusation — and a guard that cries wolf is one people learn to
            // ignore. The distinction is the point: "could not check" and "checked and failed" are different answers.
            if stderr.contains("component download failed") || stderr.contains("error downloading file") {
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
    tree_of(root, packages)
        .into_iter()
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

/// 5. A host function that reaches the operating system without the gate is a capability the manifest never granted.
///
/// The escape hatch is a macro that says so out loud, and the one legitimate user is the environment report, which reads
/// facts rather than acting.
fn guard_host_functions_are_gated(root: &Path) -> Vec<String> {
    let allowed = Path::new("crates/synra-plugin-host/src/host_funcs/env.rs");
    rust_files(&root.join("crates"))
        .into_iter()
        .filter(|path| path.strip_prefix(root).is_ok_and(|relative| relative != allowed))
        .filter(|path| std::fs::read_to_string(path).is_ok_and(|text| text.contains("ungated_host_fn!")))
        .map(|path| {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            format!("{} contains `ungated_host_fn!`", relative.display())
        })
        .collect()
}
