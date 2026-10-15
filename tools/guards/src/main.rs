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
    // Two checks outside the list, because each needs three answers rather than two — `ok`, `SKIP` with a reason, and
    // `FAIL` — and the `Guard` shape has no room for the middle one.
    let app_ok = check_sibling_app(&root);
    let msrv_ok = check_msrv(&root);

    if failures == 0 && app_ok && msrv_ok {
        println!("{} guard(s) passed", guards().len() + 2);
        std::process::ExitCode::SUCCESS
    }
    else {
        if failures > 0 {
            println!("{failures} guard(s) failed");
        }
        std::process::ExitCode::FAILURE
    }
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
