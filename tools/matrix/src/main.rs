//! `matrix` — the feature and target combination matrix, as an executable check.
//!
//! # Why this exists
//!
//! `06-workspace-layout.md` §6 lists the combinations CI is supposed to run, and warns that "core's CI must run this
//! whole matrix, or 'the kernel can be headless / can be mobile' will quietly rot." It had never been run: the flags it
//! names did not exist, and the two rows that matter most — the cross-compilation ones — could not have passed on any
//! machine.
//!
//! This runs it, or it says out loud which rows cannot run and what they are each missing.
//!
//! # The rule this tool is built around
//!
//! **A row that cannot run is reported as `SKIP` with the reason, never as a pass.** The mistake recorded in
//! `NOTES/2026-02-the-feature-matrix-was-never-buildable.md` is that five of seven rows named flags that did not exist,
//! and the two that did work reported success for a check that verified nothing — which is worse than reporting nothing,
//! because it looks like coverage.
//!
//! So a row is one of three things, and the three are never conflated:
//!
//! | Verdict | Meaning |
//! | --- | --- |
//! | `ok` | cargo compiled this combination. Something was checked. |
//! | `FAIL` | cargo ran and refused. A real defect. |
//! | `SKIP` | cargo could not run, or the combination does not exist yet. Named, with the remedy. |
//!
//! # What it deliberately does not do
//!
//! It does not claim the mobile story works. `cargo check` never links and never runs, so a green Android row proves the
//! dependency graph survives the target — not that an `.so` links, not that a component instantiates on a phone, and
//! not that Cranelift's JIT can obtain executable memory on a release build. Those are spikes 1 and 2 in
//! `spike/RESULTS.md`, and they still need a device.
//!
//! # Why a Rust binary and not a shell script
//!
//! Same reason as `guards`: the workspace is Rust and only Rust, and this runs wherever `cargo` does.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};

/// One combination the workspace claims to support.
struct Row {
    /// The claim, phrased so a failure reads as a sentence rather than as a command that failed.
    claim: &'static str,
    /// Where the claim comes from, so a reader can check the reasoning.
    source: &'static str,
    /// Arguments passed to `cargo check`.
    args: &'static [&'static str],
    /// What this row needs that is not there yet, or `None` when the row can run.
    ///
    /// A row with a reason is **not run at all**. Naming the missing capability is the useful output; discovering that
    /// `cargo` refuses an unknown flag is not, because that reports the same thing without saying why.
    blocked_by: Option<&'static str>,
}

/// The Android target every cross-compilation row is written against.
const ANDROID: &str = "aarch64-linux-android";

/// The rows, in the order a reader should meet them: the kernel that must be portable, then the two features, then the
/// combinations that do not exist yet.
fn rows() -> Vec<Row> {
    vec![
        Row {
            claim: "the protocol layer compiles for Android",
            source: "06 §2.1 · 06 §6",
            args: &[
                "-p",
                "synra-protocol",
                "-p",
                "synra-capability",
                "--target",
                ANDROID,
            ],
            blocked_by: None,
        },
        Row {
            claim: "the transport layer compiles for Android",
            source: "06 §6 · mobile-check",
            args: &["-p", "synra-net", "--target", ANDROID],
            blocked_by: None,
        },
        Row {
            claim: "persistence compiles for Android",
            source: "06 §5.4 · 06 §6",
            args: &["-p", "synra-store", "--target", ANDROID],
            blocked_by: None,
        },
        Row {
            claim: "the kernel compiles for Android",
            source: "06 §6",
            args: &["-p", "synra-core", "--target", ANDROID],
            blocked_by: None,
        },
        Row {
            claim: "the plugin host compiles for Android with a real engine",
            source: "06 §5.2 · 06 §6",
            args: &[
                "-p",
                "synra-plugin-host",
                "--features",
                "wasm-runtime",
                "--target",
                ANDROID,
            ],
            blocked_by: None,
        },
        Row {
            claim: "the plugin host compiles with no engine at all",
            source: "06 §5.2",
            args: &["-p", "synra-plugin-host", "--no-default-features"],
            blocked_by: None,
        },
        Row {
            claim: "the CLI compiles on its own",
            source: "06 §6",
            args: &["-p", "synra-cli"],
            blocked_by: None,
        },
        Row {
            claim: "the kernel can be built without its plugin subsystem",
            source: "06 §5.3 · 06 §6",
            args: &[
                "-p",
                "synra-core",
                "--no-default-features",
                "--features",
                "plugins",
            ],
            blocked_by: Some(
                "`synra-core` declares no `plugins` feature, and could not usefully gain one: its source never names \
                 `synra_plugin_host` or `synra_plugin_api`, so there is no subsystem for the flag to switch off. The \
                 wiring is the missing piece — see NOTES/2026-02-the-plugin-host-was-never-wired.md.",
            ),
        },
        Row {
            claim: "the kernel can run plugins on the wasmi interpreter",
            source: "06 §5.2 · 06 §6",
            args: &[
                "-p",
                "synra-core",
                "--no-default-features",
                "--features",
                "plugins,synra-plugin-host/wasmi",
            ],
            blocked_by: Some(
                "no `wasmi` dependency exists, so the flag would select an empty backend. Whether wasmi replaces \
                 wasmtime at compile time or at run time is still a design question, not a build flag.",
            ),
        },
        Row {
            claim: "the mobile build can use a precompiled engine",
            source: "06 §5.2 · 06 §6",
            args: &[
                "-p",
                "synra-plugin-host",
                "--features",
                "wasmtime-aot",
                "--target",
                ANDROID,
            ],
            blocked_by: Some(
                "no `wasmtime-aot` feature exists. Note that on the evidence in spike/RESULTS.md this is an iOS \
                 requirement: wasmtime sets `has_host_compiler_backend` for Android, so cranelift is available there.",
            ),
        },
        Row {
            claim: "the kernel can be built without its TCP transport",
            source: "06 §5.1 · 06 §6",
            args: &[
                "-p",
                "synra-core",
                "--no-default-features",
                "--features",
                "transport-tcp",
            ],
            blocked_by: Some(
                "`synra-net` declares no features, and its TCP transport is the only transport implemented. A flag that \
                 removed it would have nothing to remove.",
            ),
        },
    ]
}

fn main() -> ExitCode {
    let Some(root) = workspace_root() else {
        eprintln!("matrix: run this from inside the workspace (no [workspace] Cargo.toml above)");
        return ExitCode::FAILURE;
    };

    let mut failures = 0;
    let mut skipped = 0;

    for row in rows() {
        if let Some(reason) = row.blocked_by {
            skipped += 1;
            println!("SKIP  {}  ({})", row.claim, row.source);
            for line in wrap(reason) {
                println!("        {line}");
            }
            println!();
            continue;
        }

        match run(&root, row.args) {
            Ok(output) if output.status.success() => {
                println!("ok    {}  ({})", row.claim, row.source);
            }
            Ok(output) => match environmental(&output) {
                Some(remedy) => {
                    skipped += 1;
                    println!("SKIP  {}  ({})", row.claim, row.source);
                    for line in wrap(remedy) {
                        println!("        {line}");
                    }
                }
                None => {
                    failures += 1;
                    println!("FAIL  {}  ({})", row.claim, row.source);
                    for line in command(row.args) {
                        println!("        cargo check {}", line);
                    }
                    for line in errors(&output) {
                        println!("        {line}");
                    }
                }
            },
            Err(error) => {
                failures += 1;
                println!("FAIL  {}  ({})", row.claim, row.source);
                println!("        {error}");
            }
        }
        println!();
    }

    let ran = rows().len() - skipped;
    println!("{ran} row(s) checked · {skipped} skipped · {failures} failed");
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Runs `cargo check` and hands back the raw result.
///
/// A `cargo` that cannot be launched at all is an error rather than a skip: "could not check" and "checked and passed"
/// are different answers, and only one of them is a promise kept.
fn run(root: &Path, args: &[&str]) -> Result<Output, String> {
    Command::new(env!("CARGO"))
        .arg("check")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("cargo could not be run: {error}"))
}

/// Recognises a failure that is about this machine rather than about the code, and names the remedy.
///
/// Each arm is a thing a developer installs once. Reporting any of them as `FAIL` would be a false accusation, and a
/// check that cries wolf is one people learn to ignore — so the remedies are stated, not guessed at.
fn environmental(output: &Output) -> Option<&'static str> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("can't find crate for `core`") || stderr.contains("E0463") {
        return Some(
            "the target's standard library is not installed — `rustup target add aarch64-linux-android`",
        );
    }
    if stderr.contains("failed to find tool") || stderr.contains("aarch64-linux-android-clang") {
        return Some(
            "no Android C toolchain — install the NDK and point `CC_aarch64_linux_android` at \
             `toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android24-clang.cmd`",
        );
    }
    if stderr.contains("StorageFull") || stderr.contains("os error 112") {
        return Some("the build ran out of disk — point `CARGO_TARGET_DIR` at a volume with room");
    }
    None
}

/// The `error` lines of a failed check, without the trailing whitespace and noise cargo prints around them.
///
/// Owned rather than borrowed: the stderr buffer is a temporary that does not outlive the call.
fn errors(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(str::trim_end)
        .filter(|line| line.starts_with("error"))
        .take(6)
        .map(ToOwned::to_owned)
        .collect()
}

/// The command a reader would type to reproduce the row.
fn command(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

/// Folds a reason onto lines short enough to read under a `SKIP` heading.
///
/// A single 200-character line is not read; four 80-character ones are. This is why the reasons above are written as
/// prose and not as sentences assembled from parts.
fn wrap(reason: &'static str) -> Vec<String> {
    const WIDTH: usize = 76;
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in reason.split_whitespace() {
        if current.is_empty() {
            current = word.to_owned();
        } else if current.chars().count() + 1 + word.chars().count() <= WIDTH {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_owned();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        vec![reason.to_owned()]
    } else {
        lines
    }
}

/// The workspace root: the nearest ancestor whose `Cargo.toml` declares `[workspace]`.
fn workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file()
            && std::fs::read_to_string(&manifest).is_ok_and(|t| t.contains("[workspace]"))
        {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}
