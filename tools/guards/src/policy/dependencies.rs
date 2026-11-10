use std::path::Path;
use std::process::Command;

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
pub(crate) fn banned_lines(lines: &[String], packages: &[&str], banned: &[&str]) -> Vec<String> {
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
pub(crate) fn guard_no_gui(root: &Path) -> Vec<String> {
    banned_dependencies(
        root,
        &["synra-core", "synra-net", "synra-protocol", "synra-plugin-host"],
        &["tauri", "wry", "tao"],
    )
}

/// 2. The protocol layer must stay free of IO: it is the part both ends agree on, and a runtime there would decide it.
pub(crate) fn guard_protocol_has_no_io(root: &Path) -> Vec<String> {
    banned_dependencies(root, &["synra-protocol"], &["tokio", "wasmtime", "rusqlite", "hyper"])
}
