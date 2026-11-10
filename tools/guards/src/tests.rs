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
use super::policy::dependencies::banned_lines;

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
