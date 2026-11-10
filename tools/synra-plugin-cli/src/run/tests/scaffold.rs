use std::path::PathBuf;

use crate::args::NewArgs;
use crate::template::TemplateKind;

use super::super::{Outcome, new_plugin};

pub(super) fn new_args(dir: Option<PathBuf>, dry_run: bool) -> NewArgs {
    NewArgs {
        plugin_id: "@synra-plugin/example".to_owned(),
        version: "0.1.0".to_owned(),
        title: None,
        template: TemplateKind::Headless,
        dir,
        dry_run,
    }
}

#[test]
fn a_scaffold_decides_a_root_and_a_file_list() {
    let outcome = new_plugin(&new_args(None, false)).expect("builds");
    let Outcome::Scaffold { files, .. } = &outcome else {
        panic!("expected a scaffold, got {outcome:?}");
    };
    assert!(files.iter().any(|(path, _)| path == "manifest.json"), "{files:?}");
    assert!(files.iter().all(|(path, _)| !path.starts_with('/')), "{files:?}");
}

#[test]
fn the_root_defaults_to_the_wire_slug() {
    // The name the artifact uses in the registry, the cache and the log, so the author's directory matches all of
    // them — and a directory named after the raw id would contain a `/` and a scope.
    let outcome = new_plugin(&new_args(None, false)).expect("builds");
    let Outcome::Scaffold { root, files, .. } = &outcome else {
        panic!("expected a scaffold");
    };
    assert_eq!(root, &PathBuf::from("example"), "the root is not the wire slug");
    // And every path inside it is relative, so no message about a file mentions the author's home directory.
    for (path, _) in files {
        assert!(!path.contains('@'), "{path} is not a plain path");
        assert!(!std::path::Path::new(path).is_absolute(), "{path} is absolute");
    }
}

#[test]
fn an_explicit_directory_is_used() {
    // So an author can scaffold into a monorepo without a move afterwards.
    let dir = tempfile::Builder::new().prefix("explicit").tempdir().expect("a temporary directory");
    let outcome = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
    let Outcome::Scaffold { root, .. } = &outcome else {
        panic!("expected a scaffold");
    };
    assert_eq!(root, dir.path());
}

#[test]
fn a_dry_run_decides_no_files_but_the_same_listing() {
    // ★ The reason the outcome is a value: a dry run and a real run produce the same listing, so a `--dry-run`
    // implemented as a second branch would be a branch that drifts.
    let dry = new_plugin(&new_args(None, true)).expect("builds");
    let real = new_plugin(&new_args(None, false)).expect("builds");

    let Outcome::Scaffold { files: dry_files, lines: dry_lines, .. } = &dry else {
        panic!("expected a scaffold");
    };
    let Outcome::Scaffold { files: real_files, lines: real_lines, .. } = &real else {
        panic!("expected a scaffold");
    };

    assert!(dry_files.is_empty(), "a dry run decided to write {} files", dry_files.len());
    assert!(!real_files.is_empty());
    // The listing is the same, minus the closing sentence.
    assert_eq!(dry_lines[..dry_lines.len() - 1], real_lines[..real_lines.len() - 1]);
    assert!(dry_lines.last().expect("a line").contains("dry run"));
}

#[test]
fn the_listing_marks_generated_files_apart_from_authored_ones() {
    // The distinction that decides what a rebase will conflict with.
    let outcome = new_plugin(&new_args(None, false)).expect("builds");
    let lines = outcome.lines();
    assert!(lines.iter().any(|line| line.starts_with("gen")), "{lines:?}");
    assert!(lines.iter().any(|line| line.starts_with("   ")), "{lines:?}");
}

#[test]
fn a_reserved_scope_is_refused_with_a_sentence() {
    // The message is read at the moment the author is least able to guess.
    let mut args = new_args(None, false);
    args.plugin_id = "@synra/chat".to_owned();
    let error = new_plugin(&args).expect_err("refused");
    assert!(error.contains("plugin id"), "{error}");
}

#[test]
fn an_unusable_version_is_refused() {
    let mut args = new_args(None, false);
    args.version = "latest".to_owned();
    assert!(new_plugin(&args).is_err());
}
