//! Run the actual boundary guard against the workspace and its declared policy.

#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace")
}

const RULE_FRAGMENTS: [&str; 2] = ["without a Synra error boundary", "could not be read"];

#[test]
fn domain_interfaces_keep_classified_errors_without_compatibility_requirements() {
    let output = Command::new(env!("CARGO_BIN_EXE_api-guard"))
        .arg(workspace_root())
        .output()
        .expect("guard");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("no violations"));
}

#[test]
fn the_document_and_guard_classify_the_same_libraries_and_boundaries() {
    let document = std::fs::read_to_string(workspace_root().join("STABILITY.md")).expect("policy");
    assert!(document.contains("**Unpublished**"));
    for (label, boundary) in [
        ("Domain", api_guard::Boundary::Domain),
        ("Adapter", api_guard::Boundary::Adapter),
    ] {
        let mut documented: Vec<_> = document
            .lines()
            .filter(|line| line.starts_with(&format!("| {label} |")))
            .flat_map(|line| line.split('`').skip(1).step_by(2))
            .filter(|name| name.starts_with("synra-"))
            .collect();
        let mut classified: Vec<_> = api_guard::CRATES
            .iter()
            .filter(|(_, scope)| *scope == boundary)
            .map(|(name, _)| *name)
            .collect();
        assert!(!documented.is_empty(), "missing {label} policy");
        documented.sort_unstable();
        classified.sort_unstable();
        assert_eq!(documented, classified);
    }
}

#[test]
fn an_unreadable_workspace_is_a_failed_check() {
    let missing = workspace_root()
        .join("target")
        .join(format!("api-guard-missing-{}", std::process::id()));
    assert!(!missing.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_api-guard"))
        .arg(missing)
        .output()
        .expect("guard");
    assert!(!output.status.success());
}

#[test]
fn the_filter_reads_every_rule_the_tool_can_report() {
    let source = std::fs::read_to_string(workspace_root().join("tools/api-guard/src/lib.rs"))
        .expect("source");
    let syntax = syn::parse_file(&source).expect("guard Rust syntax");
    let templates: Vec<String> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item) if item.ident == "Violation" => Some(item),
            _ => None,
        })
        .flat_map(|item| &item.variants)
        .flat_map(|variant| &variant.attrs)
        .filter(|attribute| attribute.path().is_ident("error"))
        .map(|attribute| {
            attribute
                .parse_args::<syn::LitStr>()
                .expect("error message")
                .value()
        })
        .collect();
    assert!(!templates.is_empty());
    for template in &templates {
        assert!(
            RULE_FRAGMENTS
                .iter()
                .any(|fragment| template.contains(fragment)),
            "uncovered rule: {template}"
        );
    }
    for fragment in RULE_FRAGMENTS {
        assert!(
            templates.iter().any(|template| template.contains(fragment)),
            "stale fragment: {fragment}"
        );
    }
}
