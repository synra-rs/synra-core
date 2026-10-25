//! Exercise the actual guard against the workspace with no false-positive exemptions.

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

const RULE_FRAGMENTS: [&str; 4] = [
    "in its public signature",
    "without `#[non_exhaustive]`",
    "which is a promise about that crate's version",
    "could not be read",
];

#[test]
fn no_crate_that_makes_a_promise_breaks_it() {
    let output = Command::new(env!("CARGO_BIN_EXE_api-guard"))
        .arg(workspace_root())
        .output()
        .expect("api-guard runs");
    assert!(
        output.status.success(),
        "guard failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("no violations"));
}

#[test]
fn the_crates_the_promise_covers_are_the_ones_the_tool_reads() {
    let root = workspace_root();
    let document = std::fs::read_to_string(root.join("STABILITY.md")).expect("STABILITY.md");
    let mut documented: Vec<&str> = document
        .lines()
        .filter(|line| line.starts_with("| **Stable**") || line.starts_with("| **Semi-stable**"))
        .flat_map(|line| line.split('`').skip(1).step_by(2))
        .filter(|name| name.starts_with("synra-"))
        .collect();
    let mut checked: Vec<&str> = api_guard::CRATES
        .iter()
        .filter(|(_, tier)| tier.makes_a_promise())
        .map(|(name, _)| *name)
        .collect();
    documented.sort_unstable();
    checked.sort_unstable();
    assert_eq!(
        documented, checked,
        "the document and guard cover different crates"
    );
    for name in documented {
        assert!(
            root.join("crates").join(name).join("src").is_dir(),
            "missing source for {name}"
        );
    }
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
