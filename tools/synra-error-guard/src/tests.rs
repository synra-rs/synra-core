use super::*;

fn source(text: &str) -> Source {
    Source {
        path: "fixture.rs".to_owned(),
        text: text.to_owned(),
    }
}

#[test]
fn unpublished_apis_allow_exhaustive_enums_public_dtos_and_trait_refactors() {
    let fixture = source(
        r#"
        pub enum ResultKind { Success, Failed }
        pub struct Snapshot { pub values: std::collections::HashMap<String, String> }
        pub trait Service { fn apply(&mut self); }
    "#,
    );
    for boundary in [Boundary::Domain, Boundary::Adapter] {
        assert!(check(&fixture, boundary).is_empty());
    }
    assert!(
        check(
            &source("#[non_exhaustive] pub enum Kind { A }"),
            Boundary::Domain
        )
        .is_empty()
    );
}

#[test]
fn domain_errors_still_require_classification() {
    let source = source("pub enum Failure { Io(std::io::Error) }");
    assert!(matches!(
        check(&source, Boundary::Domain).as_slice(),
        [Violation::ForeignError { .. }]
    ));
    assert!(check(&source, Boundary::Adapter).is_empty());
}

#[test]
fn source_failures_are_not_successful_checks() {
    assert!(matches!(
        Source::read(std::path::Path::new("/nonexistent/synra/source.rs")),
        Err(Violation::Unreadable { .. })
    ));
    for boundary in [Boundary::Domain, Boundary::Adapter] {
        assert!(matches!(
            check(&source("pub enum"), boundary).as_slice(),
            [Violation::Unreadable { .. }]
        ));
    }
}

#[test]
fn the_catalogue_classifies_each_actual_workspace_library_once() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output =
        std::process::Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--no-deps",
                "--format-version",
                "1",
            ])
            .current_dir(&root)
            .output()
            .expect("workspace metadata");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("metadata JSON");
    let members = metadata["workspace_members"].as_array().expect("members");
    let mut actual: Vec<&str> = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|package| members.contains(&package["id"]))
        .filter(|package| {
            std::path::Path::new(package["manifest_path"].as_str().expect("manifest"))
                .parent()
                .and_then(std::path::Path::parent)
                .and_then(std::path::Path::file_name)
                .is_some_and(|name| name == "crates")
        })
        .map(|package| package["name"].as_str().expect("name"))
        .collect();
    assert!(!actual.is_empty());
    let mut classified: Vec<_> = CRATES.iter().map(|(name, _)| *name).collect();
    let before = classified.len();
    classified.sort_unstable();
    classified.dedup();
    assert_eq!(before, classified.len(), "duplicate catalogue entry");
    actual.sort_unstable();
    assert_eq!(actual, classified);
}
