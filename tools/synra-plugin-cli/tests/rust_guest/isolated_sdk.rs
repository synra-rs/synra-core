//! Copies the actual SDK library and its own assets into a workspace without the source repository.

use std::path::{Path, PathBuf};

pub(super) fn copy(into: &Path) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = root.join("crates/synra-plugin-sdk");
    let target = into.join("isolated/sdk");
    copy_tree(&source, &target);
    let manifest = target.join("Cargo.toml");
    let mut sdk = std::fs::read_to_string(&manifest)
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let workspace = std::fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    // Cargo expands workspace metadata when producing a standalone crate; preserve those actual values here.
    // Source files and normal dependencies remain untouched, and no repository WIT directory is copied.
    let mut tables = workspace.get("workspace").unwrap().clone();
    let table = tables.as_table_mut().unwrap();
    table.remove("members");
    table.remove("default-members");
    table.remove("exclude");
    sdk.insert("workspace", tables);
    std::fs::write(manifest, sdk.to_string()).unwrap();
    assert!(!target.join("../../wit/synra-plugin.wit").exists());
    target
}

fn copy_tree(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if matches!(name.to_str(), Some("tests" | "target" | ".git")) {
            continue;
        }
        let kind = entry.file_type().unwrap();
        let destination = target.join(name);
        if kind.is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            assert!(
                kind.is_file(),
                "SDK fixture must not follow external symlinks"
            );
            std::fs::copy(entry.path(), destination).unwrap();
        }
    }
}
