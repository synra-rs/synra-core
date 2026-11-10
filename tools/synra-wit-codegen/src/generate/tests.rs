//! Actual filesystem mutations must be detected for every derived file.

use super::*;

const SOURCE: &str = include_str!("../../wit/synra-plugin.wit");

fn source(dir: &Path) -> PathBuf {
    let file = dir.join("wit/synra-plugin.wit");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, SOURCE).unwrap();
    file
}

#[test]
fn fragments_regenerate_the_workspace_contract_and_detect_drift() {
    let dir = tempfile::tempdir().unwrap();
    let wit = dir.path().join("wit");
    std::fs::create_dir_all(wit.join("source")).unwrap();
    let types = SOURCE.find("/// The plugin contract").unwrap();
    let host = SOURCE.find("/// What the host offers a plugin.").unwrap();
    let guest = SOURCE.find("/// What a plugin must implement.").unwrap();
    for (file, contents) in WORKSPACE_FRAGMENTS
        .into_iter()
        .zip([&SOURCE[types..host], &SOURCE[host..guest], &SOURCE[guest..]])
    {
        std::fs::write(wit.join(file), contents).unwrap();
    }
    let contract = wit.join("synra-plugin.wit");
    let outputs = synchronize(&contract, false).unwrap();
    assert_eq!(outputs.len(), 9);
    let combined = std::fs::read_to_string(&contract).unwrap();
    assert_eq!(combined, combined_wit(&workspace_source(&contract).unwrap().unwrap()));
    synchronize(&contract, true).unwrap();

    let guest_file = wit.join("source/guest.wit");
    let guest = std::fs::read_to_string(&guest_file).unwrap();
    std::fs::write(guest_file, format!("{guest}\n// The guest contract changed.\n")).unwrap();
    let GenerateError::Drift { paths } = synchronize(&contract, true).unwrap_err() else {
        panic!("expected a stale contract diagnosis");
    };
    assert!(paths.contains(&contract));
    assert_eq!(std::fs::read_to_string(&contract).unwrap(), combined);
}

#[test]
fn checking_each_stale_artifact_fails_without_repairing_it() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path());
    let outputs = synchronize(&source, false).unwrap();
    assert_eq!(outputs.len(), 6);
    synchronize(&source, true).unwrap();
    for output in outputs {
        let previous = std::fs::read(&output).unwrap();
        std::fs::write(&output, "stale").unwrap();
        let GenerateError::Drift { paths } = synchronize(&source, true).unwrap_err() else {
            panic!("expected a stale-file diagnosis")
        };
        assert_eq!(paths.as_slice(), std::slice::from_ref(&output));
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "stale");
        std::fs::write(output, previous).unwrap();
    }
}

#[test]
fn missing_author_resources_fail_even_when_the_host_table_is_current() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path());
    synchronize(&source, false).unwrap();
    let sdk = dir
        .path()
        .join("crates/synra-plugin-sdk/wit/synra-plugin.wit");
    let host = dir
        .path()
        .join("crates/synra-plugin-host/src/generated/host_trait.rs");
    std::fs::remove_file(&sdk).unwrap();
    std::fs::remove_file(&host).unwrap();
    let cli = dir
        .path()
        .join("tools/synra-plugin-cli/wit/synra-plugin.wit");
    std::fs::remove_file(&cli).unwrap();
    let GenerateError::Drift { paths } = synchronize(&source, true).unwrap_err() else {
        panic!("expected every missing artifact")
    };
    assert_eq!(paths.len(), 3);
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("wit/synra-plugin.wit"))
    );
    assert!(!sdk.exists());
    assert!(!host.exists());
    assert!(!cli.exists());
}

#[test]
fn invalid_contracts_do_not_partially_replace_previous_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path());
    let outputs = synchronize(&source, false).unwrap();
    let before: Vec<Vec<u8>> = outputs
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    std::fs::write(&source, "not a WIT contract").unwrap();
    assert!(matches!(
        synchronize(&source, false),
        Err(GenerateError::Parse(_))
    ));
    let after: Vec<Vec<u8>> = outputs
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    assert_eq!(after, before);
}

#[test]
fn the_sdk_bundle_preserves_the_primary_contract_and_normalizes_line_endings() {
    let source = SOURCE.replace("\r\n", "\n");
    let unix = artifacts(Path::new("wit/synra-plugin.wit"), &source).unwrap();
    let windows = artifacts(
        Path::new("wit/synra-plugin.wit"),
        &source.replace('\n', "\r\n"),
    )
    .unwrap();
    for destination in [
        "crates/synra-plugin-sdk/wit/synra-plugin.wit",
        "tools/synra-plugin-cli/wit/synra-plugin.wit",
    ] {
        let bundle = unix
            .iter()
            .find(|artifact| artifact.path.ends_with(destination))
            .unwrap();
        assert!(
            bundle
                .contents
                .ends_with(&format!("{}\n", SOURCE.replace("\r\n", "\n").trim_end()))
        );
        assert!(!bundle.contents.contains('\r'));
    }
    for (left, right) in unix.iter().zip(&windows) {
        assert_eq!(left.contents, right.contents);
    }
}
