//! Actual filesystem mutations must be detected for every derived file.

use super::*;

const SOURCE: &str = include_str!("../../../../wit/synra-plugin.wit");

fn source(dir: &Path) -> PathBuf {
    let file = dir.join("wit/synra-plugin.wit");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, SOURCE).unwrap();
    file
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
