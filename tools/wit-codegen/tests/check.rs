//! Exercise the command's check option and its read-only failure through the actual binary.

// Test setup and assertions deliberately fail with local diagnostic context.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output};

fn invoke(path: &Path, check_first: bool, check_last: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wit-codegen"));
    if check_first {
        command.arg("--check");
    }
    command.arg(path);
    if check_last {
        command.arg("--check");
    }
    command.output().unwrap()
}

#[test]
fn the_cli_checks_all_outputs_with_the_option_before_or_after_the_source() {
    let dir = tempfile::tempdir().unwrap();
    let contract = dir.path().join("wit/synra-plugin.wit");
    std::fs::create_dir_all(contract.parent().unwrap()).unwrap();
    std::fs::write(&contract, include_str!("../../../wit/synra-plugin.wit")).unwrap();
    let generated = invoke(&contract, false, false);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    for (first, last) in [(true, false), (false, true)] {
        let checked = invoke(&contract, first, last);
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }
    let bundle = dir
        .path()
        .join("crates/synra-plugin-sdk/wit/synra-plugin.wit");
    std::fs::remove_file(&bundle).unwrap();
    let checked = invoke(&contract, true, false);
    assert!(!checked.status.success());
    assert!(String::from_utf8_lossy(&checked.stderr).contains("synra-plugin-sdk"));
    assert!(!bundle.exists());
}
