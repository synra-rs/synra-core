use std::path::PathBuf;
use synra_store::PathError;
use super::super::{DaemonOptions, PlanError, DATA_DIR_VAR, DEFAULT_DISCOVERY_PORT, DEFAULT_LISTEN_PORT, data_root_from};

#[test]
fn the_default_root_follows_the_same_variable_the_cli_does() {
    // The same variable and the same fallback, so `synra doctor` checks the installation the daemon actually uses.
    // A `doctor` that probed a different directory would report a healthy installation on a machine whose real one
    // is broken.
    assert_eq!(DATA_DIR_VAR, "SYNRA_DATA_DIR");
    assert_eq!(
        data_root_from(Some(std::ffi::OsString::from("/custom"))),
        PathBuf::from("/custom")
    );
    // An empty value is not an answer: it falls back rather than naming the current directory.
    let fallback = data_root_from(None);
    assert!(fallback.is_absolute(), "{fallback:?}");
    assert!(fallback.ends_with("synra"));
    assert_eq!(data_root_from(Some(std::ffi::OsString::new())), fallback);
}

#[test]
fn the_default_options_claim_and_linger() {
    // Two daemons over one database is a correctness problem, so claiming is the default; and a daemon whose
    // purpose is to keep serving after the interface closes must not exit with it.
    let options = DaemonOptions::default();
    assert!(options.exclusive);
    assert!(options.linger);
    assert_eq!(options.listen_port, DEFAULT_LISTEN_PORT);
    assert_eq!(options.discovery_port, DEFAULT_DISCOVERY_PORT);
}

#[test]
fn plan_errors_explain_themselves() {
    let errors = [
        PlanError::PortsCollide { port: 47_100 },
        PlanError::DirectoriesOverlap {
            data_dir: "/a".to_owned(),
            plugins_dir: "/a/plugins".to_owned(),
        },
        PlanError::BadName {
            name: "..".to_owned(),
        },
        PlanError::Path(PathError::Escapes {
            path: "/a".to_owned(),
            root: "/b".to_owned(),
        }),
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
