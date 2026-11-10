use super::super::error::ManifestError;
use super::super::types::ManifestContext;
use super::{MINIMAL, minimal, parse};

#[test]
fn a_plugin_needing_a_newer_sdk_than_the_host_is_refused_with_both_versions() {
    let manifest = parse(&MINIMAL.replace("\"min\": \"1.0.0\"", "\"min\": \"9.0.0\""));
    let context = ManifestContext {
        host_sdk: Some("1.2.0".to_owned()),
        ..ManifestContext::default()
    };
    match manifest.validate(&context) {
        Err(ManifestError::SdkTooOld { min, host }) => {
            assert_eq!(min, "9.0.0");
            assert_eq!(host, "1.2.0");
        }
        other => panic!("expected an SDK refusal, got {other:?}"),
    }
}

#[test]
fn a_plugin_the_host_satisfies_is_accepted() {
    let manifest = minimal();
    let context = ManifestContext {
        host_sdk: Some("1.0.0".to_owned()),
        ..ManifestContext::default()
    };
    assert_eq!(manifest.validate(&context), Ok(()));

    // A host above the minimum is fine, including one where the plugin's minimum is a pre-release of it.
    let below = parse(&MINIMAL.replace("\"min\": \"1.0.0\"", "\"min\": \"1.0.0-rc.1\""));
    assert_eq!(below.validate(&context), Ok(()));
}

#[test]
fn a_wit_mismatch_names_both_worlds() {
    let manifest = minimal();
    let context = ManifestContext {
        host_wit: Some("synra:plugin@2.0.0".to_owned()),
        ..ManifestContext::default()
    };
    match manifest.validate(&context) {
        Err(ManifestError::WitMismatch { plugin, host }) => {
            assert_eq!(plugin, "synra:plugin@1.0.0");
            assert_eq!(host, "synra:plugin@2.0.0");
        }
        other => panic!("expected a WIT refusal, got {other:?}"),
    }
}
