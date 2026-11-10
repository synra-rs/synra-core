use super::super::error::ManifestError;
use super::super::types::ManifestContext;
use super::{MINIMAL, parse};

#[test]
fn a_plugin_that_composes_with_itself_is_refused() {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"compose\": [{ \"id\": \"@synra-plugin/chat\", \"version\": \"^1.0.0\" }]",
    );
    let manifest = parse(&text);
    assert!(matches!(
        manifest.validate(&ManifestContext::default()),
        Err(ManifestError::CompositionCycle { .. })
    ));
}

#[test]
fn a_dependency_with_a_bad_version_is_refused() {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"compose\": [{ \"id\": \"@synra-plugin/format\", \"version\": \"latest\" }]",
    );
    assert!(parse(&text).validate(&ManifestContext::default()).is_err());
}

#[test]
fn a_dependency_range_is_accepted_with_its_operator() {
    for range in ["^1.0.0", "~1.2.0", "=1.0.0", ">=1.0.0"] {
        let text = MINIMAL.replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                &format!(
                    "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                     \"compose\": [{{ \"id\": \"@synra-plugin/format\", \"version\": \"{range}\" }}]"
                ),
            );
        assert_eq!(
            parse(&text).validate(&ManifestContext::default()),
            Ok(()),
            "{range}"
        );
    }
}
