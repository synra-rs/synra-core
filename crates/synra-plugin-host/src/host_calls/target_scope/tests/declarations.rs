use super::*;

#[test]
fn import_families_admit_scoped_declarations_without_authorizing_other_calls() {
    for (import, allowed, denied) in [
        (
            "action-declare",
            "action:declare:format-date".to_owned(),
            "action:declare",
        ),
        (
            "device-send",
            format!("device:send:{DEVICE}"),
            "device:list",
        ),
        (
            "action-invoke",
            "action:invoke:@acme/formatter:format-date".to_owned(),
            "action:invoke:*",
        ),
    ] {
        let import = format!("synra:plugin/host#{import}");
        assert!(crate::permits(&import, &grants(&[&allowed])));
        assert!(
            crate::undeclared_imports(std::slice::from_ref(&import), &grants(&[&allowed]))
                .is_empty()
        );
        assert_eq!(
            crate::undeclared_imports(std::slice::from_ref(&import), &grants(&[denied])),
            std::slice::from_ref(&import)
        );
        assert!(!crate::permits(&import, &CapabilitySet::new()));
    }
}

#[test]
fn declarations_require_authority_for_the_actual_name() {
    for (grant, name, expected) in [
        ("action:declare:format-date", "format-date", None),
        (
            "action:declare:format-date",
            "other",
            Some(CallError::CAPABILITY_DENIED),
        ),
        ("action:declare:*", "other", None),
        (
            "action:declare",
            "format-date",
            Some(CallError::CAPABILITY_DENIED),
        ),
        ("action:declare:*", "a:b", Some(CallError::BAD_ARGUMENT)),
    ] {
        check_call(
            grant,
            "action-declare",
            serde_json::json!({"name":name,"schema":"{}"}),
            expected,
        );
    }
}
