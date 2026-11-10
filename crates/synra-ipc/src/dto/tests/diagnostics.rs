use super::super::DiagExportOptions;

#[test]
fn a_diagnostic_export_defaults_to_the_least_intrusive_bundle() {
    // The optional sections are the ones that name the plugins the user runs and the ones most likely to
    // contain something they did not intend to share.
    let options = DiagExportOptions::default();
    assert!(!options.include_audit);
    assert!(!options.include_debug_logs);
    assert_eq!(options.log_lines, None);
}

#[test]
fn a_diagnostic_export_refuses_an_unknown_field() {
    // A mistyped option would otherwise silently export the defaults, which is the sort of thing a user
    // discovers by reading the file they just sent.
    let json = r#"{ "includeAudit": true, "mystery": 1 }"#;
    assert!(serde_json::from_str::<DiagExportOptions>(json).is_err());
}
