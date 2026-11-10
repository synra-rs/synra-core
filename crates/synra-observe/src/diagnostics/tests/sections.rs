use super::*;

#[rstest]
#[case("ts=1 level=ERROR event=boom", true, false)]
#[case("ts=1 level=DEBUG event=x", false, true)]
#[case("ts=1 level=TRACE event=x", false, true)]
#[case("ts=1 level=INFO event=x", false, false)]
#[case("ts=1 level=WARN event=x", false, false)]
fn level_detection_matches_the_line(#[case] line: &str, #[case] error: bool, #[case] debug: bool) {
    assert_eq!(is_error_line(line), error, "{line}");
    assert_eq!(is_debug_line(line), debug, "{line}");
}

#[test]
fn a_section_name_round_trips_through_json() {
    for section in BundleSection::ALL {
        let json = serde_json::to_string(section).expect("serialises");
        assert_eq!(json, format!("\"{}\"", section.as_str()));
        let back: BundleSection = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, *section);
    }
}

#[test]
fn section_names_are_unique() {
    // A duplicate name would make `contains` answer for the wrong section.
    let mut names = std::collections::HashSet::new();
    for section in BundleSection::ALL {
        assert!(names.insert(section.as_str()), "duplicate name {section:?}");
    }
    assert_eq!(BundleSection::ALL.len(), names.len());
}

#[test]
fn the_bundle_carries_the_audit_trail_only_when_asked() {
    let mut sources = sources();
    sources.audit = Some(vec![AuditEntry::new(
        1_000,
        synra_protocol::PluginId::parse("@synra-plugin/chat").expect("valid"),
        synra_capability::Capability::parse("network:fetch:evil.com").expect("valid"),
        crate::audit::AuditOutcome::Denied,
        None,
    )]);

    let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
    assert!(plan.build().audit_trail.is_none());

    plan.toggle_optional(BundleSection::AuditTrail, true);
    let bundle = plan.build();
    assert_eq!(bundle.audit_trail.as_ref().map(Vec::len), Some(1));
    // And the refusal is visible in the rendered file, which is the point of including it.
    let rendered = plan.render().expect("renders");
    assert!(rendered.contains("evil.com"), "{rendered}");
}
