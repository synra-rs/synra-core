use super::*;

#[test]
fn the_plan_includes_the_required_sections_and_none_of_the_optional_ones() {
    // The consent screen's whole point: nothing sensitive is in the bundle until the user says so.
    let plan = plan();
    assert!(plan.includes(BundleSection::Environment));
    assert!(plan.includes(BundleSection::Logs));
    assert!(!plan.includes(BundleSection::AuditTrail), "off by default");
    assert!(!plan.includes(BundleSection::DebugLogs), "off by default");
    assert!(plan.enabled_optional().is_empty());
}

#[test]
fn only_two_sections_are_optional_and_they_are_the_user_s_own_data() {
    // What the user did, and the detail lines that name their devices and files. Everything else is state
    // the application would report about itself anyway.
    let optional: Vec<BundleSection> =
        BundleSection::ALL.iter().copied().filter(|s| s.is_optional()).collect();
    assert_eq!(optional, vec![BundleSection::AuditTrail, BundleSection::DebugLogs]);

    for section in BundleSection::ALL {
        assert_eq!(section.is_default(), !section.is_optional(), "{section:?}");
    }
}

#[test]
fn a_section_with_no_source_is_not_offered() {
    // A checkbox that does nothing is a checkbox that confuses.
    let sources = BundleSources { environment: None, ..sources() };
    let plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
    assert!(!plan.includes(BundleSection::Environment));
    assert!(!plan.is_available(BundleSection::Environment));
}

#[test]
fn a_required_section_cannot_be_toggled() {
    // The two sensitive sections are the only choices here; a required section is not a decision the user
    // makes, and letting them remove it would produce a bundle a maintainer cannot use.
    let mut plan = plan();
    assert!(!plan.toggle_optional(BundleSection::Environment, false));
    assert!(plan.includes(BundleSection::Environment));
    assert!(!plan.toggle_optional(BundleSection::Metrics, true));
    assert!(!plan.includes(BundleSection::AuditTrail));
}

#[test]
fn an_optional_section_can_be_turned_on_and_off() {
    let mut plan = plan();
    assert!(plan.toggle_optional(BundleSection::AuditTrail, true));
    assert!(plan.includes(BundleSection::AuditTrail));
    assert_eq!(plan.enabled_optional(), vec![BundleSection::AuditTrail]);

    assert!(plan.toggle_optional(BundleSection::AuditTrail, false));
    assert!(!plan.includes(BundleSection::AuditTrail));
}

#[test]
fn toggling_the_same_section_twice_is_idempotent() {
    let mut plan = plan();
    plan.toggle_optional(BundleSection::DebugLogs, true);
    plan.toggle_optional(BundleSection::DebugLogs, true);
    assert_eq!(plan.enabled_optional(), vec![BundleSection::DebugLogs]);
}

#[test]
fn sections_keep_the_documented_order_however_they_were_edited() {
    // Two exports of the same state must compare equal, and a reader should see the same list each time.
    let mut plan = plan();
    plan.toggle_optional(BundleSection::DebugLogs, true);
    plan.toggle_optional(BundleSection::AuditTrail, true);

    let order: Vec<BundleSection> = plan.sections().to_vec();
    let expected: Vec<BundleSection> = BundleSection::ALL
        .iter()
        .copied()
        .filter(|section| plan.includes(*section))
        .collect();
    assert_eq!(order, expected);
}

#[test]
fn the_consent_screen_names_everything_it_collects() {
    // A prompt that only says what it collects leaves the user to wonder about the rest, and wondering is
    // what stops people from sending the file that would have got their problem fixed.
    let plan = plan();
    let inclusions = plan.inclusions();
    assert_eq!(inclusions.len(), plan.sections().len());
    for (description, name) in &inclusions {
        assert!(!description.is_empty(), "{name}");
        assert!(!name.is_empty());
    }
    // And every section has a description, so a newly added one cannot appear as a bare name.
    for section in BundleSection::ALL {
        assert!(!section.describe().is_empty(), "{section:?}");
    }
}

#[test]
fn the_consent_screen_names_what_is_never_included() {
    let plan = plan();
    let excluded = plan.excludes();
    for promised in [
        "clipboard contents",
        "the body of any message",
        "the contents of any file",
        "passwords, tokens or pairing secrets",
        "anything a plugin stored in secure storage",
    ] {
        assert!(excluded.contains(&promised), "{promised} is not promised");
    }
}
