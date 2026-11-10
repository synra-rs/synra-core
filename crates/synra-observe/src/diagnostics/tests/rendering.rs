use super::*;

#[test]
fn an_empty_bundle_is_representable_and_says_so() {
    let plan = BundlePlan::plan(BundleSources::default(), 0, PathBuf::from("/tmp/x.json"));
    let bundle = plan.build();
    assert!(bundle.is_empty());
    assert!(bundle.sections.is_empty());
    // And it still renders, because a bundle with nothing in it is a valid answer to "what is there".
    assert!(plan.render().is_ok());
}

#[test]
fn a_bundle_round_trips_through_json() {
    let bundle = plan().build();
    let json = bundle.to_json().expect("renders");
    let back: DiagnosticBundle = serde_json::from_str(&json).expect("parses");
    assert_eq!(back, bundle);
}

#[test]
fn a_bundle_renders_readably() {
    // A person reads this file; that is the point of a bundle somebody chose to export.
    let json = plan().render().expect("renders");
    assert!(json.contains('\n'), "the bundle is not pretty-printed");
    assert!(json.contains("generatedAtMs"), "{json}");
    assert!(!json.contains("generated_at_ms"), "{json}");
}

#[test]
fn the_plan_names_where_the_bundle_will_go() {
    // A path revealed only after the export is a path the user has to hunt for.
    let plan = plan();
    assert_eq!(plan.destination(), Path::new("/tmp/bundle.json"));

    let mut plan = plan;
    plan.set_destination(PathBuf::from("/tmp/other.json"));
    assert_eq!(plan.destination(), Path::new("/tmp/other.json"));
}
