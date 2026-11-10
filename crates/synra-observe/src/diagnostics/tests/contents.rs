use super::*;

#[test]
fn a_bundle_built_with_everything_enabled_still_holds_no_content() {
    // The promise in `NEVER_INCLUDED` has to hold for the most permissive plan a user can construct, or it
    // is not a promise.
    let mut plan = plan();
    plan.toggle_optional(BundleSection::AuditTrail, true);
    plan.toggle_optional(BundleSection::DebugLogs, true);
    let rendered = plan.render().expect("renders");

    // The log line that carried a payload is cut at the field name, so neither the secret nor the rest of the
    // value survives.
    assert!(!rendered.contains("the secret message"), "{rendered}");
    assert!(!rendered.contains("secret message"), "{rendered}");
    // And the never-included list is in the file so a reader sees the same promise the user agreed to.
    for promised in NEVER_INCLUDED {
        assert!(rendered.contains(promised), "{promised}");
    }
}

#[test]
fn debug_lines_are_left_out_unless_the_debug_section_is_chosen() {
    // Debug lines carry device names and file paths, which are the user's information even though they are
    // not secrets.
    let mut plan = plan();
    let default_render = plan.render().expect("renders");
    assert!(!default_render.contains("my-laptop"), "a device name leaked");

    plan.toggle_optional(BundleSection::DebugLogs, true);
    let debug_render = plan.render().expect("renders");
    assert!(debug_render.contains("my-laptop"), "the chosen section was not included");
}

#[test]
fn the_log_slice_keeps_a_tail_and_every_error() {
    // The interesting part of a log is what happened just before the problem, and an error outside the
    // tail is the problem itself.
    let mut sources = sources();
    let mut lines: Vec<String> = (0..100)
        .map(|index| format!("ts={index} level=INFO event=tick"))
        .collect();
    lines.insert(5, "ts=5 level=ERROR event=boom".to_owned());
    sources.log_lines = Some(lines);

    let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
    plan.set_log_tail_lines(10);
    let bundle = plan.build();
    let logs = bundle.logs.expect("has logs");

    assert_eq!(logs.tail.len(), 10);
    assert!(logs.errors.iter().any(|line| line.text.contains("boom")));
    assert_eq!(logs.lines_read, 101);
}

#[test]
fn the_log_tail_respects_its_cap() {
    let mut sources = sources();
    sources.log_lines = Some((0..500).map(|index| format!("ts={index} level=INFO")).collect());
    let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));

    plan.set_log_tail_lines(3);
    let logs = plan.build().logs.expect("has logs");
    // Three INFO lines, plus the errors list which is separate.
    assert!(logs.tail.len() <= 3);
}

#[test]
fn a_very_long_log_line_is_truncated_on_a_character_boundary() {
    // A byte slice would split a multi-byte character, and the resulting string cannot even be built.
    let mut sources = sources();
    let long = format!("ts=1 level=INFO note={}", "电".repeat(5_000));
    assert!(long.len() > MAX_LOG_LINE_BYTES, "the fixture must exceed the cap");
    sources.log_lines = Some(vec![long.clone()]);
    let plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
    let logs = plan.build().logs.expect("has logs");

    assert_eq!(logs.tail.len(), 1, "the fixture line is missing: {logs:?}");
    let line = &logs.tail[0];
    assert!(line.truncated, "a {} byte line was not truncated", long.len());
    assert!(line.text.ends_with("…(truncated)"));
    // The kept prefix is whole characters, which `chars().take` guarantees and a byte slice would not, so
    // the byte length can be up to four times the character cap.
    assert!(line.text.len() <= MAX_LOG_LINE_BYTES * 4 + 32, "{}", line.text.len());
}

#[test]
fn a_short_log_line_is_not_marked_truncated() {
    let plan = plan();
    let logs = plan.build().logs.expect("has logs");
    assert!(logs.tail.iter().all(|line| !line.truncated));
}

#[test]
fn a_missing_source_leaves_its_field_none_rather_than_empty() {
    // An empty list of plugins reads as "no plugins installed"; `None` reads as "not collected". The
    // difference is what tells a reader whether the absence is information.
    let sources = BundleSources { plugins: None, devices: Some(Vec::new()), ..sources() };
    let plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
    let bundle = plan.build();

    assert!(bundle.plugins.is_none());
    assert_eq!(bundle.devices, Some(Vec::new()), "an empty list is a real answer");
}

#[test]
fn the_bundle_lists_the_sections_it_holds() {
    let bundle = plan().build();
    assert_eq!(bundle.sections.len(), bundle.len());
    for section in BundleSection::ALL {
        assert_eq!(bundle.contains(*section), plan().includes(*section), "{section:?}");
    }
}
