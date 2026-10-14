//! The diagnostic bundle's tests.

use std::path::{Path, PathBuf};

use crate::audit::AuditEntry;
use crate::metrics::MetricsSnapshot;

use super::plan::*;
use super::records::*;
use super::sections::*;

    use super::*;
    use rstest::rstest;

    fn sources() -> BundleSources {
        BundleSources {
            environment: Some(EnvSummary {
                app_version: "1.0.0".to_owned(),
                kernel_version: "1.0.0".to_owned(),
                os: "windows".to_owned(),
                arch: "x86_64".to_owned(),
                webview_version: Some("120.0".to_owned()),
            }),
            config: Some(serde_json::json!({ "listen_port": 32100 })),
            devices: Some(vec![DeviceRecord {
                device_id: "0193".to_owned(),
                paired: true,
                online: true,
            }]),
            plugins: Some(vec![PluginRecord {
                plugin_id: "@synra-plugin/chat".to_owned(),
                version: "1.0.0".to_owned(),
                active: true,
                had_refusals: true,
            }]),
            metrics: Some(Box::new(MetricsSnapshot::default())),
            log_lines: Some(vec![
                "ts=1 level=INFO event=start peer=abc".to_owned(),
                "ts=2 level=ERROR payload=the secret message".to_owned(),
                "ts=3 level=DEBUG device_name=my-laptop".to_owned(),
            ]),
            crashes: Some(Vec::new()),
            probes: Some(Vec::new()),
            audit: Some(Vec::new()),
        }
    }

    fn plan() -> BundlePlan {
        BundlePlan::plan(sources(), 1_700_000_000_000, PathBuf::from("/tmp/bundle.json"))
    }

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

    #[test]
    fn the_receipt_names_the_size_the_path_and_the_digest() {
        // So a person who posts a bundle in an issue can check that what they uploaded is what they reviewed.
        let plan = plan();
        let rendered = plan.render().expect("renders");
        let receipt = plan.receipt(&rendered).expect("renders");

        assert!(receipt.contains(&rendered.len().to_string()), "{receipt}");
        assert!(receipt.contains("/tmp/bundle.json"), "{receipt}");
        assert!(receipt.contains("sha256 "), "{receipt}");
        assert!(receipt.contains(&sha256_hex(rendered.as_bytes())), "{receipt}");
    }

    #[test]
    fn the_digest_matches_an_independent_implementation() {
        // The known-answer vectors, so the hand-written SHA-256 is verified against the standard rather than
        // against itself.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // A message longer than one block, so the length append and multi-block loop are exercised.
        assert_eq!(
            sha256_hex(&b"a".repeat(1_000_000)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn a_digest_is_lowercase_hex_of_the_right_length() {
        let digest = sha256_hex(b"anything");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    #[test]
    fn the_bundle_digest_matches_its_rendering() {
        let bundle = plan().build();
        assert_eq!(bundle.digest().expect("renders"), sha256_hex(bundle.to_json().expect("renders").as_bytes()));
    }

    #[test]
    fn the_default_file_name_sorts_chronologically() {
        // A user will have more than one of these, and "synra-diagnostic (3).json" tells them nothing about
        // which is which.
        let earlier = default_file_name(1_700_000_000_000);
        let later = default_file_name(1_700_000_001_000);
        assert!(earlier < later, "{earlier} !< {later}");
        assert!(earlier.starts_with("synra-diagnostic-"));
        assert!(earlier.ends_with(".json"));
    }

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
