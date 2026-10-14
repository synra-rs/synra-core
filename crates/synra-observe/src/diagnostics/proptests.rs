//! The diagnostic bundle's property tests.

use std::path::PathBuf;


use super::plan::*;
use super::records::*;
use super::sections::*;

use proptest::prelude::*;

    use super::*;
    

    proptest! {
        /// The digest matches the standard implementation for arbitrary input lengths, which is what exercises
        /// the padding rule at every remainder. A wrong remainder produces a digest that is valid-looking and
        /// wrong, and the only way to notice is a vector.
        #[test]
        fn a_digest_is_the_right_length_for_any_input(len in 0usize..300) {
            let digest = sha256_hex(&vec![b'x'; len]);
            prop_assert_eq!(digest.len(), 64);
            prop_assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
        }

        /// A redacted bundle never contains a forbidden value, whatever was in the logs it was built from.
        /// This is the promise the consent screen makes, checked against content rather than asserted.
        #[test]
        fn a_redacted_bundle_never_leaks_a_payload(secret in "[a-zA-Z0-9]{8,24}") {
            let sources = BundleSources {
                log_lines: Some(vec![
                    format!("ts=1 level=INFO payload={secret}"),
                    format!("ts=2 level=ERROR token={secret}"),
                    format!("ts=3 level=INFO body={secret}"),
                ]),
                ..BundleSources::default()
            };

            let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
            plan.toggle_optional(BundleSection::DebugLogs, true);
            let rendered = plan.render().expect("renders");

            prop_assert!(!rendered.contains(&secret), "the secret leaked into the bundle");
        }

        /// A selected section is present and an unselected one is absent, whatever the section and whatever the
        /// sources. A bundle that quietly included something is the failure this module exists to prevent.
        #[test]
        fn selection_decides_presence(
            toggle_audit in any::<bool>(),
            toggle_debug in any::<bool>(),
        ) {
            let sources = BundleSources {
                environment: Some(EnvSummary {
                    app_version: "1".to_owned(),
                    kernel_version: "1".to_owned(),
                    os: "test".to_owned(),
                    arch: "test".to_owned(),
                    webview_version: None,
                }),
                log_lines: Some(vec!["ts=1 level=INFO event=x".to_owned()]),
                audit: Some(Vec::new()),
                ..BundleSources::default()
            };

            let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
            plan.toggle_optional(BundleSection::AuditTrail, toggle_audit);
            plan.toggle_optional(BundleSection::DebugLogs, toggle_debug);

            let bundle = plan.build();
            prop_assert_eq!(bundle.audit_trail.is_some(), toggle_audit);
            prop_assert_eq!(plan.includes(BundleSection::Environment), bundle.environment.is_some());
            prop_assert!(bundle.logs.is_some(), "logs are a default section");
            // The section list and the fields agree: nothing is listed that is not there.
            for section in BundleSection::ALL {
                let listed = bundle.contains(*section);
                let present = match section {
                    BundleSection::Environment => bundle.environment.is_some(),
                    BundleSection::Config => bundle.config.is_some(),
                    BundleSection::Devices => bundle.devices.is_some(),
                    BundleSection::Plugins => bundle.plugins.is_some(),
                    BundleSection::Metrics => bundle.metrics.is_some(),
                    BundleSection::Crashes => bundle.crashes.is_some(),
                    BundleSection::Probes => bundle.probes.is_some(),
                    BundleSection::AuditTrail => bundle.audit_trail.is_some(),
                    // The one exception, and the exception is the point: both log filters read the same file and
                    // merge into one slice, because a reader asking "what does the log say" does not care which
                    // checkbox put a line there. So the slice is present exactly when at least one is selected.
                    BundleSection::Logs | BundleSection::DebugLogs => {
                        let any = plan.includes(BundleSection::Logs) || plan.includes(BundleSection::DebugLogs);
                        prop_assert_eq!(bundle.logs.is_some(), any);
                        continue;
                    }
                };
                prop_assert_eq!(listed, present, "section {:?} disagrees with its field", section);
            }
        }

        /// The tail never exceeds its cap, whatever the log length. A bundle that carried the whole file would
        /// be one nobody reads, and one that carried unbounded memory during assembly would be a hazard.
        #[test]
        fn the_tail_respects_its_cap(
            line_count in 0usize..200,
            cap in 0usize..50,
        ) {
            let sources = BundleSources {
                log_lines: Some(
                    (0..line_count)
                        .map(|index| format!("ts={index} level=INFO event=x"))
                        .collect(),
                ),
                ..BundleSources::default()
            };

            let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
            plan.set_log_tail_lines(cap);
            let logs = plan.build().logs.expect("has logs");
            prop_assert!(logs.tail.len() <= cap);
            prop_assert_eq!(logs.lines_read, line_count);
        }
    }
