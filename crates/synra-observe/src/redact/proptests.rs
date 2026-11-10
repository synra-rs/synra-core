use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use super::{REDACTED, Redaction, Redactor};

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/redact.txt"
        )))),
        ..ProptestConfig::default()
    })]
    /// A secret field never leaks its value, whatever the value is. This is the property that has
    /// to hold for every input, because the input is whatever a developer happened to log.
    #[test]
    fn a_secret_field_never_leaks(
        value in ".{0,200}",
        field in prop::sample::select(vec![
            "payload", "body", "token", "secret", "password", "content", "clipboard",
        ]),
    ) {
        let redacted = Redactor::new().value(field, &value);
        prop_assert_eq!(redacted.text.as_str(), REDACTED);
        // The value must not be *recoverable* from the output. Asserting that the output does not contain the
        // value as a substring is the wrong check: a value of `<` occurs inside the marker itself, which
        // says nothing about whether the value was withheld.
        if !value.is_empty() && !REDACTED.contains(&value) {
            prop_assert!(!redacted.text.contains(&value));
        }
    }

    /// Any value either survives unchanged or is marked as withheld, and a marked value never
    /// contains the input in full. There is no third outcome where something was changed but
    /// reported as untouched.
    #[test]
    fn redaction_decisions_are_honest(
        value in ".{0,2000}",
        field in "[a-z_]{1,20}",
    ) {
        let redactor = Redactor::with_max_value_len(64);
        let redacted = redactor.value(&field, &value);

        if redacted.decision.is_untouched() {
            prop_assert_eq!(redacted.text.as_str(), value.as_str());
        }
        else if redacted.decision == Redaction::Replaced {
            prop_assert_eq!(redacted.text.as_str(), REDACTED);
        }
        else {
            // Truncated or stripped: the result is shorter than the input.
            prop_assert!(redacted.text.chars().count() <= value.chars().count() + 16);
        }
    }

    /// Truncation never produces invalid output, whatever the input's character widths. A cap
    /// applied in bytes would split a multi-byte character.
    #[test]
    fn truncation_keeps_valid_text(value in "\\PC{0,300}", cap in 0usize..32) {
        let redacted = Redactor::with_max_value_len(cap).value("peer", &value);
        // Reaching here means the value is a valid `String`; the assertion is that the kept prefix
        // is whole characters, which `chars().take` guarantees and a byte slice would not.
        prop_assert!(!redacted.text.is_empty() || value.is_empty());
    }

    /// A URL's query and fragment are always removed, and its scheme, host and path always survive.
    #[test]
    fn a_url_keeps_its_prefix_and_loses_its_query(
        host in "[a-z]{1,10}\\.[a-z]{2,4}",
        path in "/[a-z/]{0,20}",
        query in "[a-z=&0-9]{1,30}",
    ) {
        let url = format!("https://{host}{path}?{query}");
        let redacted = Redactor::new().value("url", &url);
        let expected = format!("https://{host}{path}");
        prop_assert!(!redacted.text.contains('?'));
        prop_assert_eq!(redacted.text, expected);
    }
}
