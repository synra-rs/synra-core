//! The logging module's property tests.

use super::*;
use proptest::prelude::*;

use crate::redact::REDACTED;

proptest! {
    /// A field whose name is on the list never contributes its value to the output. This is the
    /// property the whole module exists for, and it has to hold for arbitrary values because the
    /// value is whatever a developer happened to log.
    #[test]
    fn a_named_secret_field_never_reaches_the_output(
        // No spaces: a formatted value runs to the next space, so a value containing one cannot be
        // delimited from what follows it. That limitation is asserted separately, below.
        value in "[!-~]{1,80}",
        field in prop::sample::select(DEFAULT_REDACTED_FIELDS.to_vec()),
    ) {
        let line = format!("ts=1 level=INFO {field}={value} done=true\n");
        let (redacted, _) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

        // What follows the field name must be the marker, not the value.
        //
        // Asserting "the output does not contain the value" would be wrong in both directions: a
        // one-character value occurs inside `level`, and a value of `<` occurs inside the marker
        // itself. Only the position right after the field name says whether the value was withheld.
        let expected = format!("{field}={REDACTED}");
        prop_assert!(
            redacted.contains(&expected),
            "expected {expected:?} in {}",
            redacted,
        );
        // Skipped when the value happens to be a prefix of the marker itself — a value of `<` is
        // "followed by its value" in the letter of the check and not in its meaning.
        if !REDACTED.starts_with(value.as_str()) {
            prop_assert!(
                !redacted.contains(&format!("{field}={value}")),
                "{} still immediately follows its field name: {}",
                value,
                redacted,
            );
        }
    }

    /// A value containing a space is only partly replaced, and that is a documented limitation rather
    /// than a silent one.
    ///
    /// A formatted line has no structure the writer can trust: `payload=a b` is indistinguishable from
    /// two fields. The primary defence is redacting typed fields before they are formatted, where the
    /// name is known and the value is still whole; this asserts what the backstop does so the gap is on
    /// the record.
    #[test]
    fn a_value_with_a_space_is_only_partly_replaced(_unused in Just(())) {
        let line = "payload=secret start end peer=ok\n";
        let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
        prop_assert_eq!(count, 1);
        // The first token is gone; the remainder of the value is not.
        prop_assert!(!redacted.contains("secret"), "{}", redacted);
        prop_assert!(redacted.contains("start end"), "{}", redacted);
    }

    /// Redacting a line never loses the fields around it. A policy that ate the rest of the line
    /// would make the log useless, which is the failure mode that pushes people to turn redaction off.
    #[test]
    fn ordinary_fields_survive_redaction(
        // No spaces, for the same reason as above: a space inside the value would end it early and
        // the assertion would be about the delimiter rather than about redaction.
        value in "[!-~]{1,40}",
        peer in "[a-z0-9]{1,16}",
    ) {
        let line = format!("payload={value} peer={peer} elapsed_ms=5\n");
        let (redacted, _) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);
        prop_assert!(redacted.contains(&format!("peer={peer}")), "{}", redacted);
        prop_assert!(redacted.contains("elapsed_ms=5"), "{}", redacted);
    }

    /// Arbitrary text either survives unchanged or is modified, and the function never panics. Log
    /// lines come from everywhere, including a panic message and a third-party crate.
    #[test]
    fn redacting_a_line_is_total(line in ".{0,300}") {
        let _ = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);
    }

    /// A line with no field of interest comes back byte for byte. Reflowing it would corrupt a stack
    /// trace or a hex dump, which are the lines a reader most needs intact.
    #[test]
    fn a_line_without_secrets_is_not_reflowed(parts in proptest::collection::vec("[a-z]{1,8}", 1..6)) {
        let line = parts.join(" ");
        let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);
        prop_assert_eq!(redacted, line);
        prop_assert_eq!(count, 0);
    }
}
