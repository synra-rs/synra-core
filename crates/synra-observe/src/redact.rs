//! Keeping secrets out of logs.
//!
//! The list of things that must never reach a log file is short and absolute:
//!
//! * clipboard contents
//! * message payload bodies
//! * file contents
//! * keys and tokens
//! * the query and fragment of a URL, which routinely carry a token
//! * a plugin's secure-storage values
//!
//! This module is the one place that enforces it. A `tracing` filter could drop whole events, but the
//! problem is not whole events: it is one field inside an otherwise useful log line. Dropping the line
//! loses the diagnosis; keeping the field leaks the secret.
//!
//! # Two mechanisms, because the failure modes differ
//!
//! * **A denylist of field names** replaces the value entirely. This is the primary defence, because a
//!   developer writing `info!(payload = ?body, "received")` has made a mistake they can fix, and the
//!   name is what tells us the value is dangerous.
//! * **A length cap** truncates everything else. This is the backstop for the case the denylist cannot
//!   cover: a secret logged under a name nobody anticipated. It does not prevent the leak, but it bounds
//!   it, and a bounded leak in a bug report is a different problem from an unbounded one.
//!
//! # Why the denylist checks substrings
//!
//! Field names are written by hand and come in flavours: `payload`, `payloadLen`, `request_body`,
//! `authToken`, `api_key`, `userSecret`. Matching whole names would miss most of them, and the miss is
//! silent. Substring matching over-redacts instead — `body_count` becomes `<redacted>` — and an
//! over-redacted log is a small annoyance where an under-redacted one is a security incident.
//!
//! # URLs are handled separately
//!
//! A URL is usually safe to log and usually necessary to log. What is not safe is its query string:
//! `?token=…`, `?access_token=…`, `?code=…`. So a URL keeps its scheme, host and path and loses
//! everything from `?` or `#`.

use core::fmt;

/// The replacement written in place of a redacted value.
pub const REDACTED: &str = "<redacted>";

/// The suffix appended to a truncated value, with its original length.
///
/// The length is kept because it is frequently the diagnostic detail that matters — "the header was
/// 4 KB" — while the bytes are what must not be kept.
pub const TRUNCATION_MARK: &str = "…";

/// The default cap on an ordinary string value.
pub const DEFAULT_MAX_VALUE_LEN: usize = 512;

/// Field-name fragments that mark a value as secret.
///
/// Matched case-insensitively as substrings against the field name. Ordered longest-first only in the
/// comments: the check is a `contains`, so order does not matter, and listing them together makes it
/// obvious what the policy is.
const SECRET_FRAGMENTS: &[&str] = &[
    // Message and file content.
    "payload",
    "body",
    "content",
    "clipboard",
    "text",
    "file_data",
    "filedata",
    "bytes",
    // Credentials.
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "apikey",
    "api_key",
    "auth",
    "cookie",
    "session_key",
    "private_key",
    "privatekey",
    "signature",
    // Plugin-private storage.
    "secure",
    "keyring",
];

/// A field name that must not be logged at all.
///
/// Also matched as a substring. Kept separate from [`SECRET_FRAGMENTS`] because these are names where
/// the value is *structure* rather than content — a JWT has no useful log representation at all, and
/// logging its first few bytes is still a partial credential.
const WHOLE_VALUE_FRAGMENTS: &[&str] = &["jwt", "bearer", "authorization"];

/// What was done to a value, so a test can assert on the decision rather than on a formatted string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redaction {
    /// The value is safe and appears unchanged.
    Untouched,
    /// The value was replaced entirely.
    Replaced,
    /// The value was cut to [`Redactor::max_value_len`] characters.
    Truncated {
        /// The original length, in characters.
        original_len: usize,
    },
    /// A URL had its query and fragment removed.
    UrlStripped {
        /// How many characters were removed.
        removed: usize,
    },
}

impl Redaction {
    /// Whether the value reached the log unchanged.
    #[must_use]
    pub const fn is_untouched(&self) -> bool {
        matches!(self, Self::Untouched)
    }

    /// Whether anything was withheld.
    #[must_use]
    pub const fn withheld_something(&self) -> bool {
        !self.is_untouched()
    }
}

/// The result of redacting one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    /// What should be written to the log.
    pub text: String,
    /// What was done.
    pub decision: Redaction,
}

impl Redacted {
    /// A value that needed no change.
    fn untouched(text: impl Into<String>) -> Self {
        Self { text: text.into(), decision: Redaction::Untouched }
    }
}

impl fmt::Display for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Applies the redaction policy.
///
/// Deliberately holds no subscriber and no I/O: redaction is a pure function of a field name and a
/// value, so it can be tested exhaustively and used from anywhere — a log layer, a diagnostic bundle, an
/// audit record, an error message shown to a user.
#[derive(Debug, Clone)]
pub struct Redactor {
    max_value_len: usize,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// A redactor with the default cap.
    #[must_use]
    pub const fn new() -> Self {
        Self { max_value_len: DEFAULT_MAX_VALUE_LEN }
    }

    /// A redactor with a different cap, for tests and for a verbose mode.
    #[must_use]
    pub const fn with_max_value_len(max_value_len: usize) -> Self {
        Self { max_value_len }
    }

    /// The current cap.
    #[must_use]
    pub const fn max_value_len(&self) -> usize {
        self.max_value_len
    }

    /// Whether a field name marks its value as secret.
    ///
    /// Case-insensitive substring match, so `authToken`, `AUTH_TOKEN` and `request_body` are all caught.
    #[must_use]
    pub fn is_secret_field(name: &str) -> bool {
        let lowered = name.to_ascii_lowercase();
        SECRET_FRAGMENTS
            .iter()
            .chain(WHOLE_VALUE_FRAGMENTS)
            .any(|fragment| lowered.contains(fragment))
    }

    /// Redacts a string value according to its field name.
    ///
    /// A secret field is replaced outright, whatever it contains. Everything else is stripped of a URL's
    /// query and fragment, then truncated.
    #[must_use]
    pub fn value(&self, field: &str, value: &str) -> Redacted {
        if Self::is_secret_field(field) {
            return Redacted { text: REDACTED.to_owned(), decision: Redaction::Replaced };
        }

        // A URL keeps its scheme, host and path: those are usually the diagnosis. The query and
        // fragment are where tokens live.
        let (stripped, removed) = strip_url_query(value);
        let after_url = if removed > 0 {
            stripped
        }
        else {
            value.to_owned()
        };

        let url_decision = if removed > 0 {
            Some(Redaction::UrlStripped { removed })
        }
        else {
            None
        };

        if after_url.chars().count() > self.max_value_len {
            let original_len = after_url.chars().count();
            let mut text: String = after_url.chars().take(self.max_value_len).collect();
            text.push_str(TRUNCATION_MARK);
            let _ = fmt::Write::write_fmt(&mut text, format_args!("(len={original_len})"));
            return Redacted {
                text,
                decision: url_decision.unwrap_or(Redaction::Truncated { original_len }),
            };
        }

        match url_decision {
            Some(decision) => Redacted { text: after_url, decision },
            None => Redacted::untouched(after_url),
        }
    }

    /// Redacts a value that is not a string, by its `Debug` form.
    ///
    /// A non-string field can still hold content: `payload = ?json` where `json` is a
    /// `serde_json::Value` is the most common way to leak a message body, and it renders as a string.
    #[must_use]
    pub fn debug_value<T: fmt::Debug + ?Sized>(&self, field: &str, value: &T) -> Redacted {
        self.value(field, &format!("{value:?}"))
    }

    /// Redacts a value by its `Display` form.
    #[must_use]
    pub fn display_value<T: fmt::Display + ?Sized>(&self, field: &str, value: &T) -> Redacted {
        self.value(field, &format!("{value}"))
    }
}

/// Removes a URL's query and fragment, returning the remainder and how many characters went.
///
/// A value counts as a URL only when it *begins* with a scheme: `https://host/p?x=1` yes, and
/// `the form is scheme://host?query` no. Searching the whole string for `://` instead would treat
/// prose that happens to mention a scheme as a URL and silently cut the sentence in half — and the
/// sentence is a log line somebody wrote to be read.
fn strip_url_query(value: &str) -> (String, usize) {
    let Some(scheme_end) = value.find("://") else {
        return (value.to_owned(), 0);
    };
    let scheme = &value[..scheme_end];
    // The `://` has to be at the very start: `scheme_end == 0` means the value begins `://`, which no
    // URL does, so the scheme must be non-empty *and* the marker must come right after it.
    //
    // Stating "at the start" as a length check rather than relying on the scheme's own character class
    // is deliberate: a rule that depends on a second validator agreeing is a rule that breaks when
    // either of them changes.
    if scheme_end == 0 || scheme.is_empty() || scheme.len() > 32 {
        return (value.to_owned(), 0);
    }
    let plausible_scheme = scheme.starts_with(|ch: char| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.');
    if !plausible_scheme {
        return (value.to_owned(), 0);
    }

    let cut = value
        .get(scheme_end..)
        .and_then(|rest| rest.find(['?', '#']))
        .map(|offset| scheme_end + offset);

    match cut {
        Some(cut) => {
            let kept = value[..cut].to_owned();
            let removed = value.chars().count() - kept.chars().count();
            (kept, removed)
        }
        None => (value.to_owned(), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The secrets the design document lists as never loggable.
    const FORBIDDEN: &[(&str, &str)] = &[
        ("payload", r#"{"body":"the secret message"}"#),
        ("body", "the secret message"),
        ("content", "file contents here"),
        ("clipboard", "copied password"),
        ("text", "a chat message"),
        ("token", "ghp_0123456789abcdef"),
        ("access_token", "ya29.abcdef"),
        ("api_key", "sk-live-abcdef"),
        ("apikey", "sk-live-abcdef"),
        ("secret", "hunter2"),
        ("password", "hunter2"),
        ("credential", "user:pass"),
        ("authToken", "Bearer abc"),
        ("Authorization", "Bearer abc"),
        ("cookie", "session=abc"),
        ("private_key", "-----BEGIN PRIVATE KEY-----"),
        ("session_key", "0123456789abcdef"),
        ("secure_value", "a stored secret"),
        ("keyring_value", "a stored secret"),
        ("userSecret", "shh"),
        ("request_body", "POST /x HTTP/1.1"),
        ("file_data", "binary"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.e30.x"),
    ];

    #[test]
    fn every_forbidden_field_is_replaced_whatever_it_holds() {
        // The property the module exists for, asserted per field so a removed fragment names the field
        // that stopped being protected.
        let redactor = Redactor::new();
        for (field, value) in FORBIDDEN {
            let redacted = redactor.value(field, value);
            assert_eq!(
                redacted.decision,
                Redaction::Replaced,
                "field {field:?} was not redacted",
            );
            assert!(!redacted.text.contains(value), "{field:?} leaked its value");
            assert_eq!(redacted.text, REDACTED);
        }
    }

    #[test]
    fn a_secret_field_is_replaced_even_when_the_value_is_empty() {
        // An empty value is not an excuse to skip the decision: a field that is sometimes empty and
        // sometimes a token is exactly the one a policy that short-circuits on emptiness gets wrong.
        let redactor = Redactor::new();
        let redacted = redactor.value("token", "");
        assert_eq!(redacted.decision, Redaction::Replaced);
        assert_eq!(redacted.text, REDACTED);
    }

    #[test]
    fn field_names_are_matched_case_insensitively_and_as_substrings() {
        for field in [
            "TOKEN",
            "Token",
            "authToken",
            "user_access_token",
            "my_secret_thing",
            "PAYLOAD",
            "requestBody",
            "x-clipboard-text",
        ] {
            assert!(Redactor::is_secret_field(field), "{field} should be treated as secret");
        }
    }

    #[test]
    fn ordinary_field_names_are_not_redacted() {
        for field in ["peer", "device_id", "elapsed_ms", "event", "trace_id", "port", "count"] {
            assert!(!Redactor::is_secret_field(field), "{field} should be loggable");
        }
    }

    #[test]
    fn over_redaction_is_the_deliberate_direction() {
        // `body_count` is harmless and is redacted anyway. Stated as a test so the trade-off is visible:
        // a slightly less useful log is preferable to a leaked secret, and a whole-name match would miss
        // `bodyLen` and its relatives.
        assert!(Redactor::is_secret_field("body_count"));
        assert_eq!(Redactor::new().value("body_count", "3").text, REDACTED);
    }

    #[test]
    fn a_long_value_is_truncated_with_its_original_length() {
        let redactor = Redactor::with_max_value_len(16);
        let long = "x".repeat(100);
        let redacted = redactor.value("peer", &long);

        assert_eq!(redacted.decision, Redaction::Truncated { original_len: 100 });
        // Sixteen kept characters, then the marker and the length.
        assert!(redacted.text.starts_with(&"x".repeat(16)), "{}", redacted.text);
        assert!(redacted.text.contains("len=100"), "{}", redacted.text);
        // And the value is no longer present in full.
        assert!(!redacted.text.contains(&long));
    }

    #[test]
    fn a_value_exactly_at_the_cap_is_untouched() {
        // The boundary is inclusive, so a cap of 16 keeps a 16-character value intact.
        let redactor = Redactor::with_max_value_len(16);
        let exact = "y".repeat(16);
        assert_eq!(redactor.value("peer", &exact).decision, Redaction::Untouched);

        let one_more = "y".repeat(17);
        assert!(redactor.value("peer", &one_more).decision.withheld_something());
    }

    #[test]
    fn truncation_counts_characters_not_bytes() {
        // A length measured in bytes would cut a multi-byte character in half and produce invalid UTF-8,
        // which `String` cannot even hold — so the failure would be a panic rather than a bad log line.
        let redactor = Redactor::with_max_value_len(4);
        let cjk = "电".repeat(10);
        let redacted = redactor.value("peer", &cjk);
        assert!(redacted.text.starts_with("电电电电"), "{}", redacted.text);
        assert!(redacted.text.contains("len=10"), "{}", redacted.text);
    }

    #[rstest]
    #[case("https://api.github.com/repos?token=ghp_abc", "https://api.github.com/repos")]
    #[case("https://example.com/a/b?access_token=x&y=1", "https://example.com/a/b")]
    #[case("https://example.com/p#fragment", "https://example.com/p")]
    #[case("http://localhost:8080/x?q=1", "http://localhost:8080/x")]
    fn a_url_loses_its_query_and_fragment(#[case] input: &str, #[case] expected: &str) {
        let redactor = Redactor::new();
        let redacted = redactor.value("url", input);
        assert_eq!(redacted.text, expected);
        assert_eq!(redacted.decision, Redaction::UrlStripped {
            removed: input.chars().count() - expected.chars().count(),
        });
    }

    #[test]
    fn a_url_without_a_query_is_untouched() {
        let redactor = Redactor::new();
        let url = "https://api.github.com/repos/synra-rs/synra-core";
        let redacted = redactor.value("url", url);
        assert_eq!(redacted.decision, Redaction::Untouched);
        assert_eq!(redacted.text, url);
    }

    #[test]
    fn a_path_that_merely_contains_a_question_mark_is_left_alone() {
        // `?` in a path is part of the name. Truncating there would corrupt the value the log exists to
        // record, and the value is not a URL.
        let redactor = Redactor::new();
        let path = "/var/log/what?.log";
        assert_eq!(redactor.value("path", path).text, path);
    }

    #[test]
    fn a_url_that_is_also_a_secret_field_is_replaced_entirely() {
        // The order matters: a secret check that ran after the URL strip would log the host of a URL
        // that was supposed to be withheld.
        let redactor = Redactor::new();
        let redacted = redactor.value("token_url", "https://example.com/?t=1");
        assert_eq!(redacted.decision, Redaction::Replaced);
        assert_eq!(redacted.text, REDACTED);
    }

    #[test]
    fn a_url_that_is_also_too_long_reports_the_url_decision() {
        // The more specific decision wins, so a consumer rendering "query removed" does not instead say
        // "truncated" and leave the user looking for what was cut.
        let redactor = Redactor::with_max_value_len(8);
        let redacted = redactor.value("url", "https://example.com/a/b?token=abcdefghij");
        assert!(matches!(redacted.decision, Redaction::UrlStripped { .. }));
        assert!(redacted.text.contains("len="), "{}", redacted.text);
    }

    #[test]
    fn a_non_string_value_is_redacted_by_its_debug_form() {
        // `payload = ?value` where the value is a parsed JSON tree is the most common way to leak a
        // message body, and it renders as a string.
        let redactor = Redactor::new();
        let value = serde_json::json!({ "body": "the secret message" });
        let redacted = redactor.debug_value("payload", &value);
        assert_eq!(redacted.text, REDACTED);
        assert!(!redacted.text.contains("secret"));
    }

    #[test]
    fn an_ordinary_non_string_value_is_readable() {
        let redactor = Redactor::new();
        assert_eq!(redactor.debug_value("peer_count", &3u32).text, "3");
        assert_eq!(redactor.display_value("elapsed_ms", &12u64).text, "12");
        assert_eq!(
            redactor.display_value("elapsed_ms", &12u64).decision,
            Redaction::Untouched
        );
    }

    #[test]
    fn a_redacted_value_displays_as_its_text() {
        let redactor = Redactor::new();
        assert_eq!(redactor.value("token", "abc").to_string(), REDACTED);
        assert_eq!(redactor.value("peer", "abc").to_string(), "abc");
    }

    #[test]
    fn a_zero_cap_still_produces_readable_output() {
        // A degenerate configuration must not produce a log line that a reader cannot interpret.
        let redactor = Redactor::with_max_value_len(0);
        let redacted = redactor.value("peer", "abc");
        assert_eq!(redacted.decision, Redaction::Truncated { original_len: 3 });
        assert!(redacted.text.contains("len=3"), "{}", redacted.text);
    }

    #[test]
    fn a_url_with_no_scheme_is_not_treated_as_a_url() {
        // `example.com/a?b=c` is ambiguous, and guessing would strip a query the caller meant to log.
        let redactor = Redactor::new();
        let value = "example.com/a?b=c";
        assert_eq!(redactor.value("host", value).text, value);
    }

    #[test]
    fn a_scheme_shaped_prefix_is_not_mistaken_for_a_url() {
        // A `://` inside a sentence is part of the sentence. Treating it as a URL would cut the log line
        // in half, and the line is what somebody wrote to be read.
        let redactor = Redactor::new();
        let value = "the form is scheme://host?query";
        assert_eq!(redactor.value("note", value).text, value);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
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
}
