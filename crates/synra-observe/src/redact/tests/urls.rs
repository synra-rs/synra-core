use rstest::rstest;
use super::super::{REDACTED, Redaction, Redactor};

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
