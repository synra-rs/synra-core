use rstest::rstest;
use super::super::actions::{Policies, MAX_URL_LEN};
use super::super::error::{PlatformError, UrlRefusal};
use super::super::guard::{check_url, check_url_length};

#[test]
fn an_https_url_is_accepted_by_default() {
    let policies = Policies::new();
    for url in [
        "https://example.com",
        "https://example.com/path?q=1#frag",
        "https://api.github.com/repos/synra-rs/synra-core",
        "https://example.com:8443/x",
    ] {
        assert_eq!(check_url(url, &policies), Ok(()), "{url}");
    }
}

#[test]
fn a_plain_http_url_is_refused_by_default() {
    // The consent prompt shows the user a hostname. Over HTTP that hostname can be rewritten before the
    // response, so the prompt is true about the destination and false about what will be displayed.
    let policies = Policies::new();
    match check_url("http://example.com", &policies) {
        Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::Insecure),
        other => panic!("expected an insecure refusal, got {other:?}"),
    }
    // And the refusal explains why, in terms of what the user is deciding about.
    assert!(UrlRefusal::Insecure.explain().contains("changed in transit"));
}

#[test]
fn http_can_be_allowed_by_policy() {
    let policies = Policies::new().with_insecure_urls(true);
    assert_eq!(check_url("http://example.com", &policies), Ok(()));
}

#[rstest]
#[case("javascript:alert(1)")]
#[case("data:text/html,<script>x</script>")]
#[case("vbscript:x")]
#[case("file:///etc/passwd")]
#[case("ftp://example.com")]
fn a_non_web_scheme_is_refused_by_default(#[case] url: &str) {
    // The list is closed rather than "anything that is not http": each of these is something a plugin could
    // put behind an "open this link" prompt, and a `file:` URL reaches a path without passing through the
    // executable check.
    let policies = Policies::new();
    match check_url(url, &policies) {
        Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::LocalScheme, "{url}"),
        other => panic!("{url} should be refused, got {other:?}"),
    }
}

#[test]
fn a_local_scheme_can_be_allowed_by_policy() {
    let policies = Policies::new().with_local_schemes(true);
    assert_eq!(check_url("file:///tmp/x", &policies), Ok(()));
}

#[test]
fn a_url_with_no_scheme_or_host_is_refused() {
    let policies = Policies::new();
    for (url, expected) in [
        ("example.com", UrlRefusal::NoScheme),
        ("https://", UrlRefusal::NoHost),
        ("https:///path", UrlRefusal::NoHost),
        ("https://?q=1", UrlRefusal::NoHost),
        ("", UrlRefusal::Empty),
    ] {
        match check_url(url, &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => {
                assert_eq!(reason, expected, "{url:?}");
            }
            other => panic!("{url:?} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn a_control_character_in_a_url_is_refused() {
    // A newline could forge a line in the consent prompt or split a log record, and the prompt is what the user
    // decides from.
    let policies = Policies::new();
    for url in [
        "https://example.com/\nhttps://evil.com",
        "https://example.com/\u{7}",
        "https://exa\u{0}mple.com",
    ] {
        match check_url(url, &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => {
                assert_eq!(reason, UrlRefusal::ControlCharacter, "{url:?}");
            }
            other => panic!("{url:?} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn an_over_long_url_is_refused() {
    let policies = Policies::new();
    let long = format!("https://example.com/{}", "x".repeat(MAX_URL_LEN));
    match check_url(&long, &policies) {
        Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::TooLong),
        other => panic!("expected a length refusal, got {other:?}"),
    }
}

#[test]
fn the_scheme_check_is_case_insensitive() {
    // `HTTPS://example.com` is the same scheme, and a comparison that missed it would refuse a legitimate
    // address.
    let policies = Policies::new();
    assert_eq!(check_url("HTTPS://example.com", &policies), Ok(()));
    assert!(check_url("HTTP://example.com", &policies).is_err());
}

#[test]
fn every_url_refusal_explains_itself() {
    for reason in [
        UrlRefusal::Empty,
        UrlRefusal::TooLong,
        UrlRefusal::NoScheme,
        UrlRefusal::LocalScheme,
        UrlRefusal::Insecure,
        UrlRefusal::NoHost,
        UrlRefusal::ControlCharacter,
    ] {
        assert!(reason.explain().len() > 15, "{reason:?}");
    }
}

#[test]
fn the_url_length_helper_refuses_before_the_open() {
    // So a caller building a URL finds out where it made the mistake rather than at the point a browser is
    // asked to open something.
    assert!(check_url_length("https://example.com").is_ok());
    let long = "x".repeat(MAX_URL_LEN + 1);
    assert!(matches!(
        check_url_length(&long),
        Err(PlatformError::TooLong { field: "address", .. })
    ));
}
