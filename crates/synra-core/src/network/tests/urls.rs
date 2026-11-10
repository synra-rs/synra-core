use super::*;

#[test]
fn only_https_and_only_the_granted_host() {
    let guard = guard();

    let checked = guard.check_url("https://api.example.com/v1/things").expect("allowed");
    assert_eq!(checked.host, "api.example.com");
    assert_eq!(checked.scheme, "https");
    assert_eq!(checked.port_or_default(), 443);

    // A port that was named is the one to use.
    let checked = guard.check_url("https://api.example.com:8443/x").expect("allowed");
    assert_eq!(checked.port_or_default(), 8443);
}

#[test]
fn a_scheme_that_is_not_https_is_refused_by_name() {
    // ★ The list is closed rather than "anything but http", because `javascript:`, `data:` and `file:` all mean something
    // to some program — and a plugin that can write one where an address is expected can make the host do something other
    // than fetch.
    for url in [
        "http://api.example.com/",
        "file:///etc/passwd",
        "data:text/plain,hello",
        "javascript:alert(1)",
        "ftp://api.example.com/",
    ] {
        let refused = guard().check_url(url).expect_err(url);

        assert_eq!(refused.code, synra_protocol::error::ErrorCode::SchemeNotAllowed, "{url}: {refused}");
    }
}

#[test]
fn plain_http_is_a_decision_rather_than_an_impossibility() {
    // A host may allow it; the default is that it does not.
    let permissive = guard().allowing_insecure(true);

    assert!(permissive.check_url("http://api.example.com/").is_ok());
}

#[test]
fn a_host_the_capability_did_not_name_is_refused() {
    let refused = guard().check_url("https://evil.example/").expect_err("not granted");

    assert_eq!(refused.code, synra_protocol::error::ErrorCode::HostNotAllowed, "{refused}");
}

#[test]
fn a_host_that_merely_ends_with_the_granted_one_is_a_different_host() {
    // ★ The classic: `api.example.com.evil.example` contains the granted name as a prefix of its own. A check that used
    // `contains` or `starts_with` would allow it, and the request would go to whoever owns `evil.example`.
    for url in [
        "https://api.example.com.evil.example/",
        "https://evil-api.example.com/",
        "https://notapi.example.com/",
    ] {
        assert!(guard().check_url(url).is_err(), "{url} is not the granted host");
    }
}

#[test]
fn userinfo_does_not_decide_which_host_is_reached() {
    // ★ `https://api.example.com@evil.example/` is a request to **evil.example** carrying `api.example.com` as a username.
    // A reader that took the text before the `@` would authorise the wrong machine and then connect to the other one.
    let refused = guard().check_url("https://api.example.com@evil.example/").expect_err("the host is evil.example");

    assert_eq!(refused.code, synra_protocol::error::ErrorCode::HostNotAllowed, "{refused}");
    assert!(refused.message.contains("evil.example"), "and it names the host it would have reached: {refused}");
}

#[test]
fn case_and_a_trailing_dot_do_not_make_a_second_host() {
    // ★ DNS names are case-insensitive and `example.com.` is `example.com`. Comparing raw strings would be a bypass with
    // one keystroke in it — and a grant written the long way would not cover the short one.
    let guard = guard();

    assert!(guard.check_url("https://API.Example.COM/x").is_ok());
    assert!(guard.check_url("https://api.example.com./x").is_ok());
    assert_eq!(normalise_host("API.Example.COM."), "api.example.com");

    // And a grant written the long way covers the short spelling.
    assert!(hosts(&["api.example.com."]).check_url("https://api.example.com/x").is_ok());
}

#[test]
fn a_url_this_guard_cannot_read_is_refused_rather_than_guessed_at() {
    let guard = guard();

    for url in ["", "not a url", "https://", "https://api.example.com:not-a-port/"] {
        assert!(guard.check_url(url).is_err(), "`{url}` is not a URL this guard can read");
    }

    // A control character could forge a consent prompt's text or split a log line.
    assert!(guard.check_url("https://api.example.com/\u{0}").is_err());
    assert!(guard.check_url("https://api.example.com/a\nb").is_err());

    // And a URL long enough to matter is one carrying something other than an address.
    let long = format!("https://api.example.com/{}", "a".repeat(super::super::MAX_URL_LEN));
    assert!(guard.check_url(&long).is_err());
}

#[test]
fn an_ipv6_literal_is_read_as_a_host_rather_than_split_at_its_colons() {
    // ★ `[2606:2800::1]:8443` has five colons and one of them is the port. Reading it by splitting on the first colon
    // gives a host of `[2606` — which would then be compared against the granted set and refused, so the failure is safe
    // but the *reason* would be wrong, and a granted IPv6 literal could never be reached at all.
    let guard = hosts(&["2606:2800:220:1::1"]);

    let checked = guard.check_url("https://[2606:2800:220:1::1]:8443/x").expect("allowed");

    assert_eq!(checked.host, "2606:2800:220:1::1");
    assert_eq!(checked.port_or_default(), 8443);
}

#[test]
fn a_refusal_is_a_code_and_a_sentence() {
    // A plugin branches on the code; a person reads the sentence. Neither is optional, and the code is one of the
    // contract's rather than something spelled here.
    let refused: Refusal = guard().check_url("https://evil.example/").expect_err("refused");

    assert!(!refused.message.is_empty());
    assert!(!refused.to_string().is_empty());
    assert_eq!(refused.code, synra_protocol::error::ErrorCode::HostNotAllowed);
}
