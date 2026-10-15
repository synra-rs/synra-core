//! The guard, against the ways these are got wrong.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{Cidr, IpPolicy, NetworkGuard, Refusal, normalise_host};

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn guard() -> NetworkGuard {
    NetworkGuard::for_hosts(&["api.example.com".to_owned()])
}

fn hosts(names: &[&str]) -> NetworkGuard {
    NetworkGuard::for_hosts(&names.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>())
}

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
fn a_private_or_loopback_address_is_refused_by_default() {
    // The policy that matters, and the reason the defaults are all `false`: the safe answer has to be the one nobody wrote.
    let guard = guard();

    for address in [
        "127.0.0.1",
        "192.168.0.1",
        "10.0.0.5",
        "172.16.0.1",
        // ★ The cloud metadata service, which is the reason this whole module exists.
        "169.254.169.254",
        "::1",
        "fd00::1",
        "fe80::1",
    ] {
        let refused = guard
            .check_resolved(
                &guard.check_url("https://api.example.com/").expect("allowed"),
                &[ip(address)],
            )
            .expect_err(address);

        assert_eq!(refused.code, synra_protocol::error::ErrorCode::IpNotAllowed, "{address}: {refused}");
    }
}

#[test]
fn a_public_address_is_reachable() {
    // The other half: a guard that refused everything would pass every test above.
    let guard = guard();
    let checked = guard.check_url("https://api.example.com/").expect("allowed");

    assert!(guard.check_resolved(&checked, &[ip("93.184.216.34"), ip("2606:2800:220:1::1")]).is_ok());
}

#[test]
fn every_resolved_address_must_pass_rather_than_the_first() {
    // ★ A name that resolves to one public address and one private one can reach the private one: the caller does not
    // choose which address the connection lands on, the resolver's order does. A check that stopped at the first would be
    // a check an attacker arranges the order around.
    let guard = guard();
    let checked = guard.check_url("https://api.example.com/").expect("allowed");

    let refused = guard
        .check_resolved(&checked, &[ip("93.184.216.34"), ip("169.254.169.254")])
        .expect_err("the second address is refused");

    assert!(refused.message.contains("169.254.169.254"), "and it names which: {refused}");
}

#[test]
fn a_name_that_resolves_to_nothing_is_refused_rather_than_sent_anywhere() {
    let guard = guard();
    let checked = guard.check_url("https://api.example.com/").expect("allowed");

    assert!(guard.check_resolved(&checked, &[]).is_err());
}

#[test]
fn an_explicit_range_overrides_the_default() {
    // What `allow_cidrs` is for: a service on the local network that the user decided a plugin may reach.
    let policy = IpPolicy {
        allow_cidrs: vec![Cidr::parse("192.168.1.0/24").expect("a range")],
        ..IpPolicy::default()
    };
    let guard = guard().with_policy(policy);
    let checked = guard.check_url("https://api.example.com/").expect("allowed");

    assert!(guard.check_resolved(&checked, &[ip("192.168.1.10")]).is_ok(), "inside the granted range");
    assert!(guard.check_resolved(&checked, &[ip("192.168.2.10")]).is_err(), "outside it");
}

#[test]
fn a_denial_beats_a_permission() {
    // ★ "I denied the metadata service" has to mean it, even for a host that also allowed every link-local address.
    // A list that could be overridden by the rules above it would be a list nobody could rely on.
    let policy = IpPolicy {
        allow_link_local: true,
        deny_cidrs: vec![Cidr::parse("169.254.169.254/32").expect("a range")],
        ..IpPolicy::default()
    };
    let guard = guard().with_policy(policy);
    let checked = guard.check_url("https://api.example.com/").expect("allowed");

    assert!(guard.check_resolved(&checked, &[ip("169.254.1.1")]).is_ok(), "allowed by the flag");
    assert!(
        guard.check_resolved(&checked, &[ip("169.254.169.254")]).is_err(),
        "and denied anyway"
    );
}

#[test]
fn the_flags_open_exactly_what_they_name() {
    let checked = guard().check_url("https://api.example.com/").expect("allowed");

    let loopback = guard().with_policy(IpPolicy { allow_loopback: true, ..IpPolicy::default() });
    assert!(loopback.check_resolved(&checked, &[ip("127.0.0.1")]).is_ok());
    assert!(loopback.check_resolved(&checked, &[ip("192.168.0.1")]).is_err(), "and nothing else");

    let private = guard().with_policy(IpPolicy { allow_private: true, ..IpPolicy::default() });
    assert!(private.check_resolved(&checked, &[ip("10.0.0.5")]).is_ok());
    assert!(private.check_resolved(&checked, &[ip("127.0.0.1")]).is_err(), "loopback is its own flag");
}

#[test]
fn an_ipv4_mapped_address_is_the_address_it_maps_to() {
    // ★ `::ffff:127.0.0.1` is loopback wearing a different family. A matcher that compared families first would call it
    // "not IPv4" and let it through — which is a bypass that needs no DNS at all, only a literal.
    let checked = guard().check_url("https://api.example.com/").expect("allowed");

    let mapped = ip("::ffff:127.0.0.1");
    assert!(guard().check_resolved(&checked, &[mapped]).is_err(), "it is loopback");

    // And a mapped address matches an IPv4 range, so a denial written the ordinary way covers it.
    let guard = guard().with_policy(IpPolicy {
        deny_cidrs: vec![Cidr::parse("127.0.0.0/8").expect("a range")],
        allow_loopback: true,
        ..IpPolicy::default()
    });
    assert!(guard.check_resolved(&checked, &[mapped]).is_err(), "the denial sees through the mapping too");
}

#[test]
fn a_redirect_is_checked_like_the_request_it_replaces() {
    // ★ "The first hop was allowed" is not a property a later hop inherits. A redirect to a host nobody granted is exactly
    // how a granted host is used to reach an ungranted one.
    let guard = guard();

    // The first hop, twice, is fine.
    assert!(guard.next_hop(0, "https://api.example.com/next").is_ok());

    let refused = guard.next_hop(0, "https://evil.example/").expect_err("not granted");
    assert_eq!(refused.code, synra_protocol::error::ErrorCode::HostNotAllowed, "{refused}");

    // And a hop to a refused scheme is refused for that reason rather than for the host.
    let refused = guard.next_hop(0, "file:///etc/passwd").expect_err("not a scheme");
    assert_eq!(refused.code, synra_protocol::error::ErrorCode::SchemeNotAllowed, "{refused}");
}

#[test]
fn redirects_stop_at_the_limit() {
    let guard = guard();

    assert!(guard.next_hop(4, "https://api.example.com/x").is_ok(), "the fifth hop is allowed");

    let refused = guard.next_hop(5, "https://api.example.com/x").expect_err("the sixth is not");
    assert_eq!(refused.code, synra_protocol::error::ErrorCode::RedirectBlocked, "{refused}");
}

#[test]
fn a_range_is_parsed_or_refused_rather_than_rounded() {
    assert!(Cidr::parse("10.0.0.0/8").is_ok());
    assert!(Cidr::parse("0.0.0.0/0").is_ok(), "everything is a range somebody may write");
    assert!(Cidr::parse("fd00::/8").is_ok());

    // ★ A `/33` on IPv4 is a typo. Treating it as `/32` — the nearest thing that parses — would silently widen a policy
    // the caller wrote to be narrow.
    assert!(Cidr::parse("10.0.0.0/33").is_err());
    assert!(Cidr::parse("10.0.0.0").is_err(), "no length at all");
    assert!(Cidr::parse("not-an-address/8").is_err());
    assert!(Cidr::parse("10.0.0.0/eight").is_err());
}

#[test]
fn a_range_contains_what_it_covers_and_nothing_else() {
    let range = Cidr::parse("192.168.1.0/24").expect("a range");

    assert!(range.contains(ip("192.168.1.1")));
    assert!(range.contains(ip("192.168.1.255")));
    assert!(!range.contains(ip("192.168.2.1")));
    assert!(!range.contains(ip("192.168.0.255")));
    // A range of one family says nothing about an address of the other.
    assert!(!range.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!range.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
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
    let long = format!("https://api.example.com/{}", "a".repeat(super::MAX_URL_LEN));
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
