use super::*;

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
