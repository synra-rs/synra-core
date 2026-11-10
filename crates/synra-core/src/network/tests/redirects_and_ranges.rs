use super::*;

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
