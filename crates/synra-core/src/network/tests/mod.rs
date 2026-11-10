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

mod urls;
mod addresses;
mod redirects_and_ranges;
