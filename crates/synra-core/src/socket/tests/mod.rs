//! Discovery datagrams over loopback sockets.

use std::net::{Ipv4Addr, SocketAddr};

use super::DiscoverySocket;

const A: &str = "11111111-1111-4111-8111-111111111111";
const B: &str = "22222222-2222-4222-8222-222222222222";

/// A socket on a port the operating system chose, so a test never collides with a running kernel.
fn loopback() -> DiscoverySocket {
    DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("binds")
}

mod datagrams;
mod receiving;
mod scanning;
mod broadcast;
mod errors;
