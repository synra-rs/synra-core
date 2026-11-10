//! Discovery worker fixtures and scenarios.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::socket::DiscoverySocket;

use super::DiscoveryService;

pub(super) use crate::test_support::{announcement, device, host};

pub(super) const A: &str = "11111111-1111-4111-8111-111111111111";
pub(super) const B: &str = "22222222-2222-4222-8222-222222222222";

/// A service with both sockets on ports the operating system chose.
///
/// # Why the responder is not on the well-known port
///
/// Because binding it would collide with a kernel that happens to be running on this machine, and because a test that
/// needed the discovery port free would fail for a reason that has nothing to do with what it asserts. The service
/// takes the address it is given; only `bind` uses the well-known port.
pub(super) fn service(id: &str, interval: Duration) -> DiscoveryService {
    DiscoveryService {
        responder: DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a responder"),
        querier: DiscoverySocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a querier"),
        ours: announcement(id, "Laptop", 47_100),
        next_query: Instant::now(),
        interval,
        broadcasting: false,
    }
}

mod runtime;
mod ticks;
mod receiving;
mod responses;
mod visibility;
