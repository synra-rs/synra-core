use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};

use synra_protocol::limits::DISCOVERY_PORT;

/// Broadcast on each interface's actual subnet, plus the limited broadcast address.
/// A limited broadcast alone may follow a VPN/default route instead of the Wi-Fi LAN.
#[must_use]
pub fn broadcast_addresses() -> Vec<SocketAddr> {
    addresses_for(Ipv4Addr::UNSPECIFIED)
}

pub(super) fn addresses_for(bound: Ipv4Addr) -> Vec<SocketAddr> {
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    destinations(
        interfaces
            .into_iter()
            .filter(|interface| interface.is_oper_up() && !interface.is_p2p())
            .filter_map(|interface| match interface.addr {
                if_addrs::IfAddr::V4(address)
                    if (bound.is_unspecified() || bound == address.ip)
                        && !address.ip.is_loopback()
                        && !address.ip.is_link_local() =>
                {
                    address.broadcast
                }
                _ => None,
            }),
    )
}

fn destinations(broadcasts: impl Iterator<Item = Ipv4Addr>) -> Vec<SocketAddr> {
    broadcasts
        .chain([Ipv4Addr::BROADCAST])
        .filter(|address| !address.is_unspecified() && !address.is_loopback())
        .map(|address| SocketAddr::from((address, DISCOVERY_PORT)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcasts_use_real_subnets_and_deduplicate_interfaces() {
        let wifi = Ipv4Addr::new(192, 168, 7, 255); // /21, not an assumed /24.
        let ethernet = Ipv4Addr::new(10, 31, 255, 255);
        assert_eq!(
            destinations([wifi, ethernet, wifi].into_iter()),
            [ethernet, wifi, Ipv4Addr::BROADCAST].map(|ip| SocketAddr::from((ip, DISCOVERY_PORT)))
        );
    }
}
