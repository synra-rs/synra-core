//! Discovery table mutations and their visible results.

use std::net::SocketAddr;
use std::time::Duration;

use synra_protocol::discovery::DeviceAnnouncement;
use synra_protocol::handshake::Feature;
use synra_protocol::session::PlatformKind;

use crate::test_support::device;

use super::DiscoveryTable;

const LOCAL: &str = "11111111-1111-4111-8111-111111111111";
const PEER: &str = "22222222-2222-4222-8222-222222222222";
const OTHER: &str = "33333333-3333-4333-8333-333333333333";

fn address(port: u16) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 5], port))
}

fn announcement(id: &str, name: &str, port: u16) -> DeviceAnnouncement {
    DeviceAnnouncement {
        device_id: device(id),
        display_name: name.to_owned(),
        protocol: synra_protocol::handshake::PROTOCOL_VERSION,
        port,
        platform: Some(PlatformKind::Desktop),
        app_version: Some("0.1.0".to_owned()),
        features: vec![Feature::EventStream],
    }
}

fn table() -> DiscoveryTable {
    DiscoveryTable::new(device(LOCAL))
}

/// A table with a short lifetime, so a test does not wait one out.
fn short_table() -> DiscoveryTable {
    DiscoveryTable::with_ttl(device(LOCAL), Duration::from_millis(1_000))
}

mod announcements;
mod trust;
mod expiry;
mod snapshots;
