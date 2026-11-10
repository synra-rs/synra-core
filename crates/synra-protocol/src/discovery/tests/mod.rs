//! Discovery datagrams, admission and scan budgets.

use core::net::{IpAddr, Ipv4Addr};
use crate::handshake::{Feature, PROTOCOL_VERSION};
use crate::ids::DeviceId;
use crate::session::PlatformKind;
use super::DeviceAnnouncement;

fn device(id: DeviceId, port: u16) -> DeviceAnnouncement {
    DeviceAnnouncement {
        device_id: id,
        display_name: "laptop".to_owned(),
        protocol: PROTOCOL_VERSION,
        port,
        platform: Some(PlatformKind::Desktop),
        app_version: Some("1.0.0".to_owned()),
        features: vec![Feature::EventStream, Feature::LanDiscovery],
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

mod wire;
mod admission;
mod budget;
mod proptests;
