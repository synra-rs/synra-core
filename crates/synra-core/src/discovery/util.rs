use std::net::{IpAddr, SocketAddr};

use synra_protocol::discovery::DeviceAnnouncement;

use crate::identity::check_display_name;

use super::UNUSABLE_NAME;

/// A name to display, or the placeholder.
///
/// # Why a bad name does not drop the candidate
///
/// The datagram told us a device exists and where, which is what discovery is *for*. The name is a display concern, so a
/// name that fails the check costs the name and not the candidate — and the user still sees that something is there,
/// which is the difference between a device they can investigate and one that is silently missing.
pub(super) fn usable_name(announced: &str) -> String {
    check_display_name(announced).unwrap_or_else(|_| UNUSABLE_NAME.to_owned())
}

/// The address a datagram came from, with the port it announced.
///
/// The source address and not the announced endpoint list: the source is what the operating system vouched for, and the
/// announced list is a claim. The port is the announced one, because the source port is the ephemeral one the datagram
/// was sent from rather than the one the peer listens on.
#[must_use]
pub const fn announced_address(from: IpAddr, announcement: &DeviceAnnouncement) -> SocketAddr {
    SocketAddr::new(from, announcement.port)
}
