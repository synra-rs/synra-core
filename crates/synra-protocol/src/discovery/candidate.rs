use core::fmt;
use core::net::IpAddr;
use core::time::Duration;

use crate::ids::DeviceId;
use crate::limits;

use super::datagram::{DeviceAnnouncement, DiscoveryDatagram};

/// How much confidence there is in a device's identity.
///
/// Discovery cannot raise this above [`Self::Announced`]: a UDP datagram's contents are
/// unauthenticated, so anything it claims is a hint. Only a completed handshake — TCP, `Hello`, and
/// the challenge check — reaches [`Self::Handshaked`], and only that level may appear in the user's
/// device list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TrustLevel {
    /// An address that replied to a broadcast. The device id is unverified.
    Announced,
    /// A TCP connection was made and a `Hello` exchanged.
    Handshaked,
    /// The pairing token was accepted.
    Paired,
}

impl TrustLevel {
    /// Whether a device at this level may be shown as a peer.
    #[must_use]
    pub const fn is_displayable(self) -> bool {
        matches!(self, Self::Handshaked | Self::Paired)
    }
}

/// A device heard from, with the address it was heard from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// What the device claimed about itself, unverified.
    pub device: DeviceAnnouncement,
    /// Where the datagram came from.
    pub source: IpAddr,
    /// How much confidence there is in it.
    pub trust: TrustLevel,
}

impl Candidate {
    /// The address to connect to for the main link.
    #[must_use]
    pub const fn endpoint(&self) -> (IpAddr, u16) {
        (self.source, self.device.port)
    }

    /// Whether this candidate may appear in the user's device list.
    ///
    /// The rule that keeps a spoofed datagram from putting a fake device in the interface.
    #[must_use]
    pub const fn is_displayable(&self) -> bool {
        self.trust.is_displayable()
    }
}

/// Decides which datagrams to accept, and whether a candidate is this device itself.
///
/// One place for the self-check, per the module docs. A device that answers its own broadcast would
/// otherwise list itself, and a check spread over several layers is one that will be missed when a
/// new path is added.
#[derive(Debug, Clone)]
pub struct Discovery {
    /// This device's id.
    local_id: DeviceId,
    /// This device's own addresses, including IPv6.
    local_addresses: Vec<IpAddr>,
}

impl Discovery {
    /// Builds a filter for one device.
    #[must_use]
    pub const fn new(local_id: DeviceId, local_addresses: Vec<IpAddr>) -> Self {
        Self {
            local_id,
            local_addresses,
        }
    }

    /// Whether a datagram should be acted on.
    ///
    /// Two conditions, and no others: the device id matches ours, or the source address is one of
    /// ours. The second catches the case the first cannot — a device that has not yet learned its own
    /// id, or a datagram whose advertised id differs from the interface it left by.
    #[must_use]
    pub fn admit(&self, datagram: &DiscoveryDatagram, source: IpAddr) -> bool {
        if datagram.device_id() == self.local_id {
            return false;
        }
        !self.local_addresses.contains(&source)
    }

    /// Records a device that has completed a handshake, raising its trust.
    ///
    /// The only way a device becomes displayable. Called by the handshake path, not by discovery.
    #[must_use]
    pub fn handshaked(candidate: Candidate) -> Candidate {
        Candidate {
            trust: TrustLevel::Handshaked,
            ..candidate
        }
    }

    /// This device's id.
    #[must_use]
    pub const fn local_id(&self) -> DeviceId {
        self.local_id
    }

    /// This device's own addresses.
    #[must_use]
    pub fn local_addresses(&self) -> &[IpAddr] {
        &self.local_addresses
    }
}

/// A device's compact name for logs.
///
/// Discovery runs before logging is necessarily configured, so this is a plain `Display` rather than
/// something that needs a subscriber.
impl fmt::Display for DeviceAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, port {})",
            self.display_name, self.device_id, self.port
        )
    }
}

/// How many times an offline announcement is sent.
///
/// Best-effort, three times with a short gap: this runs while the process is shutting down, and a
/// device that dies without announcing itself is noticed by its peers anyway, via the heartbeat
/// timeout. More repeats would delay shutdown for a message that is only an optimisation.
#[must_use]
pub const fn offline_repeats() -> u8 {
    limits::OFFLINE_ANNOUNCE_REPEATS
}

/// The gap between offline announcements.
#[must_use]
pub const fn offline_interval() -> Duration {
    limits::OFFLINE_ANNOUNCE_INTERVAL
}
